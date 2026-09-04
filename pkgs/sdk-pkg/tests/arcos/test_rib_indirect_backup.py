"""Tests for SR-MPLS indirect (ECMP-FEC-optimized) RIB backup resolution.

Both fixtures below are the REAL device output for 6.6.6.6/32 on rtr1, taken
from archived CI builds of the isis_tilfa_sr_mpls_ipv4 lane:

  FLAT     - build 1587, image 3ed8a29e, testbed pushing the invalid
             `usage SRGB` token. arcOS rejected that leaf, so no valid SRGB
             existed, IS-IS could not download labels, and the RIB rendered
             two resolved next-hops carrying `interface` and `ATTACH BACKUP`.
  INDIRECT - build 1631, same suite, testbed pushing the correct `usage
             ISIS_SRGB`. SR-MPLS now genuinely programs, so the route carries
             ECMP_FEC_OPTIMIZE and one synthetic recursive next-hop whose
             `next-hop` is an integer IGP-RNH id with no interface and no
             BACKUP flag.

The suites asserted only on the flat shape, so fixing the token turned four
TI-LFA lanes red without the assertion naming a cause. Both shapes must work:
older images still render flat, and a one-hop destination whose primary label
is implicit-null renders flat even on a new image.
"""

import unittest
from unittest.mock import Mock, patch

from genie.libs.sdk.apis.arcos.rib.get import (
    get_rib_backup_nexthops,
    is_indirect_nexthop,
    resolve_indirect_nexthops,
)
from genie.libs.sdk.apis.arcos.rib.verify import verify_rib_has_backup

MOD = "genie.libs.sdk.apis.arcos.rib.get"

# ---- build 1587: flat -----------------------------------------------------
FLAT_ENTRY = {
    "prefix": "6.6.6.6/32",
    "best-protocol": "openconfig-policy-types:ISIS",
    # Parser shape: origins and next-hops are keyed by index string.
    "origins": {"0": {
        "origin-protocol": "ISIS", "protocol-name": "isis-default@default",
        "metric": 40, "route-type": "ISIS_L2", "nhid": "74", "flags": "",
        "next-hops": {
            "0": {"pathid": "73", "type": "IPV4", "next-hop": "10.14.2.4",
                  "interface": "swp2", "weight": 100,
                  "flags": "ATTACH BACKUP"},
            "1": {"pathid": "53", "type": "IPV4", "next-hop": "10.12.1.2",
                  "interface": "swp1", "weight": 100, "flags": "ATTACH"},
        },
    }},
}

# ---- build 1631: indirect -------------------------------------------------
INDIRECT_ENTRY = {
    "prefix": "6.6.6.6/32",
    "best-protocol": "openconfig-policy-types:ISIS",
    "origins": {"0": {
        "origin-protocol": "ISIS", "protocol-name": "isis-default@default",
        "metric": 40, "route-type": "ISIS_L2", "nhid": "327",
        "flags": "ECMP_FEC_OPTIMIZE",
        "next-hops": {
            "0": {"pathid": "326", "type": "IGP", "next-hop": 317,
                  "network-instance": "default", "weight": 100,
                  "flags": "RECURSIVE SR IGP_NH",
                  "pushed-mpls-label-stack": [16006]},
        },
    }},
}

# The two extra reads. Shapes follow the documented CLI columns for
# `rib IPV4 igp-rnh <id>` (PATHS [ 27 23 ]) and
# `rib IPV4 ipv4-pathids pathids <id>` (INTERFACE / FLAGS / BACKUP /
# PUSHED MPLS LABEL STACK). Wrapped in a plausible ConfD envelope on purpose:
# the resolver must not depend on the nesting, which is why it searches by key.
IGP_RNH_JSON = """{"data":{"openconfig-network-instance:network-instances":
{"network-instance":[{"name":"default","arcos-rib:rib":[{"address-family":
"openconfig-types:IPV4","igp-rnhs":{"igp-rnh":[{"id":317,"state":
{"id":317,"nhid":317,"res-state":true,"mpls-reachable":true,"metric":0,
"ref-count":2,"recur-level":1,"paths":[73,53]}}]}}]}]}}}"""

PATHID_73_JSON = """{"data":{"openconfig-network-instance:network-instances":
{"network-instance":[{"name":"default","arcos-rib:rib":[{"address-family":
"openconfig-types:IPV4","ipv4-pathids":{"pathids":[{"pathid":73,"type":"IPV4",
"network-instance":"default","next-hop":"10.14.2.4","interface":"swp2",
"ifindex":20011,"weight":100,"flags":"ATTACH,BACKUP","backup":true,
"label-cnt":1,"pushed-mpls-label-stack":[24006]}]}}]}]}}}"""

PATHID_53_JSON = """{"data":{"openconfig-network-instance:network-instances":
{"network-instance":[{"name":"default","arcos-rib:rib":[{"address-family":
"openconfig-types:IPV4","ipv4-pathids":{"pathids":[{"pathid":53,"type":"IPV4",
"network-instance":"default","next-hop":"10.12.1.2","interface":"swp1",
"ifindex":20010,"weight":100,"flags":"ATTACH","backup":false,
"label-cnt":0}]}}]}]}}}"""


def _device():
    d = Mock()
    d.name = "rtr1"
    return d


def _responder():
    """device.execute stub returning the right JSON per command."""
    def execute(cmd, *a, **kw):
        if "igp-rnh" in cmd or "-nhids" in cmd:
            return IGP_RNH_JSON
        if "pathids pathids 73" in cmd:
            return PATHID_73_JSON
        if "pathids pathids 53" in cmd:
            return PATHID_53_JSON
        raise AssertionError(f"unexpected command: {cmd}")
    return execute


class TestIndirectDetection(unittest.TestCase):
    def test_flat_ipv4_nexthop_is_not_indirect(self):
        for nh in FLAT_ENTRY["origins"]["0"]["next-hops"].values():
            self.assertFalse(is_indirect_nexthop(nh))

    def test_recursive_igp_nexthop_is_indirect(self):
        nh = INDIRECT_ENTRY["origins"]["0"]["next-hops"]["0"]
        self.assertTrue(is_indirect_nexthop(nh))

    def test_recursive_without_igp_nh_flag_is_not_indirect(self):
        """A recursive BGP next-hop also says RECURSIVE; IGP_NH is the tell."""
        self.assertFalse(is_indirect_nexthop(
            {"next-hop": 317, "flags": "RECURSIVE"}))

    def test_igp_nh_flag_with_an_address_is_not_indirect(self):
        self.assertFalse(is_indirect_nexthop(
            {"next-hop": "10.12.1.2", "flags": "RECURSIVE SR IGP_NH"}))

    def test_numeric_string_id_is_indirect(self):
        self.assertTrue(is_indirect_nexthop(
            {"next-hop": "317", "flags": "IGP_NH"}))


class TestFlatRenderingStillWorks(unittest.TestCase):
    """Older images, and one-hop destinations on new images, render flat."""

    def test_flat_backup_found(self):
        d = _device()
        with patch(f"{MOD}.get_rib_entry", return_value=FLAT_ENTRY):
            bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertEqual(len(bk), 1)
        self.assertEqual(bk[0]["interface"], "swp2")

    def test_flat_costs_no_extra_reads(self):
        d = _device()
        d.execute.side_effect = AssertionError("must not read the device")
        with patch(f"{MOD}.get_rib_entry", return_value=FLAT_ENTRY):
            get_rib_backup_nexthops(d, "6.6.6.6/32")


class TestIndirectResolution(unittest.TestCase):
    """The build-1631 shape — what turned four lanes red."""

    def test_resolves_to_the_real_backup(self):
        d = _device()
        d.execute.side_effect = _responder()
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertEqual(len(bk), 1, "expected exactly the backup path")
        self.assertEqual(bk[0]["interface"], "swp2")
        self.assertIn("BACKUP", bk[0]["flags"])

    def test_primary_is_not_reported_as_backup(self):
        d = _device()
        d.execute.side_effect = _responder()
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertNotIn("swp1", [n.get("interface") for n in bk])

    def test_parent_label_suffix_is_carried(self):
        """The RIB subtracts the common suffix from each sub-path, so the full
        stack is only reconstructable with the parent's."""
        d = _device()
        d.execute.side_effect = _responder()
        nh = INDIRECT_ENTRY["origins"]["0"]["next-hops"]["0"]
        paths = resolve_indirect_nexthops(d, nh)
        self.assertEqual(len(paths), 2)
        for p in paths:
            self.assertEqual(p["parent-pushed-mpls-label-stack"], [16006])

    def test_nesting_is_not_depended_on(self):
        """Same data, no ConfD envelope at all."""
        d = _device()
        d.execute.side_effect = lambda cmd, *a, **k: (
            '{"igp-rnh":[{"state":{"nhid":317,"paths":[73]}}]}'
            if "igp-rnh" in cmd or "-nhids" in cmd else PATHID_73_JSON)
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertEqual([n["interface"] for n in bk], ["swp2"])

    def test_backup_boolean_alone_is_enough(self):
        """pathids carries both a flags bitmap and a `backup` boolean."""
        d = _device()
        d.execute.side_effect = lambda cmd, *a, **k: (
            IGP_RNH_JSON if ("igp-rnh" in cmd or "-nhids" in cmd)
            else PATHID_73_JSON.replace('"flags":"ATTACH,BACKUP"',
                                        '"flags":"ATTACH"')
            if "73" in cmd else PATHID_53_JSON)
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertEqual([n["interface"] for n in bk], ["swp2"])

    def test_unresolvable_indirection_returns_empty_and_warns(self):
        d = _device()
        d.execute.side_effect = Exception("oper read unavailable")
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            with self.assertLogs(MOD, level="WARNING") as cm:
                bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertEqual(bk, [])
        self.assertIn("ECMP-FEC-optimized", "".join(cm.output))

    def test_device_read_failure_never_raises(self):
        d = _device()
        d.execute.side_effect = Exception("transport gone")
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            self.assertEqual(get_rib_backup_nexthops(d, "6.6.6.6/32"), [])


class TestVerifyRibHasBackup(unittest.TestCase):
    """The API the four red lanes actually call, 50 sites between them."""

    FAST = {"max_time": 0.05, "check_interval": 0.01}

    def test_indirect_with_expected_egress_passes(self):
        d = _device()
        d.execute.side_effect = _responder()
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            self.assertTrue(verify_rib_has_backup(
                d, "6.6.6.6/32", af="IPV4",
                expected_backup_egress="swp2", **self.FAST))

    def test_indirect_with_wrong_egress_fails(self):
        d = _device()
        d.execute.side_effect = _responder()
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            self.assertFalse(verify_rib_has_backup(
                d, "6.6.6.6/32", af="IPV4",
                expected_backup_egress="swp3", **self.FAST))

    def test_flat_with_expected_egress_still_passes(self):
        d = _device()
        with patch(f"{MOD}.get_rib_entry", return_value=FLAT_ENTRY):
            self.assertTrue(verify_rib_has_backup(
                d, "6.6.6.6/32", af="IPV4",
                expected_backup_egress="swp2", **self.FAST))


if __name__ == "__main__":
    unittest.main()
