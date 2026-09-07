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
    IndirectNexthopUnresolved,
    get_rib_backup_nexthops,
    get_rib_pathid,
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
"ifindex":20011,"weight":100,"flags":"ATTACH BACKUP","backup":true,
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
        """Asserts PRESENCE of the backup as well as absence of the primary.

        Asserting only `swp1 not in ...` passed on an empty result, so it held
        under every mutation including a full revert.
        """
        d = _device()
        d.execute.side_effect = _responder()
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        egress = [n.get("interface") for n in bk]
        self.assertEqual(egress, ["swp2"], "backup must be present, primary absent")

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
            else PATHID_73_JSON.replace('"flags":"ATTACH BACKUP"',
                                        '"flags":"ATTACH"')
            if "73" in cmd else PATHID_53_JSON)
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            bk = get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertEqual([n["interface"] for n in bk], ["swp2"])

    def test_unresolvable_indirection_RAISES(self):
        """Must not look like "no backup".

        Suites assert on the negative -- `not verify_rib_has_backup(...)` and
        testcases named ..._have_no_backup -- so an empty return would let a
        resolution defect satisfy them. That is the silent pass this whole
        change exists to remove.
        """
        d = _device()
        d.execute.side_effect = Exception("oper read unavailable")
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            with self.assertRaises(IndirectNexthopUnresolved) as ctx:
                get_rib_backup_nexthops(d, "6.6.6.6/32")
        self.assertIn("317", str(ctx.exception))

    def test_pathids_listed_but_unreadable_RAISES(self):
        d = _device()
        d.execute.side_effect = lambda cmd, *a, **k: (
            IGP_RNH_JSON if ("igp-rnh" in cmd or "-nhids" in cmd) else "")
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            with self.assertRaises(IndirectNexthopUnresolved):
                get_rib_backup_nexthops(d, "6.6.6.6/32")

    def test_non_default_ni_RAISES_rather_than_resolving_nothing(self):
        """The pathid/nhid tables are modelled only under NI 'default'."""
        d = _device()
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            with self.assertRaises(IndirectNexthopUnresolved):
                get_rib_backup_nexthops(d, "6.6.6.6/32", ni="vrf-red")


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
        """Paired with a positive control, so an empty result cannot satisfy it."""
        d = _device()
        d.execute.side_effect = _responder()
        with patch(f"{MOD}.get_rib_entry", return_value=INDIRECT_ENTRY):
            self.assertFalse(verify_rib_has_backup(
                d, "6.6.6.6/32", af="IPV4",
                expected_backup_egress="swp3", **self.FAST))
            # Control: the same stubs DO satisfy the real egress. Without this
            # the assertion above holds even when nothing resolves at all.
            self.assertTrue(verify_rib_has_backup(
                d, "6.6.6.6/32", af="IPV4",
                expected_backup_egress="swp2", **self.FAST))

    def test_flat_with_expected_egress_still_passes(self):
        d = _device()
        with patch(f"{MOD}.get_rib_entry", return_value=FLAT_ENTRY):
            self.assertTrue(verify_rib_has_backup(
                d, "6.6.6.6/32", af="IPV4",
                expected_backup_egress="swp2", **self.FAST))


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# The four oper table names are IRREGULAR, and interpolating them from the AF
# silently broke IPv6 entirely. Verified against arcos-rib.yang and, for the
# containers, against arcOS R8.6.1.Alpha1:
#
#   container ipv4-nhids   -> list ipv4-nhids   (:2090/:2091)
#   container ipv6-nhids   -> list v6nhids      (:2108/:2109)
#   container ipv4-pathids -> list pathids      (:2288/:2289)
#   container ipv6-pathids -> list v6pathids    (:2306/:2307)
#
# A bare `rib IPV6 v6pathids` is `syntax error: unknown element` on the device,
# so the v6 prefix belongs to the LIST, never the container.
# ---------------------------------------------------------------------------

class TestResolutionTableNames(unittest.TestCase):

    def _commands_for(self, af):
        d = _device()
        seen = []

        def execute(cmd, *a, **k):
            seen.append(cmd)
            return ""
        d.execute.side_effect = execute
        entry = INDIRECT_ENTRY
        with patch(f"{MOD}.get_rib_entry", return_value=entry):
            try:
                get_rib_backup_nexthops(d, "6.6.6.6/32", af=af)
            except IndirectNexthopUnresolved:
                pass
        return seen

    def test_ipv4_uses_ipv4_pathids_pathids(self):
        cmds = " | ".join(self._commands_for("IPV4"))
        self.assertIn("rib IPV4 igp-rnh 317", cmds)
        self.assertIn("ipv4-nhids ipv4-nhids 317", cmds)

    def test_ipv6_uses_the_v6_LIST_not_a_v6_container(self):
        cmds = " | ".join(self._commands_for("IPV6"))
        self.assertIn("rib IPV6 igp-rnh 317", cmds)
        self.assertIn("ipv6-nhids v6nhids 317", cmds)
        # The container is ipv6-nhids; `rib IPV6 v6nhids` does not exist.
        self.assertNotIn("rib IPV6 v6nhids", cmds)
        self.assertNotIn("ipv6-nhids ipv6-nhids", cmds)

    def test_ipv6_pathid_read_uses_v6pathids(self):
        d = _device()
        seen = []
        d.execute.side_effect = lambda cmd, *a, **k: (seen.append(cmd) or "")
        get_rib_pathid(d, 73, af="IPV6")
        self.assertIn("ipv6-pathids v6pathids 73", seen[0])
        self.assertNotIn("ipv6-pathids pathids", seen[0])

    def test_ipv4_pathid_read_uses_plain_pathids(self):
        d = _device()
        seen = []
        d.execute.side_effect = lambda cmd, *a, **k: (seen.append(cmd) or "")
        get_rib_pathid(d, 73, af="IPV4")
        self.assertIn("ipv4-pathids pathids 73", seen[0])


class TestRowIdentity(unittest.TestCase):
    """A row must be matched on its own key, not by "most keys wins"."""

    TWO_ROWS = """{"data":{"ipv4-pathids":{"pathids":[
      {"pathid":53,"type":"IPV4","next-hop":"10.12.1.2","interface":"swp1",
       "weight":100,"flags":"ATTACH","backup":false},
      {"pathid":73,"type":"IPV4","next-hop":"10.14.2.4","interface":"swp2",
       "ifindex":20011,"weight":100,"flags":"ATTACH BACKUP","backup":true,
       "label-cnt":1,"pushed-mpls-label-stack":[24006]}]}}}"""

    def test_requesting_the_primary_does_not_return_the_backup_row(self):
        """The backup row has MORE keys, so a max-key heuristic returned it."""
        d = _device()
        d.execute.side_effect = lambda *a, **k: self.TWO_ROWS
        row = get_rib_pathid(d, 53, af="IPV4")
        self.assertEqual(row.get("pathid"), 53)
        self.assertEqual(row.get("interface"), "swp1")
        self.assertNotIn("BACKUP", str(row.get("flags")))

    def test_absent_pathid_returns_empty_not_a_neighbour(self):
        d = _device()
        d.execute.side_effect = lambda *a, **k: self.TWO_ROWS
        self.assertEqual(get_rib_pathid(d, 999, af="IPV4"), {})


class TestRnhScoping(unittest.TestCase):
    """Pathids must come only from the RNH we asked for, without duplicates."""

    TWO_RNHS = """{"data":{"igp-rnhs":{"igp-rnh":[
      {"id":317,"state":{"id":317,"nhid":317,"paths":[73,53]}},
      {"id":999,"state":{"id":999,"nhid":999,"paths":[777,778]}}]}}}"""

    def test_only_the_requested_rnh_contributes(self):
        d = _device()
        d.execute.side_effect = lambda *a, **k: self.TWO_RNHS
        from genie.libs.sdk.apis.arcos.rib.get import get_rib_igp_rnh_pathids
        self.assertEqual(get_rib_igp_rnh_pathids(d, 317), [73, 53])

    def test_no_duplicates_when_paths_appears_at_two_depths(self):
        d = _device()
        d.execute.side_effect = lambda *a, **k: (
            '{"igp-rnh":[{"id":317,"paths":[73,53],'
            '"state":{"id":317,"paths":[73,53]}}]}')
        from genie.libs.sdk.apis.arcos.rib.get import get_rib_igp_rnh_pathids
        self.assertEqual(get_rib_igp_rnh_pathids(d, 317), [73, 53])

    def test_mismatched_nhid_warns_but_still_resolves(self):
        d = _device()
        d.execute.side_effect = lambda *a, **k: (
            '{"igp-rnh":[{"id":317,"state":{"id":317,"nhid":42,'
            '"paths":[73]}}]}')
        from genie.libs.sdk.apis.arcos.rib.get import get_rib_igp_rnh_pathids
        with self.assertLogs(MOD, level="WARNING") as cm:
            self.assertEqual(get_rib_igp_rnh_pathids(d, 317), [73])
        self.assertIn("nhid 42", "".join(cm.output))


class TestFlagTokenMatching(unittest.TestCase):
    def test_igp_nh_is_matched_as_a_whole_token(self):
        self.assertTrue(is_indirect_nexthop(
            {"next-hop": 317, "flags": "RECURSIVE SR IGP_NH"}))

    def test_a_flag_merely_containing_igp_nh_does_not_match(self):
        self.assertFalse(is_indirect_nexthop(
            {"next-hop": 317, "flags": "RECURSIVE NO_IGP_NH"}))
