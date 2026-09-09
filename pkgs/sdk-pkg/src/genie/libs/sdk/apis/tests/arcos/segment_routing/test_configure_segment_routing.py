#!/usr/bin/env python3
"""Unit tests for arcOS Segment Routing (SRv6 / SR-MPLS / SRMS)
configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under `network-instance <ni>`
(plus a locator/label-block/SRMS-mapping sub-context) and calls
device.configure(list). Tests mock device.configure and assert on a
distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock, patch

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.segment_routing import configure as sr_configure
from genie.libs.sdk.apis.arcos.segment_routing.configure import (
    # SRv6 encapsulation - source-address
    configure_srv6_encap_source_address,
    unconfigure_srv6_encap_source_address,
    # SRv6 locator
    configure_srv6_locator,
    unconfigure_srv6_locator,
    # SRv6 locator micro-segment
    configure_srv6_locator_micro_segment,
    unconfigure_srv6_locator_micro_segment,
    # SR-MPLS reserved label block
    configure_mpls_reserved_label_block,
    unconfigure_mpls_reserved_label_block,
    # SRMS mapping
    configure_srms_mapping,
    unconfigure_srms_mapping,
    # SRMS mapping IPv4 prefix
    configure_srms_mapping_ipv4_prefix,
    unconfigure_srms_mapping_ipv4_prefix,
    # SRMS mapping IPv6 prefix
    configure_srms_mapping_ipv6_prefix,
    unconfigure_srms_mapping_ipv6_prefix,
    # SRv6 encapsulation - ip-ttl-propagation
    configure_srv6_encap_ip_ttl_propagation,
    unconfigure_srv6_encap_ip_ttl_propagation,
    # SRv6 encapsulation - hop-limit
    configure_srv6_encap_hop_limit,
    unconfigure_srv6_encap_hop_limit,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestSrv6EncapSourceAddressApis(unittest.TestCase):
    """configure_srv6_encap_source_address / unconfigure_srv6_encap_source_address"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_encap_source_address(self):
        configure_srv6_encap_source_address(self.d, "2001:db8::1")
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("srv6 encapsulation source-address 2001:db8::1", c)

    def test_encap_source_address_named_instance(self):
        configure_srv6_encap_source_address(
            self.d, "2001:db8::2", network_instance="red"
        )
        self.assertIn("network-instance red", self.d.cfg())

    def test_unconfigure_encap_source_address(self):
        unconfigure_srv6_encap_source_address(self.d)
        self.assertIn("no srv6 encapsulation source-address", self.d.cfg())


class TestSrv6LocatorApis(unittest.TestCase):
    """configure_srv6_locator / unconfigure_srv6_locator"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_locator_full(self):
        configure_srv6_locator(
            self.d, "loc1", "fcbb:bb00:1::/48", 24,
            func_length=16, algorithm=128,
        )
        c = self.d.cfg()
        self.assertIn("srv6 locator loc1", c)
        self.assertIn("prefix fcbb:bb00:1::/48", c)
        self.assertIn("locator-node-length 24", c)
        self.assertIn("function-length 16", c)
        self.assertIn("algorithm 128", c)

    def test_locator_minimal(self):
        configure_srv6_locator(self.d, "loc2", "fcbb:bb00:2::/48", 24)
        c = self.d.cfg()
        self.assertIn("srv6 locator loc2", c)
        self.assertNotIn("function-length", c)
        self.assertNotIn("algorithm", c)

    def test_unconfigure_locator(self):
        unconfigure_srv6_locator(self.d, "loc1")
        self.assertIn("no srv6 locator loc1", self.d.cfg())


class TestSrv6LocatorMicroSegmentApis(unittest.TestCase):
    """configure_srv6_locator_micro_segment / unconfigure_srv6_locator_micro_segment"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_micro_segment_enabled(self):
        configure_srv6_locator_micro_segment(self.d, "loc1", enabled=True)
        c = self.d.cfg()
        self.assertIn("srv6 locator loc1", c)
        self.assertIn("micro-segment-behavior-unode true", c)

    def test_micro_segment_disabled(self):
        configure_srv6_locator_micro_segment(self.d, "loc1", enabled=False)
        self.assertIn("micro-segment-behavior-unode false", self.d.cfg())

    def test_unconfigure_micro_segment(self):
        unconfigure_srv6_locator_micro_segment(self.d, "loc1")
        c = self.d.cfg()
        self.assertIn("srv6 locator loc1", c)
        self.assertIn("no micro-segment-behavior-unode", c)


# The configure API reads the block back after committing (arcOS drops a bad
# leaf and commits the rest, so nothing else would notice), and fails closed
# when it cannot see it. `_CfgDevice` is a config recorder with no parser
# behind it, so these CLI-shape tests patch the getter to a block matching
# what they send. `verify=False` would also work but would stop exercising
# the read-back path at all.
_GETTER = ("genie.libs.sdk.apis.arcos.segment_routing.get."
           "get_mpls_reserved_label_block")


def _read_back(**over):
    block = {
        "local-id": "SRGB_BLOCK",
        "lower-bound": 16000,
        "upper-bound": 23999,
        "usage": "ISIS_SRGB",
        "protocol-identifier": "ISIS",
        "protocol-name": "default",
    }
    block.update(over)
    return block


class TestMplsReservedLabelBlockApis(unittest.TestCase):
    """configure_mpls_reserved_label_block / unconfigure_mpls_reserved_label_block"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_label_block_full(self):
        with patch(_GETTER, return_value=_read_back()):
            configure_mpls_reserved_label_block(
                self.d, "SRGB_BLOCK", 16000, 23999, "ISIS_SRGB", "ISIS",
                protocol_name="default",
            )
        c = self.d.cfg()
        self.assertIn("mpls global reserved-label-block SRGB_BLOCK", c)
        self.assertIn("lower-bound 16000", c)
        self.assertIn("upper-bound 23999", c)
        self.assertIn("usage ISIS_SRGB", c)
        self.assertIn("protocol-identifier ISIS", c)
        self.assertIn("protocol-name default", c)

    def test_label_block_no_protocol_name(self):
        block = _read_back(**{"local-id": "SRLB_BLOCK",
                              "lower-bound": 15000, "upper-bound": 15999,
                              "usage": "ISIS_SRLB",
                              "protocol-identifier": "OSPF"})
        del block["protocol-name"]
        with patch(_GETTER, return_value=block):
            configure_mpls_reserved_label_block(
                self.d, "SRLB_BLOCK", 15000, 15999, "ISIS_SRLB", "OSPF",
            )
        c = self.d.cfg()
        self.assertIn("mpls global reserved-label-block SRLB_BLOCK", c)
        self.assertNotIn("protocol-name", c)

    def test_unconfigure_label_block(self):
        # Removal confirms the block is GONE, so a None read-back is success.
        with patch(_GETTER, return_value=None):
            unconfigure_mpls_reserved_label_block(self.d, "SRGB_BLOCK")
        self.assertIn("no mpls global reserved-label-block SRGB_BLOCK", self.d.cfg())


class TestSrmsMappingApis(unittest.TestCase):
    """configure_srms_mapping / unconfigure_srms_mapping"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_srms_mapping(self):
        configure_srms_mapping(self.d, "map1")
        self.assertIn("segment-routing srms mapping map1", self.d.cfg())

    def test_unconfigure_srms_mapping(self):
        unconfigure_srms_mapping(self.d, "map1")
        self.assertIn("no segment-routing srms mapping map1", self.d.cfg())


class TestSrmsMappingIpv4PrefixApis(unittest.TestCase):
    """configure_srms_mapping_ipv4_prefix / unconfigure_srms_mapping_ipv4_prefix"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_ipv4_prefix(self):
        configure_srms_mapping_ipv4_prefix(
            self.d, "map1", "10.0.0.0/24", 16000, 100,
        )
        c = self.d.cfg()
        self.assertIn("segment-routing srms mapping map1", c)
        self.assertIn("ipv4 prefix 10.0.0.0/24", c)
        self.assertIn("sid 16000", c)
        self.assertIn("range 100", c)

    def test_unconfigure_ipv4_prefix(self):
        unconfigure_srms_mapping_ipv4_prefix(self.d, "map1", "10.0.0.0/24")
        c = self.d.cfg()
        self.assertIn("segment-routing srms mapping map1", c)
        self.assertIn("no ipv4 prefix 10.0.0.0/24", c)


class TestSrmsMappingIpv6PrefixApis(unittest.TestCase):
    """configure_srms_mapping_ipv6_prefix / unconfigure_srms_mapping_ipv6_prefix"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_ipv6_prefix(self):
        configure_srms_mapping_ipv6_prefix(
            self.d, "map1", "2001:db8::/32", 17000, 100,
        )
        c = self.d.cfg()
        self.assertIn("segment-routing srms mapping map1", c)
        self.assertIn("ipv6 prefix 2001:db8::/32", c)
        self.assertIn("sid 17000", c)
        self.assertIn("range 100", c)

    def test_unconfigure_ipv6_prefix(self):
        unconfigure_srms_mapping_ipv6_prefix(self.d, "map1", "2001:db8::/32")
        c = self.d.cfg()
        self.assertIn("segment-routing srms mapping map1", c)
        self.assertIn("no ipv6 prefix 2001:db8::/32", c)


class TestSrv6EncapIpTtlPropagationApis(unittest.TestCase):
    """configure_srv6_encap_ip_ttl_propagation / unconfigure_srv6_encap_ip_ttl_propagation"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_ip_ttl_propagation_enabled(self):
        configure_srv6_encap_ip_ttl_propagation(self.d)
        self.assertIn("srv6 encapsulation ip-ttl-propagation true", self.d.cfg())

    def test_ip_ttl_propagation_disabled(self):
        configure_srv6_encap_ip_ttl_propagation(self.d, enabled=False)
        self.assertIn("srv6 encapsulation ip-ttl-propagation false", self.d.cfg())

    def test_unconfigure_ip_ttl_propagation(self):
        unconfigure_srv6_encap_ip_ttl_propagation(self.d)
        self.assertIn("no srv6 encapsulation ip-ttl-propagation", self.d.cfg())


class TestSrv6EncapHopLimitApis(unittest.TestCase):
    """configure_srv6_encap_hop_limit / unconfigure_srv6_encap_hop_limit"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_hop_limit(self):
        configure_srv6_encap_hop_limit(self.d, 15)
        self.assertIn("srv6 encapsulation hop-limit 15", self.d.cfg())

    def test_unconfigure_hop_limit(self):
        unconfigure_srv6_encap_hop_limit(self.d)
        self.assertIn("no srv6 encapsulation hop-limit", self.d.cfg())


class TestSegmentRoutingConfigureSubCommandFailure(unittest.TestCase):
    """Every configure_*/unconfigure_* helper catches SubCommandFailure
    from device.configure() and re-raises a SubCommandFailure wrapping it.
    Table-driven so every function's raise path gets real coverage.
    """

    # (function, args, kwargs)
    CASES = [
        (configure_srv6_encap_source_address, ("2001:db8::1",), {}),
        (unconfigure_srv6_encap_source_address, (), {}),
        (configure_srv6_locator, ("loc1", "fcbb:bb00:1::/48", 24), {}),
        (unconfigure_srv6_locator, ("loc1",), {}),
        (configure_srv6_locator_micro_segment, ("loc1",), {}),
        (unconfigure_srv6_locator_micro_segment, ("loc1",), {}),
        (configure_mpls_reserved_label_block,
         ("SRGB_BLOCK", 16000, 23999, "ISIS_SRGB", "ISIS"),
         {"verify": False}),
        (unconfigure_mpls_reserved_label_block, ("SRGB_BLOCK",),
         {"verify": False}),
        (configure_srms_mapping, ("map1",), {}),
        (unconfigure_srms_mapping, ("map1",), {}),
        (configure_srms_mapping_ipv4_prefix,
         ("map1", "10.0.0.0/24", 16000, 100), {}),
        (unconfigure_srms_mapping_ipv4_prefix, ("map1", "10.0.0.0/24"), {}),
        (configure_srms_mapping_ipv6_prefix,
         ("map1", "2001:db8::/32", 17000, 100), {}),
        (unconfigure_srms_mapping_ipv6_prefix,
         ("map1", "2001:db8::/32"), {}),
        (configure_srv6_encap_ip_ttl_propagation, (), {}),
        (unconfigure_srv6_encap_ip_ttl_propagation, (), {}),
        (configure_srv6_encap_hop_limit, (15,), {}),
        (unconfigure_srv6_encap_hop_limit, (), {}),
    ]

    def test_subcommand_failure_reraised_for_every_function(self):
        for func, args, kwargs in self.CASES:
            with self.subTest(func=func.__name__):
                device = _CfgDevice()
                device.configure = Mock(side_effect=SubCommandFailure("nope"))
                with self.assertRaises(SubCommandFailure):
                    func(device, *args, **kwargs)


class TestSegmentRoutingConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in segment_routing/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sr_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sr_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Segment Routing configure/unconfigure functions: "
            f"{missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nSegment Routing configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
