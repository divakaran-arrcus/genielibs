#!/usr/bin/env python3
"""Unit tests for arcOS ACL configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.acl.configure builds an arcOS CLI config list
(an `acl acl-set <name> <type>` block, a control-plane acl-service-policy
context, an acl-counter, or a defined-sets prefix-set) and calls
`device.configure(config)`. Tests mock `device.configure` and assert on a
distinctive substring of the emitted CLI, plus the SubCommandFailure wrap
path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.acl import configure as acl_configure
from genie.libs.sdk.apis.arcos.acl.configure import (
    configure_acl_set,
    unconfigure_acl_set,
    configure_acl_counter,
    unconfigure_acl_counter,
    configure_control_plane_acl,
    unconfigure_control_plane_acl,
    configure_defined_sets_ipv4_prefix_set,
    unconfigure_defined_sets_ipv4_prefix_set,
    configure_defined_sets_ipv6_prefix_set,
    unconfigure_defined_sets_ipv6_prefix_set,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class _FailingDevice:
    """Device whose .configure() always raises SubCommandFailure."""

    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(side_effect=SubCommandFailure("boom"))


class TestConfigureAclSet(unittest.TestCase):
    """configure_acl_set / unconfigure_acl_set"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_acl_set_basic(self):
        configure_acl_set(
            self.d, "v4-acl", "ACL_IPV4",
            entries=[
                {"sequence_id": 10, "ipv4_source_address": "10.0.0.0/8",
                 "forwarding_action": "DROP"},
            ],
        )
        c = self.d.cfg()
        self.assertIn("acl acl-set v4-acl ACL_IPV4", c)
        self.assertIn("acl-entry 10", c)
        self.assertIn("ipv4 source-address 10.0.0.0/8", c)
        self.assertIn("actions forwarding-action DROP", c)

    def test_acl_set_with_description(self):
        configure_acl_set(
            self.d, "v4-acl", "ACL_IPV4",
            entries=[], description="user ACL",
        )
        self.assertIn("description user ACL", self.d.cfg())

    def test_acl_set_entry_skipped_without_sequence_id(self):
        configure_acl_set(
            self.d, "v4-acl", "ACL_IPV4",
            entries=[{"forwarding_action": "ACCEPT"}],
        )
        # No sequence id -> entry dropped entirely, only header/footer remain
        self.assertNotIn("acl-entry", self.d.cfg())

    def test_acl_set_entry_full_ipv4_ipv6_l2_transport(self):
        configure_acl_set(
            self.d, "full-acl", "ACL_IPV4",
            entries=[{
                "sequence_id": 100,
                "description": "full entry",
                "ipv4_source_address": "192.168.1.0/24",
                "ipv4_destination_address": "10.10.0.0/16",
                "ipv4_source_address_prefix_set": "SRC-SET",
                "ipv4_destination_address_prefix_set": "DST-SET",
                "ipv4_protocol": "TCP",
                "ipv4_dscp": "10",
                "ipv4_hop_limit": "64",
                "ipv4_packet_length": "1500",
                "ipv6_source_address": "2001:db8::/32",
                "ipv6_destination_address": "2001:db8:1::/48",
                "ipv6_source_address_prefix_set": "SRC-SET6",
                "ipv6_destination_address_prefix_set": "DST-SET6",
                "ipv6_protocol": "UDP",
                "ipv6_dscp": "20",
                "ipv6_hop_limit": "32",
                "ipv6_packet_length": "512",
                "ipv6_source_flow_label": "1234",
                "l2_source_mac": "aa:bb:cc:dd:ee:ff",
                "l2_source_mac_mask": "ff:ff:ff:00:00:00",
                "l2_destination_mac": "11:22:33:44:55:66",
                "l2_destination_mac_mask": "ff:ff:ff:ff:ff:00",
                "l2_ethertype": "IPV4",
                "transport_source_port": 12345,
                "transport_destination_port": 443,
                "acl_counter": "custom-counter1",
                "forwarding_action": "ACCEPT",
                "log_action": "LOG_SYSLOG",
                "redirect_ipv4_next_hop": "10.0.0.1",
                "redirect_ipv4_network_instance": "vrf-red",
                "redirect_ipv6_next_hop": "2001:db8::1",
                "redirect_ipv6_network_instance": "vrf-blue",
            }],
        )
        c = self.d.cfg()
        self.assertIn("description full entry", c)
        self.assertIn("ipv4 source-address 192.168.1.0/24", c)
        self.assertIn("ipv4 destination-address 10.10.0.0/16", c)
        self.assertIn("ipv4 source-address-prefix-set SRC-SET", c)
        self.assertIn("ipv4 destination-address-prefix-set DST-SET", c)
        self.assertIn("ipv4 protocol TCP", c)
        self.assertIn("ipv4 dscp 10", c)
        self.assertIn("ipv4 hop-limit 64", c)
        self.assertIn("ipv4 packet-length 1500", c)
        self.assertIn("ipv6 source-address 2001:db8::/32", c)
        self.assertIn("ipv6 destination-address 2001:db8:1::/48", c)
        self.assertIn("ipv6 source-address-prefix-set SRC-SET6", c)
        self.assertIn("ipv6 destination-address-prefix-set DST-SET6", c)
        self.assertIn("ipv6 protocol UDP", c)
        self.assertIn("ipv6 dscp 20", c)
        self.assertIn("ipv6 hop-limit 32", c)
        self.assertIn("ipv6 packet-length 512", c)
        self.assertIn("ipv6 source-flow-label 1234", c)
        self.assertIn("l2 source-mac aa:bb:cc:dd:ee:ff", c)
        self.assertIn("l2 source-mac-mask ff:ff:ff:00:00:00", c)
        self.assertIn("l2 destination-mac 11:22:33:44:55:66", c)
        self.assertIn("l2 destination-mac-mask ff:ff:ff:ff:ff:00", c)
        self.assertIn("l2 ethertype IPV4", c)
        self.assertIn("transport source-port 12345", c)
        self.assertIn("transport destination-port 443", c)
        self.assertIn("acl-counter custom-counter1", c)
        self.assertIn("actions forwarding-action ACCEPT", c)
        self.assertIn("actions log-action LOG_SYSLOG", c)
        self.assertIn("actions ipv4-redirect next-hop 10.0.0.1", c)
        self.assertIn("actions ipv4-redirect network-instance vrf-red", c)
        self.assertIn("actions ipv6-redirect next-hop 2001:db8::1", c)
        self.assertIn("actions ipv6-redirect network-instance vrf-blue", c)

    def test_acl_set_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_acl_set(d, "v4-acl", "ACL_IPV4", entries=[])

    def test_unconfigure_acl_set(self):
        unconfigure_acl_set(self.d, "v4-acl", "ACL_IPV4")
        self.assertIn("no acl acl-set v4-acl ACL_IPV4", self.d.cfg())

    def test_unconfigure_acl_set_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_acl_set(d, "v4-acl", "ACL_IPV4")


class TestConfigureAclCounter(unittest.TestCase):
    """configure_acl_counter / unconfigure_acl_counter"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_acl_counter(self):
        configure_acl_counter(self.d, "custom-counter1")
        self.assertIn("acl acl-counter custom-counter1", self.d.cfg())

    def test_acl_counter_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_acl_counter(d, "custom-counter1")

    def test_unconfigure_acl_counter(self):
        unconfigure_acl_counter(self.d, "custom-counter1")
        self.assertIn("no acl acl-counter custom-counter1", self.d.cfg())

    def test_unconfigure_acl_counter_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_acl_counter(d, "custom-counter1")


class TestConfigureControlPlaneAcl(unittest.TestCase):
    """configure_control_plane_acl / unconfigure_control_plane_acl"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_control_plane_acl(self):
        configure_control_plane_acl(self.d, "ACL_IPV4", "USER-CP-ACL")
        c = self.d.cfg()
        self.assertIn(
            "control-plane acl-service-policies ingress-acl-sets", c)
        self.assertIn("acl-set ACL_IPV4", c)
        self.assertIn("set-name USER-CP-ACL", c)

    def test_control_plane_acl_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_control_plane_acl(d, "ACL_IPV4", "USER-CP-ACL")

    def test_unconfigure_control_plane_acl(self):
        unconfigure_control_plane_acl(self.d, "ACL_IPV4")
        c = self.d.cfg()
        self.assertIn(
            "control-plane acl-service-policies ingress-acl-sets", c)
        self.assertIn("no acl-set ACL_IPV4", c)

    def test_unconfigure_control_plane_acl_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_control_plane_acl(d, "ACL_IPV4")


class TestConfigureDefinedSetsIpv4PrefixSet(unittest.TestCase):
    """configure_defined_sets_ipv4_prefix_set /
    unconfigure_defined_sets_ipv4_prefix_set"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_prefix_set_list(self):
        configure_defined_sets_ipv4_prefix_set(
            self.d, "DNS-SERVER", ["10.0.0.0/8", "172.16.0.0/12"])
        c = self.d.cfg()
        self.assertIn("defined-sets ipv4-prefix-set DNS-SERVER", c)
        self.assertIn("prefix [ 10.0.0.0/8 172.16.0.0/12 ]", c)

    def test_prefix_set_scalar(self):
        configure_defined_sets_ipv4_prefix_set(
            self.d, "DNS-SERVER", "10.0.0.0/8")
        self.assertIn("prefix [ 10.0.0.0/8 ]", self.d.cfg())

    def test_prefix_set_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_defined_sets_ipv4_prefix_set(d, "DNS-SERVER", ["10.0.0.0/8"])

    def test_unconfigure_prefix_set(self):
        unconfigure_defined_sets_ipv4_prefix_set(self.d, "DNS-SERVER")
        self.assertIn("no defined-sets ipv4-prefix-set DNS-SERVER", self.d.cfg())

    def test_unconfigure_prefix_set_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_defined_sets_ipv4_prefix_set(d, "DNS-SERVER")


class TestConfigureDefinedSetsIpv6PrefixSet(unittest.TestCase):
    """configure_defined_sets_ipv6_prefix_set /
    unconfigure_defined_sets_ipv6_prefix_set"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_prefix_set_list(self):
        configure_defined_sets_ipv6_prefix_set(
            self.d, "LOCAL-HOST", ["::1/128", "2001:db8::/32"])
        c = self.d.cfg()
        self.assertIn("defined-sets ipv6-prefix-set LOCAL-HOST", c)
        self.assertIn("prefix [ ::1/128 2001:db8::/32 ]", c)

    def test_prefix_set_scalar(self):
        configure_defined_sets_ipv6_prefix_set(self.d, "LOCAL-HOST", "::1/128")
        self.assertIn("prefix [ ::1/128 ]", self.d.cfg())

    def test_prefix_set_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_defined_sets_ipv6_prefix_set(d, "LOCAL-HOST", ["::1/128"])

    def test_unconfigure_prefix_set(self):
        unconfigure_defined_sets_ipv6_prefix_set(self.d, "LOCAL-HOST")
        self.assertIn("no defined-sets ipv6-prefix-set LOCAL-HOST", self.d.cfg())

    def test_unconfigure_prefix_set_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_defined_sets_ipv6_prefix_set(d, "LOCAL-HOST")


class TestAclConfigureFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in acl/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(acl_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == acl_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered ACL configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nACL configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
