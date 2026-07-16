#!/usr/bin/env python3
"""Unit tests for arcOS LDP configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under
`network-instance default mpls signaling-protocols ldp` (or a neighbor/
interface sub-context) and calls device.configure(list). Tests mock
device.configure and assert on a distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.ldp import configure as ldp_configure
from genie.libs.sdk.apis.arcos.ldp.configure import (
    configure_ldp_global,
    unconfigure_ldp_global,
    configure_ldp_enable,
    unconfigure_ldp_enable,
    configure_ldp_interface,
    unconfigure_ldp_interface,
    configure_ldp_targeted,
    unconfigure_ldp_targeted,
    configure_ldp_neighbor,
    unconfigure_ldp_neighbor,
    configure_ldp_authentication,
    unconfigure_ldp_authentication,
    configure_ldp_rib_preference,
    unconfigure_ldp_rib_preference,
    configure_ldp_session_protection,
    unconfigure_ldp_session_protection,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureLdpGlobal(unittest.TestCase):
    """configure_ldp_global / unconfigure_ldp_global"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_global_basic(self):
        configure_ldp_global(self.d, "10.0.0.1", "10.0.0.1")
        c = self.d.cfg()
        self.assertIn(
            "network-instance default mpls signaling-protocols ldp "
            "global lsr-id 10.0.0.1", c)
        self.assertIn("global enable true", c)
        self.assertIn(
            "global fec-filter default-export-policy ACCEPT_ROUTE", c)
        self.assertIn("global transport-address ipv4 10.0.0.1", c)
        self.assertNotIn("php-type", c)

    def test_global_with_php_type(self):
        configure_ldp_global(
            self.d, "10.0.0.1", "10.0.0.2", php_type="EXPLICIT")
        self.assertIn("global attributes php-type EXPLICIT", self.d.cfg())

    def test_global_custom_fec_policy(self):
        configure_ldp_global(
            self.d, "10.0.0.1", "10.0.0.1", fec_default_policy="DENY_ROUTE")
        self.assertIn(
            "global fec-filter default-export-policy DENY_ROUTE",
            self.d.cfg())

    def test_unconfigure_global(self):
        unconfigure_ldp_global(self.d)
        c = self.d.cfg()
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global lsr-id", c)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global transport-address ipv4", c)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global fec-filter default-export-policy", c)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global attributes php-type", c)


class TestConfigureLdpEnable(unittest.TestCase):
    """configure_ldp_enable / unconfigure_ldp_enable"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_enable_true_default(self):
        configure_ldp_enable(self.d)
        self.assertIn("global enable true", self.d.cfg())

    def test_enable_false(self):
        configure_ldp_enable(self.d, enabled=False)
        self.assertIn("global enable false", self.d.cfg())

    def test_unconfigure_enable(self):
        unconfigure_ldp_enable(self.d)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global enable", self.d.cfg())


class TestConfigureLdpInterface(unittest.TestCase):
    """configure_ldp_interface / unconfigure_ldp_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface_basic(self):
        configure_ldp_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface-attributes interface swp1", c)
        self.assertIn("link-hello true", c)
        self.assertIn("address-family IPV4", c)
        self.assertIn("enabled true", c)

    def test_interface_ipv4_disabled(self):
        configure_ldp_interface(self.d, "swp2", ipv4_enabled=False)
        self.assertIn("enabled false", self.d.cfg())

    def test_unconfigure_interface(self):
        unconfigure_ldp_interface(self.d, "swp1")
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "interface-attributes interface swp1", self.d.cfg())


class TestConfigureLdpTargeted(unittest.TestCase):
    """configure_ldp_targeted / unconfigure_ldp_targeted"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_targeted_defaults(self):
        configure_ldp_targeted(self.d)
        c = self.d.cfg()
        self.assertIn("targeted hello-accept true", c)
        self.assertIn("targeted hello-holdtime 45", c)
        self.assertIn("targeted hello-interval 15", c)
        self.assertNotIn("strict-targeted-hellos", c)

    def test_targeted_with_strict_and_custom_timers(self):
        configure_ldp_targeted(
            self.d, hello_accept=False, hello_holdtime=60,
            hello_interval=20, strict=True)
        c = self.d.cfg()
        self.assertIn("targeted hello-accept false", c)
        self.assertIn("targeted hello-holdtime 60", c)
        self.assertIn("targeted hello-interval 20", c)
        self.assertIn("targeted strict-targeted-hellos true", c)

    def test_unconfigure_targeted(self):
        unconfigure_ldp_targeted(self.d)
        c = self.d.cfg()
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "targeted hello-accept", c)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "targeted hello-holdtime", c)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "targeted hello-interval", c)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "targeted strict-targeted-hellos", c)


class TestConfigureLdpNeighbor(unittest.TestCase):
    """configure_ldp_neighbor / unconfigure_ldp_neighbor"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_neighbor_basic(self):
        configure_ldp_neighbor(self.d, "1.1.1.1")
        c = self.d.cfg()
        self.assertIn("neighbor 1.1.1.1 0", c)
        self.assertIn("targeted address-family IPV4", c)
        self.assertIn("enabled true", c)

    def test_neighbor_with_label_space_and_dest(self):
        configure_ldp_neighbor(
            self.d, "1.1.1.1", label_space_id=1,
            targeted_ipv4_dest="9.9.9.9")
        c = self.d.cfg()
        self.assertIn("neighbor 1.1.1.1 1", c)
        self.assertIn("destination-address 9.9.9.9", c)

    def test_neighbor_no_targeted(self):
        configure_ldp_neighbor(self.d, "1.1.1.1", targeted_ipv4=False)
        c = self.d.cfg()
        self.assertIn("neighbor 1.1.1.1 0", c)
        self.assertNotIn("targeted address-family", c)

    def test_unconfigure_neighbor(self):
        unconfigure_ldp_neighbor(self.d, "1.1.1.1")
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "neighbor 1.1.1.1 0", self.d.cfg())

    def test_unconfigure_neighbor_custom_label_space(self):
        unconfigure_ldp_neighbor(self.d, "2.2.2.2", label_space_id=5)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "neighbor 2.2.2.2 5", self.d.cfg())


class TestConfigureLdpAuthentication(unittest.TestCase):
    """configure_ldp_authentication / unconfigure_ldp_authentication"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_auth_global(self):
        configure_ldp_authentication(self.d, "mykey123")
        c = self.d.cfg()
        self.assertIn("global authentication enable true", c)
        self.assertIn(
            "global authentication authentication-key mykey123", c)

    def test_auth_per_neighbor(self):
        configure_ldp_authentication(self.d, "peerkey", lsr_id="1.1.1.1")
        c = self.d.cfg()
        self.assertIn("neighbor 1.1.1.1 0", c)
        self.assertIn("authentication enable true", c)
        self.assertIn("authentication authentication-key peerkey", c)

    def test_unconfigure_auth_global(self):
        unconfigure_ldp_authentication(self.d)
        c = self.d.cfg()
        self.assertIn("global authentication enable false", c)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global authentication authentication-key", c)

    def test_unconfigure_auth_per_neighbor(self):
        unconfigure_ldp_authentication(self.d, lsr_id="1.1.1.1")
        c = self.d.cfg()
        self.assertIn("neighbor 1.1.1.1 0", c)
        self.assertIn("authentication enable false", c)
        self.assertIn("no authentication authentication-key", c)


class TestConfigureLdpRibPreference(unittest.TestCase):
    """configure_ldp_rib_preference / unconfigure_ldp_rib_preference"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_rib_preference(self):
        configure_ldp_rib_preference(self.d, 20)
        self.assertIn("global rib-preference 20", self.d.cfg())

    def test_unconfigure_rib_preference(self):
        unconfigure_ldp_rib_preference(self.d)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global rib-preference", self.d.cfg())


class TestConfigureLdpSessionProtection(unittest.TestCase):
    """configure_ldp_session_protection / unconfigure_ldp_session_protection"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_session_protection(self):
        configure_ldp_session_protection(self.d, 60)
        self.assertIn("global session-protection 60", self.d.cfg())

    def test_session_protection_infinite(self):
        configure_ldp_session_protection(self.d, 0)
        self.assertIn("global session-protection 0", self.d.cfg())

    def test_unconfigure_session_protection(self):
        unconfigure_ldp_session_protection(self.d)
        self.assertIn(
            "no network-instance default mpls signaling-protocols ldp "
            "global session-protection", self.d.cfg())


class TestLdpConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in ldp/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ldp_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ldp_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered LDP configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nLDP configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
