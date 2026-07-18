#!/usr/bin/env python3
"""Unit tests for arcOS DHCP Relay configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under the `relay-agent dhcp` (v4)
or `relay-agent dhcpv6` (v6) context -- global or per-interface -- and calls
device.configure(list). Tests mock device.configure and assert the emitted
CLI. A machine coverage check
(TestDhcpRelayConfigureCoverage.test_zzz_all_functions_covered) asserts that
every public configure_*/unconfigure_* function in the module was exercised
by some test in this file.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.dhcp_relay.configure as configure_module
from genie.libs.sdk.apis.arcos.dhcp_relay.configure import (
    configure_dhcp_relay_helper,
    unconfigure_dhcp_relay_helper,
    configure_dhcp_relay_interface,
    unconfigure_dhcp_relay_interface,
    configure_dhcpv6_relay_helper,
    unconfigure_dhcpv6_relay_helper,
    configure_dhcpv6_relay_interface,
    unconfigure_dhcpv6_relay_interface,
)

# ---------------------------------------------------------------------------
# Machine coverage tracking: wrap each imported function so calling it during
# a test records its name. The final test asserts every public function in
# the module was called at least once.
# ---------------------------------------------------------------------------
_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


configure_dhcp_relay_helper = _track(
    "configure_dhcp_relay_helper", configure_dhcp_relay_helper
)
unconfigure_dhcp_relay_helper = _track(
    "unconfigure_dhcp_relay_helper", unconfigure_dhcp_relay_helper
)
configure_dhcp_relay_interface = _track(
    "configure_dhcp_relay_interface", configure_dhcp_relay_interface
)
unconfigure_dhcp_relay_interface = _track(
    "unconfigure_dhcp_relay_interface", unconfigure_dhcp_relay_interface
)
configure_dhcpv6_relay_helper = _track(
    "configure_dhcpv6_relay_helper", configure_dhcpv6_relay_helper
)
unconfigure_dhcpv6_relay_helper = _track(
    "unconfigure_dhcpv6_relay_helper", unconfigure_dhcpv6_relay_helper
)
configure_dhcpv6_relay_interface = _track(
    "configure_dhcpv6_relay_interface", configure_dhcpv6_relay_interface
)
unconfigure_dhcpv6_relay_interface = _track(
    "unconfigure_dhcpv6_relay_interface", unconfigure_dhcpv6_relay_interface
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureDhcpRelayHelper(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_dhcp_relay_helper_single(self):
        configure_dhcp_relay_helper(self.d, "10.0.0.5")
        c = self.d.cfg()
        self.assertIn("relay-agent dhcp", c)
        self.assertIn("helper-address 10.0.0.5", c)

    def test_configure_dhcp_relay_helper_list(self):
        configure_dhcp_relay_helper(self.d, ["10.0.0.5", "10.0.0.6"])
        c = self.d.cfg()
        self.assertIn("relay-agent dhcp", c)
        self.assertIn("helper-address [ 10.0.0.5 10.0.0.6 ]", c)

    def test_unconfigure_dhcp_relay_helper(self):
        unconfigure_dhcp_relay_helper(self.d)
        c = self.d.cfg()
        self.assertIn("relay-agent dhcp", c)
        self.assertIn("no helper-address", c)


class TestConfigureDhcpRelayInterface(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_dhcp_relay_interface_minimal(self):
        configure_dhcp_relay_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("relay-agent dhcp interface swp1", c)
        self.assertIn("enable true", c)

    def test_configure_dhcp_relay_interface_all_options(self):
        configure_dhcp_relay_interface(
            self.d, "swp1", helper_addresses=["10.0.0.5", "10.0.0.6"],
            server_vrf="mgmt", option82=True, circuit_id="circuit1",
            circuit_id_format="HOSTNAME_PORT",
        )
        c = self.d.cfg()
        self.assertIn("relay-agent dhcp interface swp1", c)
        self.assertIn("helper-address [ 10.0.0.5 10.0.0.6 ]", c)
        self.assertIn("server-vrf mgmt", c)
        self.assertIn("agent-information-option enable true", c)
        self.assertIn("agent-information-option circuit-id circuit1", c)
        self.assertIn(
            "agent-information-option circuit-id-format HOSTNAME_PORT", c
        )

    def test_configure_dhcp_relay_interface_single_helper(self):
        configure_dhcp_relay_interface(self.d, "swp2", helper_addresses="10.0.0.9")
        c = self.d.cfg()
        self.assertIn("helper-address 10.0.0.9", c)

    def test_unconfigure_dhcp_relay_interface(self):
        unconfigure_dhcp_relay_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("relay-agent dhcp interface swp1", c)
        self.assertIn("enable false", c)


class TestConfigureDhcpv6RelayHelper(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_dhcpv6_relay_helper_single(self):
        configure_dhcpv6_relay_helper(self.d, "2001:db8::1")
        c = self.d.cfg()
        self.assertIn("relay-agent dhcpv6", c)
        self.assertIn("helper-address 2001:db8::1", c)

    def test_configure_dhcpv6_relay_helper_list(self):
        configure_dhcpv6_relay_helper(self.d, ["2001:db8::1", "2001:db8::2"])
        c = self.d.cfg()
        self.assertIn("relay-agent dhcpv6", c)
        self.assertIn("helper-address [ 2001:db8::1 2001:db8::2 ]", c)

    def test_unconfigure_dhcpv6_relay_helper(self):
        unconfigure_dhcpv6_relay_helper(self.d)
        c = self.d.cfg()
        self.assertIn("relay-agent dhcpv6", c)
        self.assertIn("no helper-address", c)


class TestConfigureDhcpv6RelayInterface(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_dhcpv6_relay_interface_minimal(self):
        configure_dhcpv6_relay_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("relay-agent dhcpv6 interface swp1", c)
        self.assertIn("enable true", c)

    def test_configure_dhcpv6_relay_interface_all_options(self):
        configure_dhcpv6_relay_interface(
            self.d, "swp1", helper_addresses=["2001:db8::1"],
            server_vrf="mgmt", enable_interface_id=True,
        )
        c = self.d.cfg()
        self.assertIn("relay-agent dhcpv6 interface swp1", c)
        self.assertIn("helper-address [ 2001:db8::1 ]", c)
        self.assertIn("server-vrf mgmt", c)
        self.assertIn("options enable-interface-id true", c)

    def test_configure_dhcpv6_relay_interface_single_helper(self):
        configure_dhcpv6_relay_interface(
            self.d, "swp2", helper_addresses="2001:db8::9"
        )
        c = self.d.cfg()
        self.assertIn("helper-address 2001:db8::9", c)

    def test_unconfigure_dhcpv6_relay_interface(self):
        unconfigure_dhcpv6_relay_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("relay-agent dhcpv6 interface swp1", c)
        self.assertIn("enable false", c)


class TestConfigureDhcpRelayFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_dhcp_relay_helper_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_dhcp_relay_helper(self.d, "10.0.0.5")

    def test_unconfigure_dhcp_relay_helper_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_dhcp_relay_helper(self.d)

    def test_configure_dhcp_relay_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_dhcp_relay_interface(self.d, "swp1")

    def test_unconfigure_dhcp_relay_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_dhcp_relay_interface(self.d, "swp1")

    def test_configure_dhcpv6_relay_helper_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_dhcpv6_relay_helper(self.d, "2001:db8::1")

    def test_unconfigure_dhcpv6_relay_helper_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_dhcpv6_relay_helper(self.d)

    def test_configure_dhcpv6_relay_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_dhcpv6_relay_interface(self.d, "swp1")

    def test_unconfigure_dhcpv6_relay_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_dhcpv6_relay_interface(self.d, "swp1")


class TestDhcpRelayConfigureCoverage(unittest.TestCase):
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in configure.py
        must have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(configure_module, inspect.isfunction)
            if obj.__module__ == configure_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in dhcp_relay/configure.py: {sorted(missing)}",
        )

        configure_count = sum(1 for n in public_fns if n.startswith("configure_"))
        unconfigure_count = sum(1 for n in public_fns if n.startswith("unconfigure_"))
        print(
            f"\nDHCP Relay configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(public_fns)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
