#!/usr/bin/env python3
"""Unit tests for arcOS VRRP configure/unconfigure APIs (full coverage).

Both helpers build an arcOS CLI config list under
`interface <intf> subinterface <sub> <af> address <address>
vrrp vrrp-group <vrid>` and call device.configure(list). Tests mock
device.configure and assert on the emitted CLI, plus the SubCommandFailure
error-wrapping path.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.vrrp import configure as vrrp_configure
from genie.libs.sdk.apis.arcos.vrrp.configure import (
    configure_vrrp_group,
    unconfigure_vrrp_group,
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
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(side_effect=SubCommandFailure("boom"))


class TestConfigureVrrpGroup(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_minimal_required_only(self):
        """Only mandatory args set -- no optional lines emitted."""
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10,
        )
        c = self.d.cfg()
        self.assertIn("interface swp10", c)
        self.assertIn("subinterface 0", c)
        self.assertIn("ipv4 address 172.16.1.1", c)
        self.assertIn("prefix-length 24", c)
        self.assertIn("vrrp vrrp-group 10", c)
        self.assertNotIn("virtual-address", c)
        self.assertNotIn("priority", c)
        self.assertNotIn("advertisement-interval", c)
        self.assertNotIn("accept-mode", c)
        self.assertNotIn("vrrp-version", c)
        self.assertNotIn("virtual-link-local", c)

    def test_virtual_addresses_list(self):
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10,
            virtual_addresses=["172.16.1.100", "172.16.1.101"],
        )
        self.assertIn(
            "virtual-address [ 172.16.1.100 172.16.1.101 ]", self.d.cfg()
        )

    def test_virtual_addresses_single_string(self):
        """Non list/tuple virtual_addresses -- exercises the str() branch."""
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10,
            virtual_addresses="172.16.1.100",
        )
        self.assertIn("virtual-address [ 172.16.1.100 ]", self.d.cfg())

    def test_priority(self):
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10, priority=200,
        )
        self.assertIn("priority 200", self.d.cfg())

    def test_advertisement_interval(self):
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10,
            advertisement_interval=300,
        )
        self.assertIn("advertisement-interval 300", self.d.cfg())

    def test_accept_mode_true(self):
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10,
            accept_mode=True,
        )
        self.assertIn("accept-mode true", self.d.cfg())

    def test_accept_mode_false(self):
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10,
            accept_mode=False,
        )
        self.assertIn("accept-mode false", self.d.cfg())

    def test_vrrp_version(self):
        configure_vrrp_group(
            self.d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10,
            vrrp_version="VRRP_V3",
        )
        self.assertIn("vrrp-version VRRP_V3", self.d.cfg())

    def test_virtual_link_local(self):
        configure_vrrp_group(
            self.d, "swp11", 0, "ipv6", "2001:db8::1", 64, 20,
            virtual_link_local="fe80::1",
        )
        self.assertIn("virtual-link-local fe80::1", self.d.cfg())

    def test_all_optional_together(self):
        configure_vrrp_group(
            self.d, "swp12", 1, "ipv4", "10.2.2.2", 30, 30,
            virtual_addresses=["10.2.2.100"],
            priority=150,
            advertisement_interval=100,
            accept_mode=True,
            vrrp_version="VRRP_V2_V3",
        )
        c = self.d.cfg()
        self.assertIn("interface swp12", c)
        self.assertIn("subinterface 1", c)
        self.assertIn("ipv4 address 10.2.2.2", c)
        self.assertIn("prefix-length 30", c)
        self.assertIn("vrrp vrrp-group 30", c)
        self.assertIn("virtual-address [ 10.2.2.100 ]", c)
        self.assertIn("priority 150", c)
        self.assertIn("advertisement-interval 100", c)
        self.assertIn("accept-mode true", c)
        self.assertIn("vrrp-version VRRP_V2_V3", c)

    def test_configure_raises_subcommandfailure(self):
        """device.configure() failure is wrapped and re-raised."""
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_vrrp_group(d, "swp10", 0, "ipv4", "172.16.1.1", 24, 10)


class TestUnconfigureVrrpGroup(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_unconfigure_basic(self):
        unconfigure_vrrp_group(self.d, "swp10", 0, "ipv4", "172.16.1.1", 10)
        c = self.d.cfg()
        self.assertIn("interface swp10", c)
        self.assertIn("subinterface 0", c)
        self.assertIn("ipv4 address 172.16.1.1", c)
        self.assertIn("no vrrp vrrp-group 10", c)

    def test_unconfigure_raises_subcommandfailure(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_vrrp_group(d, "swp10", 0, "ipv4", "172.16.1.1", 10)


class TestVrrpConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in vrrp/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(vrrp_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == vrrp_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered VRRP configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nVRRP configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
