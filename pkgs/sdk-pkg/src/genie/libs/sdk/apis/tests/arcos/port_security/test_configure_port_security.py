#!/usr/bin/env python3
"""Unit tests for arcOS Port Security configure/unconfigure APIs (full
coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.port_security.configure builds either a
`port-security profile <name>` context or an `interface <intf>` context
CLI config list and calls `device.configure(config)`. Tests mock
device.configure and assert on a distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.port_security import configure as ps_configure
from genie.libs.sdk.apis.arcos.port_security.configure import (
    configure_port_security_profile,
    unconfigure_port_security_profile,
    configure_port_security_interface,
    unconfigure_port_security_interface,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigurePortSecurityProfile(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_profile_defaults(self):
        configure_port_security_profile(self.d, "PROF1", 5)
        c = self.d.cfg()
        self.assertIn("port-security profile PROF1", c)
        self.assertIn("limit 5", c)
        self.assertIn("sticky false", c)
        self.assertIn("violation-policy restrict", c)

    def test_configure_profile_sticky_and_shutdown(self):
        configure_port_security_profile(
            self.d, "PROF2", 10, sticky=True, violation_policy="port-shut"
        )
        c = self.d.cfg()
        self.assertIn("limit 10", c)
        self.assertIn("sticky true", c)
        self.assertIn("violation-policy port-shut", c)

    def test_unconfigure_profile(self):
        unconfigure_port_security_profile(self.d, "PROF1")
        self.assertIn("no port-security profile PROF1", self.d.cfg())


class TestConfigurePortSecurityInterface(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_interface_defaults(self):
        configure_port_security_interface(self.d, "swp1", "PROF1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("port-security profile PROF1", c)
        self.assertIn("enable true", c)
        self.assertNotIn("static-mac-list", c)

    def test_configure_interface_disabled(self):
        configure_port_security_interface(self.d, "swp2", "PROF1", enabled=False)
        c = self.d.cfg()
        self.assertIn("enable false", c)

    def test_configure_interface_static_mac_list(self):
        configure_port_security_interface(
            self.d, "swp3", "PROF1",
            static_mac_list=["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"],
        )
        c = self.d.cfg()
        self.assertIn(
            "static-mac-list [ 00:11:22:33:44:55 aa:bb:cc:dd:ee:ff ]", c
        )

    def test_configure_interface_static_mac_string(self):
        configure_port_security_interface(
            self.d, "swp4", "PROF1", static_mac_list="00:11:22:33:44:55"
        )
        c = self.d.cfg()
        self.assertIn("static-mac-list [ 00:11:22:33:44:55 ]", c)

    def test_unconfigure_interface(self):
        unconfigure_port_security_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("no port-security", c)


class TestConfigurePortSecurityErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context."""

    def setUp(self):
        self.d = _CfgDevice()

    def _fail(self):
        from unicon.core.errors import SubCommandFailure
        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))

    def test_configure_profile_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_port_security_profile(self.d, "PROF1", 5)

    def test_unconfigure_profile_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_port_security_profile(self.d, "PROF1")

    def test_configure_interface_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_port_security_interface(self.d, "swp1", "PROF1")

    def test_unconfigure_interface_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_port_security_interface(self.d, "swp1")


class TestPortSecurityConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in port_security/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ps_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ps_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Port Security configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nPort Security configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
