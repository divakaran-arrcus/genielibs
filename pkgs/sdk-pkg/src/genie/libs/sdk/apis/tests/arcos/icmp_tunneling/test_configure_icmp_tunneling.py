#!/usr/bin/env python3
"""Unit tests for arcOS MPLS ICMP tunneling configure/unconfigure APIs
(full coverage).

ArcOS ICMP tunneling uses the default network-instance context:

    network-instance default
        mpls global config icmp-tunnelling <true|false>

unconfigure_icmp_tunneling delegates to configure_icmp_tunneling(enabled=
False), so its device.configure() call -- and therefore its
SubCommandFailure wrapping path -- is exercised entirely through the
delegate. Tests mock device.configure and assert the emitted CLI, plus
exercise the SubCommandFailure wrapping branch for both the direct and
delegating helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.icmp_tunneling import (
    configure as icmp_tunneling_configure,
)
from genie.libs.sdk.apis.arcos.icmp_tunneling.configure import (
    configure_icmp_tunneling,
    unconfigure_icmp_tunneling,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestIcmpTunnelingApis(unittest.TestCase):
    """configure_icmp_tunneling, unconfigure_icmp_tunneling"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_icmp_tunneling_default_enabled(self):
        configure_icmp_tunneling(self.d)
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("mpls global config icmp-tunnelling true", c)

    def test_icmp_tunneling_disabled(self):
        configure_icmp_tunneling(self.d, enabled=False)
        self.assertIn("mpls global config icmp-tunnelling false", self.d.cfg())

    def test_unconfigure_icmp_tunneling_delegates(self):
        """unconfigure_icmp_tunneling delegates to
        configure_icmp_tunneling(enabled=False)."""
        unconfigure_icmp_tunneling(self.d)
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("mpls global config icmp-tunnelling false", c)


class TestSubCommandFailureWrapping(unittest.TestCase):
    """configure_icmp_tunneling wraps a device.configure() failure in a
    re-raised SubCommandFailure with a descriptive message. The delegating
    unconfigure_icmp_tunneling inherits this failure path."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_icmp_tunneling_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_icmp_tunneling(self.d)

    def test_unconfigure_icmp_tunneling_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_icmp_tunneling(self.d)


class TestIcmpTunnelingConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in icmp_tunneling/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(icmp_tunneling_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == icmp_tunneling_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered ICMP tunneling configure/unconfigure functions: "
            f"{missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nICMP tunneling configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
