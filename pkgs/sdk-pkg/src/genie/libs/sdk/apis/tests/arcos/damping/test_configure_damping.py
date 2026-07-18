#!/usr/bin/env python3
"""Unit tests for arcOS interface damping configure/unconfigure APIs
(full coverage).

ArcOS interface damping uses an interface sub-context:

    interface <name>
        damping enabled true
        damping max-suppress-time <ms>
        damping decay-half-life <ms>
        damping suppress-threshold <ms>
        damping reuse-threshold <ms>
        damping flap-penalty <ms>

Each helper builds a CLI config list and calls device.configure(list).
Tests mock device.configure and assert the emitted CLI (including default
and overridden parameter values), plus exercise the SubCommandFailure
wrapping branch for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.damping import configure as damping_configure
from genie.libs.sdk.apis.arcos.damping.configure import (
    configure_interface_damping,
    unconfigure_interface_damping,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestInterfaceDampingApis(unittest.TestCase):
    """configure_interface_damping, unconfigure_interface_damping"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_damping_defaults(self):
        configure_interface_damping(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("damping enabled true", c)
        self.assertIn("damping max-suppress-time 20000", c)
        self.assertIn("damping decay-half-life 5000", c)
        self.assertIn("damping suppress-threshold 5000", c)
        self.assertIn("damping reuse-threshold 2000", c)
        self.assertIn("damping flap-penalty 1000", c)

    def test_damping_custom_values(self):
        configure_interface_damping(
            self.d, "swp2",
            max_suppress_time=30000,
            decay_half_life=6000,
            suppress_threshold=7000,
            reuse_threshold=3000,
            flap_penalty=2000,
        )
        c = self.d.cfg()
        self.assertIn("interface swp2", c)
        self.assertIn("damping max-suppress-time 30000", c)
        self.assertIn("damping decay-half-life 6000", c)
        self.assertIn("damping suppress-threshold 7000", c)
        self.assertIn("damping reuse-threshold 3000", c)
        self.assertIn("damping flap-penalty 2000", c)

    def test_unconfigure_damping(self):
        unconfigure_interface_damping(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("damping enabled false", c)


class TestSubCommandFailureWrapping(unittest.TestCase):
    """Every configure_*/unconfigure_* helper wraps a device.configure()
    failure in a re-raised SubCommandFailure with a descriptive message."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_damping_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_interface_damping(self.d, "swp1")

    def test_unconfigure_damping_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_damping(self.d, "swp1")


class TestDampingConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in damping/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(damping_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == damping_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered damping configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nDamping configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
