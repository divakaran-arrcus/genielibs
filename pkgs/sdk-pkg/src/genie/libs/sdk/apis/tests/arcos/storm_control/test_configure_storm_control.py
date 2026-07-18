#!/usr/bin/env python3
"""Unit tests for arcOS Storm Control configure/unconfigure APIs (full
coverage).

Both helpers in genie.libs.sdk.apis.arcos.storm_control.configure build an
`interface <intf>` CLI config list with `storm-control ...` sub-lines and
call `device.configure(config)`. Tests mock device.configure and assert on
the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.storm_control import configure as sc_configure
from genie.libs.sdk.apis.arcos.storm_control.configure import (
    configure_storm_control,
    unconfigure_storm_control,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureStormControl(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_storm_control_levels(self):
        configure_storm_control(
            self.d, "swp1",
            broadcast_level=10.5, multicast_level=5.25,
            unknown_unicast_level=1.0,
        )
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("storm-control broadcast-level 10.5", c)
        self.assertIn("storm-control multicast-level 5.25", c)
        self.assertIn("storm-control unknown-unicast-level 1.0", c)

    def test_configure_storm_control_kbps(self):
        configure_storm_control(
            self.d, "swp2",
            broadcast_kbps=1000, multicast_kbps=2000,
            unknown_unicast_kbps=500,
        )
        c = self.d.cfg()
        self.assertIn("interface swp2", c)
        self.assertIn("storm-control broadcast-kbps 1000", c)
        self.assertIn("storm-control multicast-kbps 2000", c)
        self.assertIn("storm-control unknown-unicast-kbps 500", c)

    def test_configure_storm_control_no_params(self):
        configure_storm_control(self.d, "swp3")
        c = self.d.cfg()
        self.assertIn("interface swp3", c)
        self.assertNotIn("storm-control", c)

    def test_configure_storm_control_partial(self):
        configure_storm_control(self.d, "swp4", broadcast_level=20)
        c = self.d.cfg()
        self.assertIn("storm-control broadcast-level 20", c)
        self.assertNotIn("multicast-level", c)
        self.assertNotIn("kbps", c)

    def test_unconfigure_storm_control(self):
        unconfigure_storm_control(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("no storm-control", c)


class TestConfigureStormControlErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_storm_control_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            configure_storm_control(self.d, "swp1", broadcast_level=10)

    def test_unconfigure_storm_control_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            unconfigure_storm_control(self.d, "swp1")


class TestStormControlConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in storm_control/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sc_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sc_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Storm Control configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nStorm Control configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
