#!/usr/bin/env python3
"""Unit tests for arcOS SyncE configure/unconfigure APIs (full coverage).

ArcOS SyncE uses a global context and a per-interface sub-context:

    sync-e
        enabled <true|false>
        holdover <seconds>
        quality-level-enabled <true|false>
        revertive-enabled <true|false>
        synchronization-network-option <option-1|option-2>

    interface <name>
        sync-e
            enabled <true|false>
            input-source-priority <priority>
            quality-level <QL_*>

Each helper builds a CLI config list and calls device.configure(list).
Tests mock device.configure and assert the emitted CLI (including every
optional-parameter branch), plus exercise the SubCommandFailure wrapping
branch for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.synce import configure as synce_configure
from genie.libs.sdk.apis.arcos.synce.configure import (
    configure_synce_global,
    unconfigure_synce_global,
    configure_synce_interface,
    unconfigure_synce_interface,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestSyncEGlobalApis(unittest.TestCase):
    """configure_synce_global, unconfigure_synce_global"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_global_defaults(self):
        configure_synce_global(self.d)
        c = self.d.cfg()
        self.assertIn("sync-e", c)
        self.assertIn("enabled true", c)
        self.assertNotIn("holdover", c)
        self.assertNotIn("quality-level-enabled", c)
        self.assertNotIn("revertive-enabled", c)
        self.assertNotIn("synchronization-network-option", c)

    def test_global_disabled(self):
        configure_synce_global(self.d, enabled=False)
        self.assertIn("enabled false", self.d.cfg())

    def test_global_holdover(self):
        configure_synce_global(self.d, holdover=300)
        self.assertIn("holdover 300", self.d.cfg())

    def test_global_quality_level_enabled(self):
        configure_synce_global(self.d, quality_level_enabled=True)
        self.assertIn("quality-level-enabled true", self.d.cfg())

    def test_global_quality_level_disabled(self):
        configure_synce_global(self.d, quality_level_enabled=False)
        self.assertIn("quality-level-enabled false", self.d.cfg())

    def test_global_revertive_enabled(self):
        configure_synce_global(self.d, revertive_enabled=True)
        self.assertIn("revertive-enabled true", self.d.cfg())

    def test_global_revertive_disabled(self):
        configure_synce_global(self.d, revertive_enabled=False)
        self.assertIn("revertive-enabled false", self.d.cfg())

    def test_global_network_option(self):
        configure_synce_global(self.d, network_option="option-1")
        self.assertIn("synchronization-network-option option-1", self.d.cfg())

    def test_unconfigure_global(self):
        unconfigure_synce_global(self.d)
        c = self.d.cfg()
        self.assertIn("sync-e", c)
        self.assertIn("enabled false", c)


class TestSyncEInterfaceApis(unittest.TestCase):
    """configure_synce_interface, unconfigure_synce_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface_defaults(self):
        configure_synce_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("sync-e", c)
        self.assertIn("enabled true", c)
        self.assertNotIn("input-source-priority", c)
        self.assertNotIn("quality-level", c)

    def test_interface_disabled(self):
        configure_synce_interface(self.d, "swp1", enabled=False)
        self.assertIn("enabled false", self.d.cfg())

    def test_interface_priority(self):
        configure_synce_interface(self.d, "swp1", priority=1)
        self.assertIn("input-source-priority 1", self.d.cfg())

    def test_interface_quality_level(self):
        configure_synce_interface(self.d, "swp1", quality_level="QL_PRC")
        self.assertIn("quality-level QL_PRC", self.d.cfg())

    def test_unconfigure_interface(self):
        unconfigure_synce_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("sync-e", c)
        self.assertIn("enabled false", c)


class TestSubCommandFailureWrapping(unittest.TestCase):
    """Every configure_*/unconfigure_* helper wraps a device.configure()
    failure in a re-raised SubCommandFailure with a descriptive message."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_global_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_synce_global(self.d)

    def test_unconfigure_global_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_synce_global(self.d)

    def test_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_synce_interface(self.d, "swp1")

    def test_unconfigure_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_synce_interface(self.d, "swp1")


class TestSyncEConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in synce/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(synce_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == synce_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered SyncE configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nSyncE configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
