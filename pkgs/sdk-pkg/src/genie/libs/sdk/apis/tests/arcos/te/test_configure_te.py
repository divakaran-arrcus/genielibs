#!/usr/bin/env python3
"""Unit tests for arcOS TE configure/unconfigure APIs (full coverage).

Both helpers in genie.libs.sdk.apis.arcos.te.configure build an arcOS CLI
config list under `network-instance <ni>` / `te admin-group <name>` and call
`device.configure(config)`. Tests mock device.configure and assert on the
emitted CLI, plus SubCommandFailure re-raise behavior.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.te import configure as te_configure
from genie.libs.sdk.apis.arcos.te.configure import (
    configure_te_admin_group,
    unconfigure_te_admin_group,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureTeAdminGroup(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_te_admin_group(self):
        configure_te_admin_group(self.d, "red", 11)
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("te admin-group red", c)
        self.assertIn("bit-position 11", c)

    def test_configure_te_admin_group_named_instance(self):
        configure_te_admin_group(self.d, "green", 2, network_instance="vrf1")
        c = self.d.cfg()
        self.assertIn("network-instance vrf1", c)
        self.assertIn("te admin-group green", c)
        self.assertIn("bit-position 2", c)

    def test_configure_te_admin_group_subcommand_failure(self):
        self.d.configure.side_effect = SubCommandFailure("boom")
        with self.assertRaises(SubCommandFailure):
            configure_te_admin_group(self.d, "red", 11)

    def test_unconfigure_te_admin_group(self):
        unconfigure_te_admin_group(self.d, "red")
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("no te admin-group red", c)

    def test_unconfigure_te_admin_group_named_instance(self):
        unconfigure_te_admin_group(self.d, "blue", network_instance="vrf2")
        c = self.d.cfg()
        self.assertIn("network-instance vrf2", c)
        self.assertIn("no te admin-group blue", c)

    def test_unconfigure_te_admin_group_subcommand_failure(self):
        self.d.configure.side_effect = SubCommandFailure("boom")
        with self.assertRaises(SubCommandFailure):
            unconfigure_te_admin_group(self.d, "red")

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(te_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == te_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered TE configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nTE configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
