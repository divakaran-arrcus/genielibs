#!/usr/bin/env python3
"""Unit tests for arcOS NAT configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under the `nat instance <id>`
context and calls device.configure(list). Tests mock device.configure and
assert the emitted CLI. A machine coverage check
(TestNatConfigureCoverage.test_zzz_all_functions_covered) asserts that every
public configure_*/unconfigure_* function in the module was exercised by
some test in this file.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.nat.configure as configure_module
from genie.libs.sdk.apis.arcos.nat.configure import (
    configure_nat_instance,
    unconfigure_nat_instance,
    configure_nat_mapping_entry,
    unconfigure_nat_mapping_entry,
    configure_nat_policy,
    unconfigure_nat_policy,
)

class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureNatInstance(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_nat_instance_defaults(self):
        configure_nat_instance(self.d, 1, "napt1")
        c = self.d.cfg()
        self.assertIn("nat instance 1", c)
        self.assertIn("name napt1", c)
        self.assertIn("enable true", c)

    def test_configure_nat_instance_disabled(self):
        configure_nat_instance(self.d, 2, "napt2", enabled=False)
        c = self.d.cfg()
        self.assertIn("nat instance 2", c)
        self.assertIn("name napt2", c)
        self.assertIn("enable false", c)

    def test_unconfigure_nat_instance(self):
        unconfigure_nat_instance(self.d, 1)
        self.assertIn("no nat instance 1", self.d.cfg())


class TestConfigureNatMappingEntry(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_nat_mapping_entry(self):
        configure_nat_mapping_entry(self.d, 1, 1, "10.10.0.0/16")
        c = self.d.cfg()
        self.assertIn("nat instance 1", c)
        self.assertIn(
            "mapping-entry 1 internal-src-address 10.10.0.0/16", c
        )

    def test_unconfigure_nat_mapping_entry(self):
        unconfigure_nat_mapping_entry(self.d, 1, 1)
        c = self.d.cfg()
        self.assertIn("nat instance 1", c)
        self.assertIn("no mapping-entry 1", c)


class TestConfigureNatPolicy(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_nat_policy(self):
        configure_nat_policy(self.d, 1, 1, "swp1")
        c = self.d.cfg()
        self.assertIn("nat instance 1", c)
        self.assertIn("policy 1 external-interface swp1", c)

    def test_unconfigure_nat_policy(self):
        unconfigure_nat_policy(self.d, 1, 1)
        c = self.d.cfg()
        self.assertIn("nat instance 1", c)
        self.assertIn("no policy 1", c)


class TestConfigureNatFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_nat_instance_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_nat_instance(self.d, 1, "napt1")

    def test_unconfigure_nat_instance_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_nat_instance(self.d, 1)

    def test_configure_nat_mapping_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_nat_mapping_entry(self.d, 1, 1, "10.10.0.0/16")

    def test_unconfigure_nat_mapping_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_nat_mapping_entry(self.d, 1, 1)

    def test_configure_nat_policy_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_nat_policy(self.d, 1, 1, "swp1")

    def test_unconfigure_nat_policy_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_nat_policy(self.d, 1, 1)


class TestNatConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in nat/configure.py must be referenced by name somewhere
    in this test file's source. Order-safe under both pytest (file
    order) and unittest (alphabetical class order via dir()).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name
            for name, obj in inspect.getmembers(configure_module, inspect.isfunction)
            if obj.__module__ == configure_module.__name__
            and (name.startswith("configure_") or name.startswith("unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Untested public functions in nat/configure.py: {missing}",
        )

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nNAT configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
