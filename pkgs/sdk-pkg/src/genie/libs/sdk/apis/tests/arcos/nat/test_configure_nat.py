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


configure_nat_instance = _track("configure_nat_instance", configure_nat_instance)
unconfigure_nat_instance = _track("unconfigure_nat_instance", unconfigure_nat_instance)
configure_nat_mapping_entry = _track(
    "configure_nat_mapping_entry", configure_nat_mapping_entry
)
unconfigure_nat_mapping_entry = _track(
    "unconfigure_nat_mapping_entry", unconfigure_nat_mapping_entry
)
configure_nat_policy = _track("configure_nat_policy", configure_nat_policy)
unconfigure_nat_policy = _track("unconfigure_nat_policy", unconfigure_nat_policy)


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
            f"Untested public functions in nat/configure.py: {sorted(missing)}",
        )

        configure_count = sum(1 for n in public_fns if n.startswith("configure_"))
        unconfigure_count = sum(1 for n in public_fns if n.startswith("unconfigure_"))
        print(
            f"\nNAT configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(public_fns)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
