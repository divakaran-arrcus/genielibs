#!/usr/bin/env python3
"""Unit tests for arcOS MPLS TTL configure API (full coverage).

ArcOS MPLS TTL propagation uses the default network-instance context:

    network-instance default
        mpls global config ttl-propagation <true|false>

configure_mpls_ttl_propagation is the only configure_*/unconfigure_*
helper in this module -- there is no separate unconfigure_* counterpart,
the same function toggles the flag via the `enabled` parameter. The
module also exposes a get_mpls_ttl_propagation() read helper (parses
`show ... | display json`); it is covered here too for full file
coverage even though it falls outside the configure_*/unconfigure_*
naming convention exercised by the machine coverage check below.

Tests mock device.configure/device.execute and assert the emitted CLI /
parsed return value, plus exercise the SubCommandFailure wrapping branch
and the get helper's exception-swallowing default-True fallback.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.mpls_ttl import configure as mpls_ttl_configure
from genie.libs.sdk.apis.arcos.mpls_ttl.configure import (
    configure_mpls_ttl_propagation,
    get_mpls_ttl_propagation,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestMplsTtlPropagationApis(unittest.TestCase):
    """configure_mpls_ttl_propagation"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_ttl_propagation_default_enabled(self):
        configure_mpls_ttl_propagation(self.d)
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("mpls global config ttl-propagation true", c)

    def test_ttl_propagation_disabled(self):
        configure_mpls_ttl_propagation(self.d, enabled=False)
        self.assertIn("mpls global config ttl-propagation false", self.d.cfg())


class TestGetMplsTtlPropagation(unittest.TestCase):
    """get_mpls_ttl_propagation (bonus coverage, not a configure_*/
    unconfigure_* helper)."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_get_true(self):
        self.d.execute = Mock(return_value='{"ttl-propagation": true}')
        self.assertTrue(get_mpls_ttl_propagation(self.d))

    def test_get_false(self):
        self.d.execute = Mock(return_value='{"ttl-propagation": false}')
        self.assertFalse(get_mpls_ttl_propagation(self.d))

    def test_get_exception_defaults_true(self):
        self.d.execute = Mock(side_effect=Exception("boom"))
        self.assertTrue(get_mpls_ttl_propagation(self.d))


class TestSubCommandFailureWrapping(unittest.TestCase):
    """configure_mpls_ttl_propagation wraps a device.configure() failure
    in a re-raised SubCommandFailure with a descriptive message."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_ttl_propagation_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_mpls_ttl_propagation(self.d)


class TestMplsTtlConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in mpls_ttl/configure.py must be referenced by name somewhere
    in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(mpls_ttl_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == mpls_ttl_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered MPLS TTL configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nMPLS TTL configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing "
            f"(note: no unconfigure_* counterpart exists in source; "
            f"get_mpls_ttl_propagation is also tested but excluded from "
            f"this configure_/unconfigure_ machine check by design)"
        )


if __name__ == "__main__":
    unittest.main()
