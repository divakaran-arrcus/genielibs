#!/usr/bin/env python3
"""Unit tests for arcOS RSVP-TE configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.rsvp_te.configure builds an arcOS CLI config list
(an `mpls mpls-te interface` context, an `protocol RSVP default` global
context, or an RSVP interface context) and calls `device.configure(config)`.
Tests mock `device.configure` and assert on a distinctive substring of the
emitted CLI, plus the SubCommandFailure wrap path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.rsvp_te import configure as rsvp_te_configure
from genie.libs.sdk.apis.arcos.rsvp_te.configure import (
    configure_rsvp_te_interface,
    unconfigure_rsvp_te_interface,
    configure_rsvp_global,
    unconfigure_rsvp_global,
    configure_rsvp_interface,
    unconfigure_rsvp_interface,
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
    """Device whose .configure() always raises SubCommandFailure."""

    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(side_effect=SubCommandFailure("boom"))


class TestConfigureRsvpTeInterface(unittest.TestCase):
    """configure_rsvp_te_interface / unconfigure_rsvp_te_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_rsvp_te_interface_basic(self):
        configure_rsvp_te_interface(self.d, "ethernet-1/1")
        c = self.d.cfg()
        self.assertIn(
            "network-instance default mpls mpls-te interface ethernet-1/1", c)
        self.assertIn("enable true", c)

    def test_rsvp_te_interface_with_metric(self):
        configure_rsvp_te_interface(self.d, "ethernet-1/1", metric=100)
        self.assertIn("metric 100", self.d.cfg())

    def test_rsvp_te_interface_no_metric_omitted(self):
        configure_rsvp_te_interface(self.d, "ethernet-1/1")
        self.assertNotIn("metric", self.d.cfg())

    def test_rsvp_te_interface_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_rsvp_te_interface(d, "ethernet-1/1")

    def test_unconfigure_rsvp_te_interface(self):
        unconfigure_rsvp_te_interface(self.d, "ethernet-1/1")
        self.assertIn(
            "no network-instance default mpls mpls-te interface ethernet-1/1",
            self.d.cfg())

    def test_unconfigure_rsvp_te_interface_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_rsvp_te_interface(d, "ethernet-1/1")


class TestConfigureRsvpGlobal(unittest.TestCase):
    """configure_rsvp_global / unconfigure_rsvp_global"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_rsvp_global_basic(self):
        configure_rsvp_global(self.d)
        self.assertIn("network-instance default protocol RSVP default", self.d.cfg())

    def test_rsvp_global_hello_supported_true(self):
        configure_rsvp_global(self.d, hello_supported=True)
        self.assertIn("global hello-supported true", self.d.cfg())

    def test_rsvp_global_hello_supported_false(self):
        configure_rsvp_global(self.d, hello_supported=False)
        self.assertIn("global hello-supported false", self.d.cfg())

    def test_rsvp_global_hello_interval(self):
        configure_rsvp_global(self.d, hello_interval=5)
        self.assertIn("global hello-interval 5", self.d.cfg())

    def test_rsvp_global_refresh_reduction_true(self):
        configure_rsvp_global(self.d, refresh_reduction=True)
        self.assertIn("global refresh-reduction true", self.d.cfg())

    def test_rsvp_global_refresh_reduction_false(self):
        configure_rsvp_global(self.d, refresh_reduction=False)
        self.assertIn("global refresh-reduction false", self.d.cfg())

    def test_rsvp_global_all_options(self):
        configure_rsvp_global(
            self.d, hello_supported=True, hello_interval=10, refresh_reduction=True)
        c = self.d.cfg()
        self.assertIn("global hello-supported true", c)
        self.assertIn("global hello-interval 10", c)
        self.assertIn("global refresh-reduction true", c)

    def test_rsvp_global_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_rsvp_global(d)

    def test_unconfigure_rsvp_global(self):
        unconfigure_rsvp_global(self.d)
        self.assertIn(
            "no network-instance default protocol RSVP default", self.d.cfg())

    def test_unconfigure_rsvp_global_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_rsvp_global(d)


class TestConfigureRsvpInterface(unittest.TestCase):
    """configure_rsvp_interface / unconfigure_rsvp_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_rsvp_interface_basic(self):
        configure_rsvp_interface(self.d, "ethernet-1/1")
        c = self.d.cfg()
        self.assertIn(
            "network-instance default protocol RSVP default interface ethernet-1/1", c)
        self.assertIn("enable true", c)

    def test_rsvp_interface_hello_supported(self):
        configure_rsvp_interface(self.d, "ethernet-1/1", hello_supported=True)
        self.assertIn("hello-supported true", self.d.cfg())

    def test_rsvp_interface_hello_supported_false(self):
        configure_rsvp_interface(self.d, "ethernet-1/1", hello_supported=False)
        self.assertIn("hello-supported false", self.d.cfg())

    def test_rsvp_interface_bandwidth_subscription(self):
        configure_rsvp_interface(self.d, "ethernet-1/1", bandwidth_subscription=80)
        self.assertIn("bandwidth subscription 80", self.d.cfg())

    def test_rsvp_interface_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_rsvp_interface(d, "ethernet-1/1")

    def test_unconfigure_rsvp_interface(self):
        unconfigure_rsvp_interface(self.d, "ethernet-1/1")
        c = self.d.cfg()
        self.assertIn("network-instance default protocol RSVP default", c)
        self.assertIn("no interface ethernet-1/1", c)

    def test_unconfigure_rsvp_interface_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_rsvp_interface(d, "ethernet-1/1")


class TestRsvpTeConfigureFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in rsvp_te/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(rsvp_te_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == rsvp_te_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered RSVP-TE configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nRSVP-TE configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
