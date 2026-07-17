#!/usr/bin/env python3
"""Unit tests for arcOS sFlow configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.sflow.configure builds an arcOS CLI config list
(a `sflow global ...` or `sflow interface <name> <direction>` line) and calls
`device.configure(config)`. Tests mock `device.configure` and assert on a
distinctive substring of the emitted CLI, plus the SubCommandFailure wrap
path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.sflow import configure as sflow_configure
from genie.libs.sdk.apis.arcos.sflow.configure import (
    configure_sflow_global,
    unconfigure_sflow_global,
    configure_sflow_interface,
    unconfigure_sflow_interface,
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


class TestConfigureSflowGlobal(unittest.TestCase):
    """configure_sflow_global / unconfigure_sflow_global"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_global_all_params(self):
        configure_sflow_global(
            self.d, counter_interval=30, sampling_rate=1000,
            network_instance="default", collector_ipv4="10.0.0.5",
            collector_port=6343, agent_interface="loopback0",
        )
        c = self.d.cfg()
        self.assertIn("sflow global counter-sampling-interval 30", c)
        self.assertIn("sflow global packet-sampling-rate 1000", c)
        self.assertIn("sflow global network-instance default", c)
        self.assertIn("sflow global ipv4 collector 10.0.0.5 port 6343", c)
        self.assertIn("sflow global agent-ip-interface loopback0", c)

    def test_global_collector_without_port(self):
        configure_sflow_global(self.d, collector_ipv4="10.0.0.5")
        c = self.d.cfg()
        self.assertIn("sflow global ipv4 collector 10.0.0.5", c)
        self.assertNotIn("port", c)

    def test_global_no_params_skips_configure(self):
        # No config lines built -> device.configure() should not be called
        configure_sflow_global(self.d)
        self.d.configure.assert_not_called()

    def test_global_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_sflow_global(d, counter_interval=30)

    def test_unconfigure_global(self):
        unconfigure_sflow_global(self.d)
        c = self.d.cfg()
        self.assertIn("no sflow global counter-sampling-interval", c)
        self.assertIn("no sflow global packet-sampling-rate", c)
        self.assertIn("no sflow global network-instance", c)

    def test_unconfigure_global_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_sflow_global(d)


class TestConfigureSflowInterface(unittest.TestCase):
    """configure_sflow_interface / unconfigure_sflow_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface_default_direction(self):
        configure_sflow_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("sflow interface swp1 ingress", c)

    def test_interface_egress_with_sampling_rate(self):
        configure_sflow_interface(self.d, "swp1", direction="egress",
                                   sampling_rate=500)
        c = self.d.cfg()
        self.assertIn("sflow interface swp1 egress", c)
        self.assertIn("packet-sampling-rate 500", c)

    def test_interface_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_sflow_interface(d, "swp1")

    def test_unconfigure_interface(self):
        unconfigure_sflow_interface(self.d, "swp1")
        self.assertIn("no sflow interface swp1 ingress", self.d.cfg())

    def test_unconfigure_interface_egress(self):
        unconfigure_sflow_interface(self.d, "swp1", direction="egress")
        self.assertIn("no sflow interface swp1 egress", self.d.cfg())

    def test_unconfigure_interface_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_sflow_interface(d, "swp1")


class TestSflowConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in sflow/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sflow_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sflow_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered sFlow configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nsFlow configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
