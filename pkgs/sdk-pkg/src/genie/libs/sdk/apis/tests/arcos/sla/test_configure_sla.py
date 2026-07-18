#!/usr/bin/env python3
"""Unit tests for arcOS SLA (IP SLA ICMP) configure/unconfigure APIs (full
coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.sla.configure builds an arcOS CLI config list
(a `network-instance <ni> sla icmp icmp-session <name>` block or the master
`sla icmp` admin-state context) and calls `device.configure(config)`. Tests
mock `device.configure` and assert on a distinctive substring of the emitted
CLI, plus the SubCommandFailure wrap path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.sla import configure as sla_configure
from genie.libs.sdk.apis.arcos.sla.configure import (
    configure_sla_icmp_session,
    unconfigure_sla_icmp_session,
    configure_sla_icmp_admin_state,
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


class TestConfigureSlaIcmpSession(unittest.TestCase):
    """configure_sla_icmp_session / unconfigure_sla_icmp_session"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_sla_icmp_session_basic(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000)
        c = self.d.cfg()
        self.assertIn(
            "network-instance default sla icmp icmp-session probe1", c)
        self.assertIn("admin-state true", c)
        self.assertIn("target-address 10.0.0.1", c)
        self.assertIn("session-interval 60", c)
        self.assertIn("probe probe-count 5", c)
        self.assertIn("probe probe-interval 1000", c)

    def test_sla_icmp_session_with_source_address(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000, source_address="10.0.0.2")
        self.assertIn("source-address 10.0.0.2", self.d.cfg())

    def test_sla_icmp_session_with_payload_size(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000, payload_size=128)
        self.assertIn("probe payload-size 128", self.d.cfg())

    def test_sla_icmp_session_with_dscp(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000, dscp=46)
        self.assertIn("dscp 46", self.d.cfg())

    def test_sla_icmp_session_with_excessive_rtd(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000, excessive_rtd=500000)
        self.assertIn("threshold excessive-rtd 500000", self.d.cfg())

    def test_sla_icmp_session_with_successive_loss(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000, successive_loss=3)
        self.assertIn("threshold successive-loss 3", self.d.cfg())

    def test_sla_icmp_session_named_instance(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000, network_instance="vrf-red")
        self.assertIn(
            "network-instance vrf-red sla icmp icmp-session probe1",
            self.d.cfg())

    def test_sla_icmp_session_no_source_omitted(self):
        configure_sla_icmp_session(
            self.d, "probe1", "10.0.0.1", session_interval=60,
            probe_count=5, probe_interval=1000)
        self.assertNotIn("source-address", self.d.cfg())

    def test_sla_icmp_session_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_sla_icmp_session(
                d, "probe1", "10.0.0.1", session_interval=60,
                probe_count=5, probe_interval=1000)

    def test_unconfigure_sla_icmp_session(self):
        unconfigure_sla_icmp_session(self.d, "probe1")
        c = self.d.cfg()
        self.assertIn("network-instance default sla icmp", c)
        self.assertIn("no icmp-session probe1", c)

    def test_unconfigure_sla_icmp_session_named_instance(self):
        unconfigure_sla_icmp_session(self.d, "probe1", network_instance="vrf-red")
        self.assertIn("network-instance vrf-red sla icmp", self.d.cfg())

    def test_unconfigure_sla_icmp_session_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_sla_icmp_session(d, "probe1")


class TestConfigureSlaIcmpAdminState(unittest.TestCase):
    """configure_sla_icmp_admin_state"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_sla_icmp_admin_state_enable(self):
        configure_sla_icmp_admin_state(self.d, enabled=True)
        c = self.d.cfg()
        self.assertIn("network-instance default sla icmp", c)
        self.assertIn("admin-state true", c)

    def test_sla_icmp_admin_state_disable(self):
        configure_sla_icmp_admin_state(self.d, enabled=False)
        self.assertIn("admin-state false", self.d.cfg())

    def test_sla_icmp_admin_state_named_instance(self):
        configure_sla_icmp_admin_state(self.d, enabled=True, network_instance="vrf-red")
        self.assertIn("network-instance vrf-red sla icmp", self.d.cfg())

    def test_sla_icmp_admin_state_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_sla_icmp_admin_state(d)


class TestSlaConfigureFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in sla/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sla_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sla_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered SLA configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nSLA configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
