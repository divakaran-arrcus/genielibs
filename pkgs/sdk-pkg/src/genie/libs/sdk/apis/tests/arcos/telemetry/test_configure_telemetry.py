#!/usr/bin/env python3
"""Unit tests for arcOS Telemetry (Kafka streaming) configure/unconfigure
APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.telemetry.configure builds an arcOS CLI config
list under the `telemetry-system` context (`global`, `destination-group
<name>`, or `persistent-subscription <name>`) and calls
`device.configure(config)`. Tests mock `device.configure` and assert on a
distinctive substring of the emitted CLI, plus the SubCommandFailure wrap
path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.telemetry import configure as telemetry_configure
from genie.libs.sdk.apis.arcos.telemetry.configure import (
    configure_telemetry_global,
    unconfigure_telemetry_global,
    configure_telemetry_destination_group,
    unconfigure_telemetry_destination_group,
    configure_telemetry_subscription,
    unconfigure_telemetry_subscription,
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


class TestConfigureTelemetryGlobal(unittest.TestCase):
    """configure_telemetry_global / unconfigure_telemetry_global"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_global_default_status(self):
        configure_telemetry_global(self.d)
        c = self.d.cfg()
        self.assertIn("telemetry-system global status on", c)

    def test_global_with_cuid(self):
        configure_telemetry_global(self.d, status="on", cuid="CUST123")
        c = self.d.cfg()
        self.assertIn("telemetry-system global status on", c)
        self.assertIn("telemetry-system global cuid CUST123", c)

    def test_global_off_status(self):
        configure_telemetry_global(self.d, status="off")
        self.assertIn("telemetry-system global status off", self.d.cfg())

    def test_global_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_telemetry_global(d, cuid="CUST123")

    def test_unconfigure_global(self):
        unconfigure_telemetry_global(self.d)
        self.assertIn("telemetry-system global status off", self.d.cfg())

    def test_unconfigure_global_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_telemetry_global(d)


class TestConfigureTelemetryDestinationGroup(unittest.TestCase):
    """configure_telemetry_destination_group / unconfigure_telemetry_destination_group"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_destination_group_all_params(self):
        configure_telemetry_destination_group(
            self.d, "DG1", "10.0.0.5", 50051,
            source_interface="loopback0", network_instance="default",
            ssl=True,
        )
        c = self.d.cfg()
        self.assertIn("telemetry-system destination-group DG1", c)
        self.assertIn("destination 10.0.0.5 50051", c)
        self.assertIn("source-interface loopback0", c)
        self.assertIn("network-instance default", c)
        self.assertIn("ssl", c)

    def test_destination_group_minimal(self):
        configure_telemetry_destination_group(self.d, "DG1", "10.0.0.5", 50051)
        c = self.d.cfg()
        self.assertIn("destination 10.0.0.5 50051", c)
        self.assertNotIn("source-interface", c)
        self.assertNotIn("ssl", c)

    def test_destination_group_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_telemetry_destination_group(d, "DG1", "10.0.0.5", 50051)

    def test_unconfigure_destination_group(self):
        unconfigure_telemetry_destination_group(self.d, "DG1")
        self.assertIn(
            "no telemetry-system destination-group DG1", self.d.cfg()
        )

    def test_unconfigure_destination_group_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_telemetry_destination_group(d, "DG1")


class TestConfigureTelemetrySubscription(unittest.TestCase):
    """configure_telemetry_subscription / unconfigure_telemetry_subscription"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_subscription_list_sensors(self):
        configure_telemetry_subscription(
            self.d, "SUB1", ["interfaces", "isis"], "DG1",
        )
        c = self.d.cfg()
        self.assertIn("telemetry-system persistent-subscription SUB1", c)
        self.assertIn("sensors [ interfaces isis ]", c)
        self.assertIn("destination-group DG1", c)

    def test_subscription_single_sensor(self):
        configure_telemetry_subscription(self.d, "SUB1", "interfaces", "DG1")
        c = self.d.cfg()
        self.assertIn("sensors [ interfaces ]", c)

    def test_subscription_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_telemetry_subscription(d, "SUB1", "interfaces", "DG1")

    def test_unconfigure_subscription(self):
        unconfigure_telemetry_subscription(self.d, "SUB1")
        self.assertIn(
            "no telemetry-system persistent-subscription SUB1", self.d.cfg()
        )

    def test_unconfigure_subscription_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_telemetry_subscription(d, "SUB1")


class TestTelemetryConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in telemetry/configure.py must be referenced by name somewhere
    in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(telemetry_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == telemetry_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Telemetry configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nTelemetry configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
