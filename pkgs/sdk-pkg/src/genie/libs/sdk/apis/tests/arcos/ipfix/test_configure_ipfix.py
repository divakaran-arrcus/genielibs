#!/usr/bin/env python3
"""Unit tests for arcOS IPFIX configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.ipfix.configure builds an arcOS CLI config list
(an `ipfix observationPoint <name>`, `ipfix selectionProcess <name>`, or
`ipfix exportingProcess <name>` block) and calls `device.configure(config)`.
Tests mock `device.configure` and assert on a distinctive substring of the
emitted CLI, plus the SubCommandFailure wrap path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.ipfix import configure as ipfix_configure
from genie.libs.sdk.apis.arcos.ipfix.configure import (
    configure_ipfix_observation_point,
    unconfigure_ipfix_observation_point,
    configure_ipfix_selection_process,
    unconfigure_ipfix_selection_process,
    configure_ipfix_exporting_process,
    unconfigure_ipfix_exporting_process,
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


class TestConfigureIpfixObservationPoint(unittest.TestCase):
    """configure_ipfix_observation_point / unconfigure_ipfix_observation_point"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_observation_point_list_interfaces(self):
        configure_ipfix_observation_point(
            self.d, "OBS1", 100, "SEL1", ["swp1", "swp2"],
        )
        c = self.d.cfg()
        self.assertIn("ipfix observationPoint OBS1", c)
        self.assertIn("observationDomainId 100", c)
        self.assertIn("selectionProcess [ SEL1 ]", c)
        self.assertIn("interface [ swp1 swp2 ]", c)

    def test_observation_point_single_interface(self):
        configure_ipfix_observation_point(
            self.d, "OBS1", 100, "SEL1", "swp1",
        )
        c = self.d.cfg()
        self.assertIn("interface [ swp1 ]", c)

    def test_observation_point_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_ipfix_observation_point(d, "OBS1", 100, "SEL1", "swp1")

    def test_unconfigure_observation_point(self):
        unconfigure_ipfix_observation_point(self.d, "OBS1")
        self.assertIn("no ipfix observationPoint OBS1", self.d.cfg())

    def test_unconfigure_observation_point_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_ipfix_observation_point(d, "OBS1")


class TestConfigureIpfixSelectionProcess(unittest.TestCase):
    """configure_ipfix_selection_process / unconfigure_ipfix_selection_process"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_selection_process_list_afi(self):
        configure_ipfix_selection_process(
            self.d, "SEL1", ["IPv4", "IPv6"], "SEL_NAME1", 500,
        )
        c = self.d.cfg()
        self.assertIn("ipfix selectionProcess SEL1", c)
        self.assertIn("sample-afi [ IPv4 IPv6 ]", c)
        self.assertIn("selector SEL_NAME1", c)
        self.assertIn("sampCountBased packetSpace 500", c)

    def test_selection_process_single_afi(self):
        configure_ipfix_selection_process(
            self.d, "SEL1", "IPv4", "SEL_NAME1", 500,
        )
        c = self.d.cfg()
        self.assertIn("sample-afi [ IPv4 ]", c)

    def test_selection_process_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_ipfix_selection_process(d, "SEL1", "IPv4", "SEL_NAME1", 500)

    def test_unconfigure_selection_process(self):
        unconfigure_ipfix_selection_process(self.d, "SEL1")
        self.assertIn("no ipfix selectionProcess SEL1", self.d.cfg())

    def test_unconfigure_selection_process_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_ipfix_selection_process(d, "SEL1")


class TestConfigureIpfixExportingProcess(unittest.TestCase):
    """configure_ipfix_exporting_process / unconfigure_ipfix_exporting_process"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_exporting_process(self):
        configure_ipfix_exporting_process(
            self.d, "EXP1", "DEST1", 4739, "10.0.0.1", "10.0.0.2",
        )
        c = self.d.cfg()
        self.assertIn("ipfix exportingProcess EXP1", c)
        self.assertIn("destination DEST1", c)
        self.assertIn("udpExporter destinationPort 4739", c)
        self.assertIn("udpExporter sourceIPAddress 10.0.0.1", c)
        self.assertIn("udpExporter destinationIPAddress 10.0.0.2", c)

    def test_exporting_process_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_ipfix_exporting_process(
                d, "EXP1", "DEST1", 4739, "10.0.0.1", "10.0.0.2",
            )

    def test_unconfigure_exporting_process(self):
        unconfigure_ipfix_exporting_process(self.d, "EXP1")
        self.assertIn("no ipfix exportingProcess EXP1", self.d.cfg())

    def test_unconfigure_exporting_process_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_ipfix_exporting_process(d, "EXP1")


class TestIpfixConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in ipfix/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ipfix_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ipfix_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered IPFIX configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nIPFIX configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
