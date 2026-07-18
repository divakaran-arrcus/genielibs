#!/usr/bin/env python3
"""Unit tests for arcOS QoS configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.qos.configure builds a plain CLI command list
(`qos classifier <name>`, `qos policy <name>`, or `interface <intf>`
context) and calls `device.configure(config)`. Tests mock device.configure
and assert on a distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.qos import configure as qos_configure
from genie.libs.sdk.apis.arcos.qos.configure import (
    configure_qos_classifier,
    unconfigure_qos_classifier,
    configure_qos_policy,
    unconfigure_qos_policy,
    configure_qos_service_policy,
    unconfigure_qos_service_policy,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureQosClassifier(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_classifier_dscp(self):
        configure_qos_classifier(self.d, "class-dscp-46", "DSCP", dscp_values=[46])
        c = self.d.cfg()
        self.assertIn("qos classifier class-dscp-46", c)
        self.assertIn("filter DSCP dscp-value [ 46 ]", c)

    def test_classifier_dscp_scalar_value(self):
        configure_qos_classifier(self.d, "class-dscp-1", "DSCP", dscp_values=46)
        self.assertIn("filter DSCP dscp-value [ 46 ]", self.d.cfg())

    def test_classifier_local_tc(self):
        configure_qos_classifier(self.d, "class-tc1", "LOCAL_TC", local_tc_value=1)
        self.assertIn("filter LOCAL_TC local-tc-value 1", self.d.cfg())

    def test_classifier_acl_ipv4(self):
        configure_qos_classifier(self.d, "class-acl1", "ACL_IPV4", acl_name="ACL1")
        self.assertIn("filter ACL_IPV4 acl-name ACL1", self.d.cfg())

    def test_classifier_any(self):
        configure_qos_classifier(self.d, "match-all", "ANY")
        self.assertIn("filter ANY", self.d.cfg())

    def test_unconfigure_classifier(self):
        unconfigure_qos_classifier(self.d, "class-dscp-46")
        self.assertIn("no qos classifier class-dscp-46", self.d.cfg())


class TestConfigureQosPolicy(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_policy_police(self):
        configure_qos_policy(self.d, "ingress-pol", [
            {"classifier": "class-dscp-46", "action_type": "POLICE",
             "action_args": {"rate_value": 500, "rate_unit": "mbps"}},
        ])
        c = self.d.cfg()
        self.assertIn("qos policy ingress-pol", c)
        self.assertIn("classifier class-dscp-46", c)
        self.assertIn("action POLICE committed rate value 500 unit mbps", c)

    def test_policy_priority(self):
        configure_qos_policy(self.d, "pol-prio", [
            {"classifier": "voice", "action_type": "PRIORITY",
             "action_args": {"level": 2}},
        ])
        self.assertIn("action PRIORITY level 2", self.d.cfg())

    def test_policy_rate_max(self):
        configure_qos_policy(self.d, "pol-rm", [
            {"classifier": "voice", "action_type": "RATE_MAX",
             "action_args": {"rate_value": 100, "rate_unit": "mbps"}},
        ])
        self.assertIn("action RATE_MAX value 100 unit mbps", self.d.cfg())

    def test_policy_rate_excess(self):
        configure_qos_policy(self.d, "pol-re", [
            {"classifier": "voice", "action_type": "RATE_EXCESS",
             "action_args": {"ratio": 2}},
        ])
        self.assertIn("action RATE_EXCESS ratio 2", self.d.cfg())

    def test_policy_marking(self):
        configure_qos_policy(self.d, "pol-mk", [
            {"classifier": "voice", "action_type": "MARKING",
             "action_args": {"local_tc": 3}},
        ])
        self.assertIn("action MARKING local-tc 3", self.d.cfg())

    def test_policy_skips_missing_classifier(self):
        configure_qos_policy(self.d, "pol-skip", [
            {"action_type": "PRIORITY", "action_args": {"level": 1}},
        ])
        c = self.d.cfg()
        self.assertIn("qos policy pol-skip", c)
        self.assertNotIn("classifier", c.replace("qos policy pol-skip", ""))

    def test_unconfigure_policy(self):
        unconfigure_qos_policy(self.d, "ingress-pol")
        self.assertIn("no qos policy ingress-pol", self.d.cfg())


class TestConfigureQosServicePolicy(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_service_policy(self):
        configure_qos_service_policy(self.d, "swp1", "INGRESS", "ingress-pol")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("qos service-policy INGRESS name ingress-pol", c)

    def test_unconfigure_service_policy(self):
        unconfigure_qos_service_policy(self.d, "swp1", "INGRESS")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("no qos service-policy INGRESS", c)


class TestConfigureQosErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context."""

    def setUp(self):
        self.d = _CfgDevice()

    def _fail(self):
        from unicon.core.errors import SubCommandFailure
        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))

    def test_configure_classifier_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_qos_classifier(self.d, "c1", "ANY")

    def test_unconfigure_classifier_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_qos_classifier(self.d, "c1")

    def test_configure_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_qos_policy(self.d, "p1", [])

    def test_unconfigure_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_qos_policy(self.d, "p1")

    def test_configure_service_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_qos_service_policy(self.d, "swp1", "INGRESS", "p1")

    def test_unconfigure_service_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_qos_service_policy(self.d, "swp1", "INGRESS")


class TestQosConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in qos/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(qos_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == qos_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered QoS configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nQoS configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
