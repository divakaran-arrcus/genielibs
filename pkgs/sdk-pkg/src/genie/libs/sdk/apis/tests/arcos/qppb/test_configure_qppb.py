#!/usr/bin/env python3
"""Unit tests for arcOS QPPB (QoS Policy Propagation via BGP)
configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.qppb.configure builds an arcOS CLI config list
(a `routing-policy policy-definition` statement with a set-qos-class-id
BGP action, a `protocol BGP` rib-install policy context, or a `qos
classifier` QPPB filter) and calls `device.configure(config)`. Tests mock
`device.configure` and assert on a distinctive substring of the emitted
CLI, plus the SubCommandFailure wrap path for each helper.

Note: qppb has no get.py/verify.py in
genie/libs/sdk/apis/arcos/qppb/ -- configure.py is the only source module,
so this file alone provides full API coverage for the feature.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.qppb import configure as qppb_configure
from genie.libs.sdk.apis.arcos.qppb.configure import (
    configure_routing_policy_set_qos_class_id,
    unconfigure_routing_policy_set_qos_class_id,
    configure_bgp_rib_install_policy,
    unconfigure_bgp_rib_install_policy,
    configure_qos_classifier_qppb,
    unconfigure_qos_classifier_qppb,
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


class TestConfigureRoutingPolicySetQosClassId(unittest.TestCase):
    """configure_routing_policy_set_qos_class_id /
    unconfigure_routing_policy_set_qos_class_id"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_policy_basic(self):
        configure_routing_policy_set_qos_class_id(
            self.d, "QPPB-POL", 10, qos_class_id=5)
        c = self.d.cfg()
        self.assertIn("routing-policy policy-definition QPPB-POL", c)
        self.assertIn("statement 10", c)
        self.assertIn("actions accept-route", c)
        self.assertIn("actions bgp-actions set-qos-class-id 5", c)

    def test_policy_with_match_next_hop_set(self):
        configure_routing_policy_set_qos_class_id(
            self.d, "QPPB-POL", 10, qos_class_id=5,
            match_next_hop_set="NH-SET1")
        # EXACT emission pin, not assertIn. A mutation test showed that with
        # only substring checks, appending a stray rejected line to the
        # emission left this test green -- and on arcOS one rejected line
        # stages nothing, so the whole commit (including the correct lines)
        # becomes a silent no-op. Substring assertions cannot see an extra
        # line; an exact list can.
        #
        # The set name belongs under a "next-hop-set" sub-leaf. The bare form
        # this previously asserted is rejected by arcOS outright, so the old
        # assertion was pinning a silent-failure emission. See T2R-A.
        self.assertEqual(
            self.d.cfg().splitlines(),
            [
                "routing-policy policy-definition QPPB-POL",
                "statement 10",
                "conditions match-next-hop-set next-hop-set NH-SET1",
                "conditions match-next-hop-set match-set-options ANY",
                "actions accept-route",
                "actions bgp-actions set-qos-class-id 5",
                "!",
            ])

    def test_policy_with_match_set_options_all(self):
        configure_routing_policy_set_qos_class_id(
            self.d, "QPPB-POL", 10, qos_class_id=5,
            match_next_hop_set="NH-SET1", match_set_options="ALL")
        self.assertIn(
            "conditions match-next-hop-set match-set-options ALL", self.d.cfg())

    def test_policy_no_match_next_hop_set_omitted(self):
        configure_routing_policy_set_qos_class_id(
            self.d, "QPPB-POL", 10, qos_class_id=5)
        self.assertNotIn("match-next-hop-set", self.d.cfg())

    def test_policy_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_routing_policy_set_qos_class_id(
                d, "QPPB-POL", 10, qos_class_id=5)

    def test_unconfigure_policy(self):
        unconfigure_routing_policy_set_qos_class_id(self.d, "QPPB-POL")
        self.assertIn(
            "no routing-policy policy-definition QPPB-POL", self.d.cfg())

    def test_unconfigure_policy_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_routing_policy_set_qos_class_id(d, "QPPB-POL")


class TestConfigureBgpRibInstallPolicy(unittest.TestCase):
    """configure_bgp_rib_install_policy / unconfigure_bgp_rib_install_policy"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_rib_install_policy_basic(self):
        configure_bgp_rib_install_policy(self.d, "IPV4_UNICAST", "QPPB-POL")
        c = self.d.cfg()
        self.assertIn(
            "network-instance default protocol BGP default", c)
        self.assertIn("global afi-safi IPV4_UNICAST", c)
        self.assertIn("rib-install policy [ QPPB-POL ]", c)

    def test_rib_install_policy_named_instances(self):
        configure_bgp_rib_install_policy(
            self.d, "IPV4_UNICAST", "QPPB-POL",
            network_instance="vrf-red", protocol_instance="bgp1")
        self.assertIn("network-instance vrf-red protocol BGP bgp1", self.d.cfg())

    def test_rib_install_policy_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_bgp_rib_install_policy(d, "IPV4_UNICAST", "QPPB-POL")

    def test_unconfigure_rib_install_policy(self):
        unconfigure_bgp_rib_install_policy(self.d, "IPV4_UNICAST")
        c = self.d.cfg()
        self.assertIn("global afi-safi IPV4_UNICAST", c)
        self.assertIn("no rib-install policy", c)

    def test_unconfigure_rib_install_policy_named_instances(self):
        unconfigure_bgp_rib_install_policy(
            self.d, "IPV4_UNICAST",
            network_instance="vrf-red", protocol_instance="bgp1")
        self.assertIn("network-instance vrf-red protocol BGP bgp1", self.d.cfg())

    def test_unconfigure_rib_install_policy_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_bgp_rib_install_policy(d, "IPV4_UNICAST")


class TestConfigureQosClassifierQppb(unittest.TestCase):
    """configure_qos_classifier_qppb / unconfigure_qos_classifier_qppb"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_qos_classifier_src(self):
        configure_qos_classifier_qppb(
            self.d, "QPPB-CLASS", "SRC_QOS_CLASS", 5)
        c = self.d.cfg()
        self.assertIn("qos classifier QPPB-CLASS", c)
        self.assertIn("filter SRC_QOS_CLASS", c)
        self.assertIn("qos-class-id 5", c)

    def test_qos_classifier_dst(self):
        configure_qos_classifier_qppb(
            self.d, "QPPB-CLASS", "DST_QOS_CLASS", 7)
        c = self.d.cfg()
        self.assertIn("filter DST_QOS_CLASS", c)
        self.assertIn("qos-class-id 7", c)

    def test_qos_classifier_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_qos_classifier_qppb(d, "QPPB-CLASS", "SRC_QOS_CLASS", 5)

    def test_unconfigure_qos_classifier(self):
        unconfigure_qos_classifier_qppb(self.d, "QPPB-CLASS")
        self.assertIn("no qos classifier QPPB-CLASS", self.d.cfg())

    def test_unconfigure_qos_classifier_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_qos_classifier_qppb(d, "QPPB-CLASS")


class TestQppbConfigureFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in qppb/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(qppb_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == qppb_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered QPPB configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nQPPB configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
