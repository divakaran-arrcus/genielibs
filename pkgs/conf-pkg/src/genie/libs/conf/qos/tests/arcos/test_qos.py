"""Unit tests for ArcOS QoS configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.qos.arcos.qos import Qos


class TestQosDeviceAttributes(TestCase):
    """Unit tests for Qos.DeviceAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_qos_tablemap(self):
        """Test QoS tablemap with from_type, to_type, and one entry."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.tablemaps = {
            "dscp-to-tc": {
                "from_type": "DSCP",
                "to_type": "LOCAL_TC",
                "entries": [
                    {
                        "local_tc": 0,
                        "dp": 0,
                        "from_values": [0, 8, 10, 16],
                    },
                ],
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("qos tablemap dscp-to-tc", output)
        self.assertIn("from-type DSCP", output)
        self.assertIn("to-type LOCAL_TC", output)
        self.assertIn("local-tc-entry 0 0", output)
        self.assertIn("from-value [ 0 8 10 16 ]", output)

    def test_qos_classifier_dscp(self):
        """Test QoS classifier with DSCP filter and dscp_values."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.classifiers = {
            "dscp-cs5": {
                "filter_type": "DSCP",
                "dscp_values": [40, 46],
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("qos classifier dscp-cs5", output)
        self.assertIn("filter DSCP dscp-value [ 40 46 ]", output)

    def test_qos_classifier_any(self):
        """Test QoS classifier with filter_type=ANY generates 'filter ANY'."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.classifiers = {
            "match-all": {
                "filter_type": "ANY",
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("qos classifier match-all", output)
        self.assertIn("filter ANY", output)

    def test_qos_policy_police(self):
        """Test QoS policy with POLICE action."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.policies = {
            "rate-limit-1g": {
                "classifiers": [
                    {
                        "classifier": "match-all",
                        "actions": [
                            {
                                "type": "POLICE",
                                "rate_value": 1000,
                                "rate_unit": "mbps",
                            },
                        ],
                    },
                ],
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("qos policy rate-limit-1g", output)
        self.assertIn("classifier match-all", output)
        self.assertIn(
            "action POLICE committed rate value 1000 unit mbps", output
        )

    def test_qos_interface_binding(self):
        """Test QoS interface binding with service-policy."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.interface_bindings = [
            {
                "interface": "swp1",
                "policy_direction": "ingress",
                "policy_name": "rate-limit-1g",
            },
        ]

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface swp1", output)
        self.assertIn(
            "qos service-policy ingress name rate-limit-1g", output
        )

    def test_qos_full_config(self):
        """Test QoS with tablemap, classifier, policy, and interface binding."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.tablemaps = {
            "dscp-map": {
                "from_type": "DSCP",
                "to_type": "LOCAL_TC",
                "entries": [
                    {
                        "local_tc": 1,
                        "dp": 0,
                        "from_values": [32, 34, 36],
                    },
                ],
            },
        }

        dev_attr.classifiers = {
            "voice": {
                "filter_type": "DSCP",
                "dscp_values": [46],
            },
            "default-cls": {
                "filter_type": "ANY",
            },
        }

        dev_attr.policies = {
            "ingress-pol": {
                "classifiers": [
                    {
                        "classifier": "voice",
                        "actions": [
                            {
                                "type": "POLICE",
                                "rate_value": 500,
                                "rate_unit": "mbps",
                            },
                        ],
                    },
                ],
            },
        }

        dev_attr.interface_bindings = [
            {
                "interface": "ethernet-1/1",
                "policy_direction": "ingress",
                "policy_name": "ingress-pol",
                "tablemap_direction": "ingress",
                "tablemap_name": "dscp-map",
            },
        ]

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        # Tablemap
        self.assertIn("qos tablemap dscp-map", output)
        self.assertIn("from-type DSCP", output)
        self.assertIn("to-type LOCAL_TC", output)
        self.assertIn("local-tc-entry 1 0", output)
        self.assertIn("from-value [ 32 34 36 ]", output)

        # Classifiers (sorted by name: default-cls before voice)
        self.assertIn("qos classifier default-cls", output)
        self.assertIn("filter ANY", output)
        self.assertIn("qos classifier voice", output)
        self.assertIn("filter DSCP dscp-value [ 46 ]", output)

        # Policy
        self.assertIn("qos policy ingress-pol", output)
        self.assertIn("classifier voice", output)
        self.assertIn(
            "action POLICE committed rate value 500 unit mbps", output
        )

        # Interface binding
        self.assertIn("interface ethernet-1/1", output)
        self.assertIn(
            "qos service-policy ingress name ingress-pol", output
        )
        self.assertIn(
            "qos service-tablemap ingress name dscp-map", output
        )


class TestQosDeviceAttributesUnconfig(TestCase):
    """Unit tests for Qos.DeviceAttributes build_unconfig() / build_config(unconfig=True)."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_qos_tablemap_unconfig(self):
        """Test build_unconfig() emits 'no' prefixed lines for a tablemap."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.tablemaps = {
            "dscp-to-tc": {
                "from_type": "DSCP",
                "to_type": "LOCAL_TC",
                "entries": [
                    {"local_tc": 0, "dp": 0, "from_values": [0, 8, 10, 16]},
                ],
            },
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("qos tablemap dscp-to-tc", output)
        self.assertIn("no from-type DSCP", output)
        self.assertIn("no to-type LOCAL_TC", output)
        self.assertIn("no from-value [ 0 8 10 16 ]", output)

    def test_qos_classifier_unconfig(self):
        """Test build_config(unconfig=True) emits 'no' prefixed lines for a classifier."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.classifiers = {
            "dscp-cs5": {
                "filter_type": "DSCP",
                "dscp_values": [40, 46],
            },
        }

        result = dev_attr.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn("qos classifier dscp-cs5", output)
        self.assertIn("no filter DSCP dscp-value [ 40 46 ]", output)

    def test_qos_policy_unconfig(self):
        """Test build_unconfig() emits 'no' prefixed lines for a policy action."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.policies = {
            "rate-limit-1g": {
                "classifiers": [
                    {
                        "classifier": "match-all",
                        "actions": [
                            {"type": "POLICE", "rate_value": 1000, "rate_unit": "mbps"},
                        ],
                    },
                ],
            },
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("qos policy rate-limit-1g", output)
        self.assertIn("no classifier match-all", output)
        self.assertIn(
            "no action POLICE committed rate value 1000 unit mbps", output
        )

    def test_qos_interface_binding_unconfig(self):
        """Test build_unconfig() emits 'no' prefixed lines for an interface binding."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.interface_bindings = [
            {
                "interface": "swp1",
                "policy_direction": "ingress",
                "policy_name": "rate-limit-1g",
            },
        ]

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface swp1", output)
        self.assertIn(
            "no qos service-policy ingress name rate-limit-1g", output
        )

    def test_qos_build_config_apply_true_calls_device_configure(self):
        """apply=True should call device.configure() with the rendered
        config and fail_invalid=True."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.classifiers = {"match-all": {"filter_type": "ANY"}}

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("qos classifier match-all", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))

    def test_qos_build_config_apply_true_no_config_skips_configure(self):
        """apply=True with zero attributes set should not call device.configure()."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_not_called()


class TestQosDeviceAttributesEdgeCases(TestCase):
    """Edge cases: no-op with zero attributes set, MPLS_TC / LOCAL_TC / ACL_IPV6
    classifier filters, and additional policy action types."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_no_attributes_set_yields_empty_config(self):
        """Zero attributes set -> empty CliConfig, nothing to apply."""
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device

        result = dev_attr.build_config(apply=False)
        self.assertEqual(str(result.cli_config), "")

    def test_classifier_mpls_tc(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.classifiers = {
            "mpls-cls": {"filter_type": "MPLS_TC", "mpls_tc_values": [5, 6]},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("filter MPLS_TC mpls-tc-value [ 5 6 ]", output)

    def test_classifier_local_tc(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.classifiers = {
            "tc-cls": {"filter_type": "LOCAL_TC", "local_tc_value": 2},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("filter LOCAL_TC local-tc-value 2", output)

    def test_classifier_acl_ipv6(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.classifiers = {
            "acl6-cls": {"filter_type": "ACL_IPV6", "acl_name": "ACL6"},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("filter ACL_IPV6 acl-name ACL6", output)

    def test_policy_action_marking(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.policies = {
            "pol-mk": {
                "classifiers": [
                    {"classifier": "c1", "actions": [
                        {"type": "MARKING", "local_tc": 4},
                    ]},
                ],
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("action MARKING local-tc 4", output)

    def test_policy_action_rate_min_and_excess(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.policies = {
            "pol-rm": {
                "classifiers": [
                    {"classifier": "c1", "actions": [
                        {"type": "RATE_MIN", "rate_value": 10, "rate_unit": "mbps"},
                        {"type": "RATE_EXCESS", "ratio": 3},
                    ]},
                ],
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("action RATE_MIN value 10 unit mbps", output)
        self.assertIn("action RATE_EXCESS ratio 3", output)

    def test_policy_action_random_detect(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.policies = {
            "pol-rd": {
                "classifiers": [
                    {"classifier": "c1", "actions": [
                        {"type": "RANDOM_DETECT", "profile": "wred1"},
                    ]},
                ],
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("action RANDOM_DETECT random-detect profile wred1", output)

    def test_policy_classifier_entry_without_classifier_name_skipped(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.policies = {
            "pol-skip": {
                "classifiers": [
                    {"actions": [{"type": "PRIORITY", "level": 1}]},
                ],
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("qos policy pol-skip", output)
        self.assertNotIn("action PRIORITY", output)

    def test_interface_binding_missing_interface_skipped(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.interface_bindings = [
            {"policy_direction": "ingress", "policy_name": "p1"},
        ]

        result = dev_attr.build_config(apply=False)
        self.assertEqual(str(result.cli_config), "")

    def test_interface_binding_tablemap_only(self):
        dev_attr = Qos.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.interface_bindings = [
            {
                "interface": "swp2",
                "tablemap_direction": "egress",
                "tablemap_name": "dscp-map",
            },
        ]

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)
        self.assertIn("interface swp2", output)
        self.assertIn("qos service-tablemap egress name dscp-map", output)
        self.assertNotIn("service-policy", output)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
