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


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
