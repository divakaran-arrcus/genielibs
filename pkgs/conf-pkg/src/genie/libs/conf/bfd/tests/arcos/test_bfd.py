"""Unit tests for ArcOS BFD configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.bfd.arcos.bfd import Bfd


class TestBfdProfileAttributes(TestCase):
    """Unit tests for Bfd ProfileAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_bfd_profile_basic(self):
        """Test BFD profile with enabled, tx, rx, and multiplier."""
        profile = Bfd.DeviceAttributes.ProfileAttributes()
        profile.device = self.device
        profile.profile_name = "isis-bfd"

        profile.enabled = True
        profile.desired_minimum_tx_interval = 300
        profile.required_minimum_receive = 300
        profile.detection_multiplier = 3

        result = profile.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("bfd profile isis-bfd", output)
        self.assertIn("enabled true", output)
        self.assertIn("desired-minimum-tx-interval 300", output)
        self.assertIn("required-minimum-receive 300", output)
        self.assertIn("detection-multiplier 3", output)

    def test_bfd_profile_full(self):
        """Test BFD profile with all seven attributes set."""
        profile = Bfd.DeviceAttributes.ProfileAttributes()
        profile.device = self.device
        profile.profile_name = "full-profile"

        profile.enabled = True
        profile.desired_minimum_tx_interval = 150
        profile.required_minimum_receive = 200
        profile.detection_multiplier = 5
        profile.dscp_value = 48
        profile.v4_hw_offload = True
        profile.v6_hw_offload = False

        result = profile.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("bfd profile full-profile", output)
        self.assertIn("enabled true", output)
        self.assertIn("desired-minimum-tx-interval 150", output)
        self.assertIn("required-minimum-receive 200", output)
        self.assertIn("detection-multiplier 5", output)
        self.assertIn("dscp-value 48", output)
        self.assertIn("v4-hw-offload true", output)
        self.assertIn("v6-hw-offload false", output)

    def test_bfd_profile_disabled(self):
        """Test BFD profile with enabled=False generates 'enabled false'."""
        profile = Bfd.DeviceAttributes.ProfileAttributes()
        profile.device = self.device
        profile.profile_name = "disabled-prof"

        profile.enabled = False

        result = profile.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("bfd profile disabled-prof", output)
        self.assertIn("enabled false", output)

    def test_bfd_empty_profile(self):
        """Test BFD profile with no attributes set produces only context line."""
        profile = Bfd.DeviceAttributes.ProfileAttributes()
        profile.device = self.device
        profile.profile_name = "empty-prof"

        result = profile.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("bfd profile empty-prof", output)
        self.assertNotIn("enabled", output)
        self.assertNotIn("desired-minimum-tx-interval", output)
        self.assertNotIn("required-minimum-receive", output)
        self.assertNotIn("detection-multiplier", output)
        self.assertNotIn("dscp-value", output)
        self.assertNotIn("v4-hw-offload", output)
        self.assertNotIn("v6-hw-offload", output)


class TestBfdSingleHopInterfaceAttributes(TestCase):
    """Unit tests for Bfd SingleHopInterfaceAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_bfd_single_hop_basic(self):
        """Test BFD single-hop interface with tx, rx, and multiplier."""
        sh_attr = Bfd.DeviceAttributes.SingleHopInterfaceAttributes()
        sh_attr.device = self.device
        sh_attr.interface_name = "swp1"

        sh_attr.desired_minimum_tx_interval = 100
        sh_attr.required_minimum_receive = 100
        sh_attr.detection_multiplier = 5

        result = sh_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("bfd single-hop interface swp1", output)
        self.assertIn("desired-minimum-tx-interval 100", output)
        self.assertIn("required-minimum-receive 100", output)
        self.assertIn("detection-multiplier 5", output)

    def test_bfd_single_hop_partial(self):
        """Test BFD single-hop interface with only tx interval set."""
        sh_attr = Bfd.DeviceAttributes.SingleHopInterfaceAttributes()
        sh_attr.device = self.device
        sh_attr.interface_name = "swp2"

        sh_attr.desired_minimum_tx_interval = 250

        result = sh_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("bfd single-hop interface swp2", output)
        self.assertIn("desired-minimum-tx-interval 250", output)
        self.assertNotIn("required-minimum-receive", output)
        self.assertNotIn("detection-multiplier", output)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
