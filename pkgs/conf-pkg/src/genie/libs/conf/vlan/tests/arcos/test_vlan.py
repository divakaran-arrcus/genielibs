"""Unit tests for ArcOS VLAN configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.vlan.arcos.vlan import Vlan


class TestVlanAttributes(TestCase):
    """Unit tests for Vlan.DeviceAttributes.VlanAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"

    def test_vlan_basic_config(self):
        """Test basic VLAN config generates vlan name and vlan-id."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "VLAN100"
        attr.vlan_id = 100

        result = attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("vlan VLAN100", output)
        self.assertIn("vlan-id 100", output)

    def test_vlan_unconfig(self):
        """Test VLAN unconfiguration generates 'no vlan <name>'."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "VLAN100"
        attr.vlan_id = 100

        result = attr.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn("no vlan VLAN100", output)
        # Unconfig should NOT contain vlan-id sub-command
        self.assertNotIn("vlan-id", output)

    def test_vlan_config_without_vlan_id(self):
        """Test VLAN config with no vlan_id produces empty submode (cancel_empty)."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "VLAN200"
        # Deliberately do not set vlan_id

        result = attr.build_config(apply=False)
        output = str(result.cli_config).strip()

        # cancel_empty=True means no output when submode body is empty
        self.assertEqual(output, "")

    def test_vlan_unconfig_without_vlan_id(self):
        """Test VLAN unconfig works even when vlan_id is not set."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "MGMT-VLAN"

        result = attr.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn("no vlan MGMT-VLAN", output)

    def test_vlan_different_names(self):
        """Test VLAN config with various name formats."""
        for name, vid in [("DATA", 10), ("voice-vlan", 20), ("VLAN_999", 999)]:
            attr = Vlan.DeviceAttributes.VlanAttributes()
            attr.device = self.device
            attr.vlan_name = name
            attr.vlan_id = vid

            result = attr.build_config(apply=False)
            output = str(result.cli_config)

            self.assertIn(f"vlan {name}", output)
            self.assertIn(f"vlan-id {vid}", output)
