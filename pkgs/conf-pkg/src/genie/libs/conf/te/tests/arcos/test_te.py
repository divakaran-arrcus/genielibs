"""Unit tests for ArcOS TE configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.te.arcos.te import Te


class TestTeDeviceAttributes(TestCase):
    """Unit tests for Te.DeviceAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_te_admin_groups_config(self):
        """Test TE admin-group config with two groups."""
        dev_attr = Te.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.admin_groups = {
            "green": {"bit_position": 2},
            "red": {"bit_position": 11},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("te admin-group green", output)
        self.assertIn("bit-position 2", output)
        self.assertIn("te admin-group red", output)
        self.assertIn("bit-position 11", output)

    def test_te_admin_groups_unconfig(self):
        """Test TE admin-group unconfig generates flat removal lines."""
        dev_attr = Te.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.admin_groups = {
            "green": {"bit_position": 2},
            "red": {"bit_position": 11},
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default te admin-group green", output)
        self.assertIn("network-instance default te admin-group red", output)
        # Unconfig should NOT contain bit-position sub-commands
        self.assertNotIn("bit-position", output)

    def test_te_empty_config(self):
        """Test TE with no admin_groups generates empty config."""
        dev_attr = Te.DeviceAttributes()
        dev_attr.device = self.device
        # admin_groups defaults to None

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config).strip()

        self.assertEqual(output, "")

    def test_te_single_group(self):
        """Test TE config with a single admin-group."""
        dev_attr = Te.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.admin_groups = {
            "blue": {"bit_position": 5},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("te admin-group blue", output)
        self.assertIn("bit-position 5", output)

    def test_te_group_without_bit_position(self):
        """Test TE admin-group dict entry with no bit_position key."""
        dev_attr = Te.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.admin_groups = {
            "yellow": {},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("te admin-group yellow", output)
        # No bit-position line should appear
        self.assertNotIn("bit-position", output)
