"""Unit tests for ArcOS LLDP configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.lldp.arcos.lldp import Lldp


class TestLldp(TestCase):
    """Unit tests for Lldp configuration object."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_lldp_hello_timer(self):
        """Test LLDP hello-timer generates expected CLI."""
        dev_attr = Lldp.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.hello_timer = 60

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("lldp hello-timer 60", output)

    def test_lldp_empty_config(self):
        """Test LLDP with no attributes generates empty config."""
        dev_attr = Lldp.DeviceAttributes()
        dev_attr.device = self.device

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config).strip()

        self.assertEqual(output, "")

    def test_lldp_interface_mode(self):
        """Test InterfaceAttributes with mode generates expected CLI."""
        intf_attr = Lldp.DeviceAttributes.InterfaceAttributes()
        intf_attr.device = self.device
        intf_attr.interface_name = "ethernet-1/1"

        intf_attr.mode = "TX_RX"

        result = intf_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("lldp interface ethernet-1/1 mode TX_RX", output)

    def test_lldp_interface_enabled(self):
        """Test InterfaceAttributes with enabled=True generates 'enabled true'."""
        intf_attr = Lldp.DeviceAttributes.InterfaceAttributes()
        intf_attr.device = self.device
        intf_attr.interface_name = "ethernet-1/2"

        intf_attr.enabled = True

        result = intf_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("lldp interface ethernet-1/2 enabled true", output)

    def test_lldp_interface_disabled(self):
        """Test InterfaceAttributes with enabled=False generates 'enabled false'."""
        intf_attr = Lldp.DeviceAttributes.InterfaceAttributes()
        intf_attr.device = self.device
        intf_attr.interface_name = "ethernet-1/3"

        intf_attr.enabled = False

        result = intf_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("lldp interface ethernet-1/3 enabled false", output)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
