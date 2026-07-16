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

    def test_lldp_device_build_unconfig(self):
        """Test DeviceAttributes.build_unconfig prefixes 'no' onto the
        hello-timer line (build_unconfig delegates to build_config with
        unconfig=True)."""
        dev_attr = Lldp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.hello_timer = 45

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no lldp hello-timer 45", output)

    def test_lldp_interface_build_unconfig(self):
        """Test InterfaceAttributes.build_unconfig prefixes 'no' onto both
        the mode and enabled lines."""
        intf_attr = Lldp.DeviceAttributes.InterfaceAttributes()
        intf_attr.device = self.device
        intf_attr.interface_name = "swp1"
        intf_attr.mode = "TX_RX"
        intf_attr.enabled = False

        result = intf_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no lldp interface swp1 mode TX_RX", output)
        self.assertIn("no lldp interface swp1 enabled false", output)

    def test_lldp_device_build_config_aggregates_interface_attr(self):
        """Test DeviceAttributes.build_config's `interface_attr` mapping
        loop: when a sub-interface's build_config produces non-empty CLI,
        it is folded into the device-level config block alongside the
        global hello-timer line.

        Note: arcOS LLDP's DeviceAttributes ABC does not declare
        `interface_attr` as a managedattribute/SubAttributesDict itself
        (that only exists on the base genie.libs.conf.lldp.lldp.Lldp
        class, and the base<->arcos merge for LLDP is not wired through
        genie's abstraction `build_config` lookup -- confirmed it raises
        NotImplementedError when driven via the generic `Lldp` factory).
        Direct dispatch is therefore the only working path for arcOS LLDP,
        matching the ISIS/Interface conf gold-standard's approach of
        exercising the concrete arcos class directly. To reach the
        `attributes.mapping_values('interface_attr', ...)` loop under
        direct dispatch, a plain dict is assigned onto the instance --
        AttributesHelper only requires a mapping, not a declared
        managedattribute.
        """
        dev_attr = Lldp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.hello_timer = 45

        intf_attr = Lldp.DeviceAttributes.InterfaceAttributes()
        intf_attr.device = self.device
        intf_attr.interface_name = "swp1"
        intf_attr.mode = "TX_RX"
        intf_attr.enabled = True
        dev_attr.interface_attr = {"swp1": intf_attr}

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("lldp hello-timer 45", output)
        self.assertIn("lldp interface swp1 mode TX_RX", output)
        self.assertIn("lldp interface swp1 enabled true", output)

    def test_lldp_device_build_config_skips_empty_interface_attr(self):
        """When a mapped sub-interface has no attributes set, its
        build_config() returns an empty CliConfig and the `if intf_config:`
        guard skips appending an empty block."""
        dev_attr = Lldp.DeviceAttributes()
        dev_attr.device = self.device

        empty_intf_attr = Lldp.DeviceAttributes.InterfaceAttributes()
        empty_intf_attr.device = self.device
        empty_intf_attr.interface_name = "swp2"
        dev_attr.interface_attr = {"swp2": empty_intf_attr}

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config).strip()

        self.assertEqual(output, "")

    def test_lldp_device_build_config_apply_true_calls_device_configure(self):
        """When apply=True (and there is CLI to send), build_config pushes
        the rendered config straight to device.configure(fail_invalid=True)
        instead of returning a CliConfig."""
        dev_attr = Lldp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.hello_timer = 45

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("lldp hello-timer 45", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))

    def test_lldp_device_build_config_apply_true_empty_config_no_call(self):
        """When apply=True but there is no CLI to send (empty
        configurations), device.configure is never called."""
        dev_attr = Lldp.DeviceAttributes()
        dev_attr.device = self.device

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
