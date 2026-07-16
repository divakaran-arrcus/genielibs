"""Unit tests for ArcOS VRRP configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.vrrp.arcos.vrrp import Vrrp


class TestVrrp(TestCase):
    """Unit tests for Vrrp VrrpGroupAttributes configuration object."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def _build(self, **kwargs):
        """Helper: create a VrrpGroupAttributes, set fields, return CLI string."""
        attr = Vrrp.DeviceAttributes.VrrpGroupAttributes()
        attr.device = self.device
        for k, v in kwargs.items():
            setattr(attr, k, v)
        result = attr.build_config(apply=False)
        return str(result.cli_config)

    # ------------------------------------------------------------------
    # 1. Basic VRRP: interface, sub_id, address, prefix_length, vrid, vips
    # ------------------------------------------------------------------
    def test_vrrp_basic(self):
        """Test basic VRRP group configuration."""
        output = self._build(
            interface="swp1",
            sub_id=0,
            address="10.1.1.1",
            prefix_length=24,
            vrid=10,
            virtual_addresses=["10.1.1.100"],
        )

        self.assertIn("interface swp1", output)
        self.assertIn("subinterface 0", output)
        self.assertIn("ipv4 address 10.1.1.1", output)
        self.assertIn("prefix-length 24", output)
        self.assertIn("vrrp vrrp-group 10", output)
        self.assertIn("virtual-address [ 10.1.1.100 ]", output)

    # ------------------------------------------------------------------
    # 2. Full VRRP: all optional attributes set
    # ------------------------------------------------------------------
    def test_vrrp_full(self):
        """Test VRRP group with all attributes including priority,
        advertisement-interval, accept-mode, and vrrp-version."""
        output = self._build(
            interface="swp2",
            sub_id=1,
            address="10.2.2.2",
            prefix_length=30,
            vrid=20,
            virtual_addresses=["10.2.2.100"],
            priority=150,
            advertisement_interval=200,
            accept_mode=True,
            vrrp_version="VRRP_V3",
        )

        self.assertIn("interface swp2", output)
        self.assertIn("subinterface 1", output)
        self.assertIn("ipv4 address 10.2.2.2", output)
        self.assertIn("prefix-length 30", output)
        self.assertIn("vrrp vrrp-group 20", output)
        self.assertIn("virtual-address [ 10.2.2.100 ]", output)
        self.assertIn("priority 150", output)
        self.assertIn("advertisement-interval 200", output)
        self.assertIn("accept-mode true", output)
        self.assertIn("vrrp-version VRRP_V3", output)

    # ------------------------------------------------------------------
    # 3. Missing required fields -> empty config
    # ------------------------------------------------------------------
    def test_vrrp_missing_required(self):
        """Test VRRP with no interface set produces empty config."""
        output = self._build(
            vrid=10,
            virtual_addresses=["10.1.1.100"],
        )

        # Should be empty since interface/address/prefix_length are missing
        self.assertEqual(output.strip(), "")

    # ------------------------------------------------------------------
    # 4. IPv6 VRRP with virtual_link_local
    # ------------------------------------------------------------------
    def test_vrrp_ipv6(self):
        """Test VRRP group with IPv6 address family and virtual-link-local."""
        output = self._build(
            interface="swp3",
            sub_id=0,
            af="ipv6",
            address="2001:db8::1",
            prefix_length=64,
            vrid=30,
            virtual_addresses=["2001:db8::100"],
            virtual_link_local="fe80::1",
        )

        self.assertIn("interface swp3", output)
        self.assertIn("subinterface 0", output)
        self.assertIn("ipv6 address 2001:db8::1", output)
        self.assertIn("prefix-length 64", output)
        self.assertIn("vrrp vrrp-group 30", output)
        self.assertIn("virtual-address [ 2001:db8::100 ]", output)
        self.assertIn("virtual-link-local fe80::1", output)
        # Ensure ipv4 is not used when af=ipv6
        self.assertNotIn("ipv4 address", output)

    # ------------------------------------------------------------------
    # 5. Multiple virtual addresses
    # ------------------------------------------------------------------
    def test_vrrp_multiple_vips(self):
        """Test VRRP group with multiple virtual addresses."""
        output = self._build(
            interface="swp4",
            sub_id=0,
            address="10.4.4.4",
            prefix_length=24,
            vrid=40,
            virtual_addresses=["10.4.4.100", "10.4.4.101", "10.4.4.102"],
        )

        self.assertIn("vrrp vrrp-group 40", output)
        self.assertIn(
            "virtual-address [ 10.4.4.100 10.4.4.101 10.4.4.102 ]", output
        )

    # ------------------------------------------------------------------
    # 6. sub_id not set -- defaults to subinterface 0
    # ------------------------------------------------------------------
    def test_vrrp_default_sub_id(self):
        """sub_id omitted entirely -- build_config falls back to 0."""
        output = self._build(
            interface="swp5",
            address="10.5.5.5",
            prefix_length=24,
            vrid=50,
        )

        self.assertIn("interface swp5", output)
        self.assertIn("subinterface 0", output)
        self.assertIn("vrrp vrrp-group 50", output)

    # ------------------------------------------------------------------
    # 7. Group-level build_unconfig() -- "no"-prefixed leaf lines
    # ------------------------------------------------------------------
    def test_vrrp_group_build_unconfig(self):
        """build_unconfig() delegates to build_config(unconfig=True) and
        emits 'no'-prefixed leaf lines (context lines stay unprefixed)."""
        attr = Vrrp.DeviceAttributes.VrrpGroupAttributes()
        attr.device = self.device
        attr.interface = "swp1"
        attr.sub_id = 0
        attr.address = "10.1.1.1"
        attr.prefix_length = 24
        attr.vrid = 10
        attr.virtual_addresses = ["10.1.1.100"]
        attr.priority = 200

        result = attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface swp1", output)
        self.assertIn("subinterface 0", output)
        self.assertIn("ipv4 address 10.1.1.1", output)
        self.assertIn("vrrp vrrp-group 10", output)
        self.assertIn("no prefix-length 24", output)
        self.assertIn("no virtual-address [ 10.1.1.100 ]", output)
        self.assertIn("no priority 200", output)

    def test_vrrp_group_virtual_addresses_non_list_defensive_branch(self):
        """virtual_addresses is managedattribute-typed to list-only, so the
        str(vips) fallback branch in build_config() can't be reached via
        the normal setter. Exercise it directly via the private slot to
        cover that defensive line."""
        attr = Vrrp.DeviceAttributes.VrrpGroupAttributes()
        attr.device = self.device
        attr.interface = "swp1"
        attr.sub_id = 0
        attr.address = "10.1.1.1"
        attr.prefix_length = 24
        attr.vrid = 10
        attr._virtual_addresses = "10.1.1.100"  # bypass list-only typing

        result = attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("virtual-address [ 10.1.1.100 ]", output)

    def test_vrrp_group_build_config_unconfig_true_missing_required(self):
        """Missing required fields short-circuits even with unconfig=True."""
        attr = Vrrp.DeviceAttributes.VrrpGroupAttributes()
        attr.device = self.device
        attr.vrid = 10

        result = attr.build_config(apply=False, unconfig=True)
        self.assertEqual(str(result.cli_config).strip(), "")


class TestVrrpDeviceAttributes(TestCase):
    """Unit tests for Vrrp.DeviceAttributes build_config()/build_unconfig()
    (device-level dispatch to per-group VrrpGroupAttributes via
    mapping_values)."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def _make_group(self, **attrs):
        grp = Vrrp.DeviceAttributes.VrrpGroupAttributes()
        grp.device = self.device
        for key, value in attrs.items():
            setattr(grp, key, value)
        return grp

    def test_device_build_config_delegates_to_groups(self):
        """Device-level build_config(apply=False) should aggregate config
        blocks from every group in vrrp_group_attr."""
        dev_attr = Vrrp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.vrrp_group_attr = {
            "g1": self._make_group(
                interface="swp1", sub_id=0, address="10.1.1.1",
                prefix_length=24, vrid=10,
                virtual_addresses=["10.1.1.100"], priority=200,
            ),
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface swp1", output)
        self.assertIn("vrrp vrrp-group 10", output)
        self.assertIn("priority 200", output)

    def test_device_build_config_empty_vrrp_group_attr(self):
        """No VRRP groups configured -> empty CliConfig, nothing to apply."""
        dev_attr = Vrrp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.vrrp_group_attr = {}

        result = dev_attr.build_config(apply=False)
        self.assertEqual(str(result.cli_config), "")

    def test_device_build_config_apply_true_calls_device_configure(self):
        """apply=True should call device.configure() with the rendered
        config and return None."""
        dev_attr = Vrrp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.vrrp_group_attr = {
            "g1": self._make_group(
                interface="swp1", sub_id=0, address="10.1.1.1",
                prefix_length=24, vrid=10,
            ),
        }

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("interface swp1", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))

    def test_device_build_config_apply_true_empty_skips_configure(self):
        """apply=True with no groups configured -- device.configure() is
        never called."""
        dev_attr = Vrrp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.vrrp_group_attr = {}

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_not_called()

    def test_device_build_unconfig_delegates(self):
        """build_unconfig() should delegate to build_config(unconfig=True)
        and emit 'no'-prefixed lines from the group."""
        dev_attr = Vrrp.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.vrrp_group_attr = {
            "g1": self._make_group(
                interface="swp1", sub_id=0, address="10.1.1.1",
                prefix_length=24, vrid=10, priority=200,
            ),
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface swp1", output)
        self.assertIn("no priority 200", output)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
