"""Unit tests for ArcOS LAG (Bond/LACP) configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.lag.arcos.lag import Lag


class TestLagBondAttributes(TestCase):
    """Unit tests for Lag.DeviceAttributes.BondAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"

    def _make_bond(self, bond_name, **attrs):
        """Helper: create a BondAttributes instance with given attributes."""
        bond = Lag.DeviceAttributes.BondAttributes()
        bond.device = self.device
        bond.bond_name = bond_name
        for key, value in attrs.items():
            setattr(bond, key, value)
        return bond

    # ------------------------------------------------------------------ #
    # 1. Basic bond configuration
    # ------------------------------------------------------------------ #

    def test_lag_basic(self):
        """Test basic bond config: enabled, lag_type, min_links."""
        bond = self._make_bond(
            "bond0",
            enabled=True,
            lag_type="LACP",
            min_links=1,
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("enabled true", output)
        self.assertIn("aggregation lag-type LACP", output)
        self.assertIn("aggregation min-links 1", output)

    # ------------------------------------------------------------------ #
    # 2. Member interfaces
    # ------------------------------------------------------------------ #

    def test_lag_members(self):
        """Test member interfaces generate aggregate-id lines."""
        bond = self._make_bond(
            "bond0",
            members=["swp10", "swp20"],
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        # Each member should have its own interface block
        self.assertIn("interface swp10", output)
        self.assertIn("interface swp20", output)

        # Each member should be enabled and linked to bond0
        self.assertIn("enabled true", output)
        self.assertIn("ethernet aggregate-id bond0", output)

        # Verify aggregate-id references the correct bond
        self.assertEqual(output.count("ethernet aggregate-id bond0"), 2)

    # ------------------------------------------------------------------ #
    # 3. L2 ACCESS mode
    # ------------------------------------------------------------------ #

    def test_lag_l2_access(self):
        """Test L2 ACCESS mode with access VLAN."""
        bond = self._make_bond(
            "bond0",
            l2_mode="ACCESS",
            l2_access_vlan=100,
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("aggregation switched-vlan interface-mode ACCESS", output)
        self.assertIn("aggregation switched-vlan access-vlan 100", output)

    # ------------------------------------------------------------------ #
    # 4. L2 TRUNK mode
    # ------------------------------------------------------------------ #

    def test_lag_l2_trunk(self):
        """Test L2 TRUNK mode with trunk VLANs."""
        bond = self._make_bond(
            "bond0",
            l2_mode="TRUNK",
            l2_trunk_vlans=[100, 200, 300],
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("aggregation switched-vlan interface-mode TRUNK", output)
        self.assertIn("aggregation switched-vlan trunk-vlans [ 100 200 300 ]", output)

    # ------------------------------------------------------------------ #
    # 5. L3 IPv4 addressing
    # ------------------------------------------------------------------ #

    def test_lag_l3_ipv4(self):
        """Test L3 IPv4 address on bond via subinterface 0."""
        bond = self._make_bond(
            "bond0",
            ipv4_address="10.0.0.1",
            ipv4_prefix_length=24,
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("subinterface 0", output)
        self.assertIn("ipv4 address 10.0.0.1", output)
        self.assertIn("prefix-length 24", output)

    # ------------------------------------------------------------------ #
    # 6. LACP fallback
    # ------------------------------------------------------------------ #

    def test_lag_fallback(self):
        """Test LACP fallback mode, timeout, and primary interface."""
        bond = self._make_bond(
            "bond0",
            lacp_fallback_mode="INDIVIDUAL",
            lacp_fallback_timeout=5,
            lacp_fallback_primary="swp10",
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("aggregation lacp fallback mode INDIVIDUAL", output)
        self.assertIn("aggregation lacp fallback timeout 5", output)
        self.assertIn("aggregation lacp fallback primary-interface swp10", output)

    # ------------------------------------------------------------------ #
    # 7. Custom MAC
    # ------------------------------------------------------------------ #

    def test_lag_custom_mac(self):
        """Test custom-mac knob."""
        bond = self._make_bond("bond0", custom_mac=True)

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("custom-mac true", output)

    # ------------------------------------------------------------------ #
    # 8. L3 IPv6 addressing
    # ------------------------------------------------------------------ #

    def test_lag_l3_ipv6(self):
        """Test L3 IPv6 address on bond via subinterface 0."""
        bond = self._make_bond(
            "bond0",
            ipv6_address="2001:db8::1",
            ipv6_prefix_length=64,
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("subinterface 0", output)
        self.assertIn("ipv6 address 2001:db8::1", output)
        self.assertIn("prefix-length 64", output)

    def test_lag_l3_ipv4_and_ipv6_together(self):
        """Test both IPv4 and IPv6 addresses under the same subinterface 0."""
        bond = self._make_bond(
            "bond0",
            ipv4_address="10.0.0.1",
            ipv4_prefix_length=24,
            ipv6_address="2001:db8::1",
            ipv6_prefix_length=64,
        )

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("ipv4 address 10.0.0.1", output)
        self.assertIn("ipv6 address 2001:db8::1", output)

    # ------------------------------------------------------------------ #
    # 9. Unconfig
    # ------------------------------------------------------------------ #

    def test_lag_unconfig(self):
        """Test build_unconfig() emits 'no' prefixed lines."""
        bond = self._make_bond(
            "bond0",
            enabled=True,
            lag_type="LACP",
        )

        result = bond.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("no enabled true", output)
        self.assertIn("no aggregation lag-type LACP", output)

    def test_lag_build_config_unconfig_true(self):
        """Test build_config(unconfig=True) directly (build_unconfig
        delegates to this)."""
        bond = self._make_bond("bond0", min_links=2)

        result = bond.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn("no aggregation min-links 2", output)

    # ------------------------------------------------------------------ #
    # 10. No-op / empty attributes
    # ------------------------------------------------------------------ #

    def test_lag_no_attributes_still_emits_interface_block(self):
        """Even with zero attributes set, the interface <bond> context is
        still opened (no attribute-gated lines emitted inside)."""
        bond = self._make_bond("bond0")

        result = bond.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertNotIn("aggregation lag-type", output)
        self.assertNotIn("ethernet aggregate-id", output)


class TestLagDeviceAttributes(TestCase):
    """Unit tests for Lag.DeviceAttributes.build_config()/build_unconfig()
    (device-level dispatch to per-bond BondAttributes via mapping_values).
    """

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"

    def _make_bond(self, bond_name, **attrs):
        bond = Lag.DeviceAttributes.BondAttributes()
        bond.device = self.device
        bond.bond_name = bond_name
        for key, value in attrs.items():
            setattr(bond, key, value)
        return bond

    def test_device_build_config_delegates_to_bonds(self):
        """Device-level build_config(apply=False) should aggregate config
        blocks from every bond in bond_attr."""
        dev_attr = Lag.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.bond_attr = {
            "bond0": self._make_bond("bond0", enabled=True, lag_type="LACP"),
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("aggregation lag-type LACP", output)

    def test_device_build_config_empty_bond_attr(self):
        """No bonds configured -> empty CliConfig, nothing to apply."""
        dev_attr = Lag.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.bond_attr = {}

        result = dev_attr.build_config(apply=False)
        self.assertEqual(str(result.cli_config), "")

    def test_device_build_config_apply_true_calls_device_configure(self):
        """apply=True should call device.configure() with the rendered
        config and return None."""
        dev_attr = Lag.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.bond_attr = {
            "bond0": self._make_bond("bond0", enabled=True),
        }

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("interface bond0", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))

    def test_device_build_unconfig_delegates(self):
        """build_unconfig() should delegate to build_config(unconfig=True)
        and emit 'no' prefixed lines from the bond."""
        dev_attr = Lag.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.bond_attr = {
            "bond0": self._make_bond("bond0", enabled=True),
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("no enabled true", output)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
