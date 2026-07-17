"""Unit tests for ArcOS Network Instance configuration object.

NetworkInstance.DeviceAttributes.NetworkInstanceAttributes.build_config()
covers L3VRF (rib-options, table-connections, interface binding), L2VLAN
(type, vlan, EVI, FDB, interface binding), L2P2P_EVPN (VPWS), and plain
instances (interface binding only). Unlike the managedattribute-based
conf objects elsewhere in this tree, this plugin uses plain Python
attributes set directly on the instance (no AttributesHelper), and its
unconfig path collapses to a single `no network-instance <name>` line
regardless of which attributes were set.
"""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.network_instance.arcos.network_instance import NetworkInstance

NIA = NetworkInstance.DeviceAttributes.NetworkInstanceAttributes
DA = NetworkInstance.DeviceAttributes


class TestNetworkInstanceAttributesBuildConfig(TestCase):
    """Unit tests for NetworkInstanceAttributes.build_config()/build_unconfig()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_ni(self, ni_name, **attrs):
        ni = NIA()
        ni.device = self.device
        ni.ni_name = ni_name
        for key, value in attrs.items():
            setattr(ni, key, value)
        return ni

    # ------------------------------------------------------------------ #
    # 1. Basic type-only NI (L3VRF)
    # ------------------------------------------------------------------ #

    def test_basic_type(self):
        ni = self._make_ni("vrf1", ni_type="L3VRF")

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance vrf1", output)
        self.assertIn("type L3VRF", output)

    def test_no_attributes_still_emits_ni_block(self):
        """Even with zero attributes set (besides ni_name), the
        network-instance <name> context is still opened."""
        ni = self._make_ni("vrf1")

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance vrf1", output)
        self.assertNotIn("type", output)

    # ------------------------------------------------------------------ #
    # 2. L2VLAN: vlan object stanza + vlan line inside NI block
    # ------------------------------------------------------------------ #

    def test_l2vlan_vlan(self):
        ni = self._make_ni("vlan100", ni_type="L2VLAN", vlan=100)

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        # Top-level vlan object stanza created first
        self.assertIn("vlan 100", output)
        self.assertIn("vlan-id 100", output)
        # NI block itself
        self.assertIn("network-instance vlan100", output)
        self.assertIn("type L2VLAN", output)

    # ------------------------------------------------------------------ #
    # 3. Description
    # ------------------------------------------------------------------ #

    def test_description(self):
        ni = self._make_ni("VRF-1", description="L3VPN for customer A")

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn('description "L3VPN for customer A"', output)

    # ------------------------------------------------------------------ #
    # 4. Advertise MAC routes (L2VLAN)
    # ------------------------------------------------------------------ #

    def test_advertise_mac_routes_true(self):
        ni = self._make_ni("vlan100", advertise_mac_routes=True)

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("advertise-mac-routes true", output)

    def test_advertise_mac_routes_false(self):
        ni = self._make_ni("vlan100", advertise_mac_routes=False)

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("advertise-mac-routes false", output)

    # ------------------------------------------------------------------ #
    # 5. EVI alone (no sub-attributes) vs EVI with sub-attributes
    # ------------------------------------------------------------------ #

    def test_evi_alone_no_subattrs(self):
        """evi_id set but no sub-attributes -> single 'evi <id>' line,
        no submode context opened."""
        ni = self._make_ni("EPLAN-1", evi_id=2001)

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("evi 2001", output)
        self.assertNotIn("arp-nd-suppression", output)
        self.assertNotIn("control-word", output)
        self.assertNotIn("flow-label", output)
        self.assertNotIn("advertise-irb-mac-ip", output)

    def test_evi_with_all_subattrs(self):
        ni = self._make_ni(
            "EPLAN-1",
            evi_id=2001,
            evi_arp_nd_suppression=True,
            evi_advertise_irb_mac_ip=True,
            evi_control_word=False,
            evi_flow_label=False,
        )

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("evi 2001", output)
        self.assertIn("arp-nd-suppression true", output)
        self.assertIn("advertise-irb-mac-ip true", output)
        self.assertIn("control-word false", output)
        self.assertIn("flow-label false", output)

    # ------------------------------------------------------------------ #
    # 6. RIB options (IPv4 / IPv6)
    # ------------------------------------------------------------------ #

    def test_rib_options_ipv4(self):
        ni = self._make_ni(
            "VRF-1", rib_ipv4_max_prefix_limit=1000, rib_ipv4_threshold=90
        )

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("rib-options ipv4 max-prefix-limit 1000", output)
        self.assertIn("rib-options ipv4 threshold 90", output)

    def test_rib_options_ipv6(self):
        ni = self._make_ni(
            "VRF-1", rib_ipv6_max_prefix_limit=500, rib_ipv6_threshold=80
        )

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("rib-options ipv6 max-prefix-limit 500", output)
        self.assertIn("rib-options ipv6 threshold 80", output)

    # ------------------------------------------------------------------ #
    # 7. Table connections
    # ------------------------------------------------------------------ #

    def test_table_connection_full(self):
        ni = self._make_ni(
            "default",
            table_connections=[{
                "src_proto": "STATIC",
                "dst_proto": "ISIS",
                "af": "IPV4",
                "src_dst_instance": "default default",
                "import_policy": "redis_static",
            }],
        )

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("table-connection STATIC ISIS IPV4", output)
        self.assertIn("src-dst-instance default default", output)
        self.assertIn("import-policy [ redis_static ]", output)

    def test_table_connection_minimal(self):
        """No src_dst_instance/import_policy -> only the context header."""
        ni = self._make_ni(
            "default",
            table_connections=[{
                "src_proto": "STATIC", "dst_proto": "BGP", "af": "IPV6",
            }],
        )

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("table-connection STATIC BGP IPV6", output)
        self.assertNotIn("src-dst-instance", output)
        self.assertNotIn("import-policy", output)

    # ------------------------------------------------------------------ #
    # 8. Interface bindings (plain and VPWS)
    # ------------------------------------------------------------------ #

    def test_interfaces_plain(self):
        ni = self._make_ni("vlan100", interfaces=["swp1.100", "swp2.100"])

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface swp1.100", output)
        self.assertIn("interface swp2.100", output)
        self.assertNotIn("vpws-service-id", output)

    def test_interfaces_with_vpws(self):
        ni = self._make_ni(
            "VPWS-1",
            interfaces=["swp5.7001"],
            vpws_interfaces={"swp5.7001": {"local": 1001, "remote": 2001}},
        )

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface swp5.7001", output)
        self.assertIn("vpws-service-id local 1001", output)
        self.assertIn("vpws-service-id remote 2001", output)

    # ------------------------------------------------------------------ #
    # 9. FDB helpers (invoked directly - not via build_config(), which
    #    intentionally omits FDB so the caller can commit it separately)
    # ------------------------------------------------------------------ #

    def test_has_fdb_config_false_by_default(self):
        ni = self._make_ni("EPLAN-1")
        self.assertFalse(ni._has_fdb_config())

    def test_has_fdb_config_true(self):
        ni = self._make_ni("EPLAN-1", fdb_maximum_entries=2048)
        self.assertTrue(ni._has_fdb_config())

    def test_build_fdb_config_all_fields(self):
        from genie.conf.base.cli import CliConfigBuilder

        ni = self._make_ni(
            "EPLAN-1",
            fdb_maximum_entries=2048,
            fdb_packet_action="FLOOD_ACTION",
            fdb_mac_learning=True,
        )
        cb = CliConfigBuilder()
        ni._build_fdb_config(cb)
        output = str(cb)

        self.assertIn("fdb maximum-entries 2048", output)
        self.assertIn("fdb packet-action FLOOD_ACTION", output)
        self.assertIn("fdb mac-learning true", output)

    def test_build_fdb_config_mac_learning_false(self):
        from genie.conf.base.cli import CliConfigBuilder

        ni = self._make_ni("EPLAN-1", fdb_mac_learning=False)
        cb = CliConfigBuilder()
        ni._build_fdb_config(cb)

        self.assertIn("fdb mac-learning false", str(cb))

    def test_build_config_never_emits_fdb_lines(self):
        """build_config() itself must not emit FDB lines even when FDB
        attributes are set -- DeviceAttributes handles FDB as a second,
        separate commit."""
        ni = self._make_ni("EPLAN-1", fdb_maximum_entries=2048)

        result = ni.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance EPLAN-1", output)
        self.assertNotIn("fdb", output)

    # ------------------------------------------------------------------ #
    # 10. Unconfig
    # ------------------------------------------------------------------ #

    def test_build_config_unconfig_true(self):
        """Regardless of which attributes are set, unconfig=True collapses
        to a single 'no network-instance <name>' line."""
        ni = self._make_ni(
            "vrf1", ni_type="L3VRF", description="doomed",
            rib_ipv4_max_prefix_limit=1000,
        )

        result = ni.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertEqual(output, "no network-instance vrf1")

    def test_build_unconfig_delegates(self):
        ni = self._make_ni("vrf1", ni_type="L3VRF")

        result = ni.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertEqual(output, "no network-instance vrf1")


class TestNetworkInstanceDeviceAttributesBuildConfig(TestCase):
    """Unit tests for DeviceAttributes.build_config()/build_unconfig()
    (device-level dispatch across all configured NIs, plus the two-commit
    FDB handling)."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_ni(self, ni_name, **attrs):
        ni = NIA()
        ni.device = self.device
        ni.ni_name = ni_name
        for key, value in attrs.items():
            setattr(ni, key, value)
        return ni

    def test_device_build_config_delegates_and_sorts(self):
        """Aggregates config blocks from every NI in network_instance_attr,
        iterating in sorted (alphabetical) NI-name order regardless of
        insertion order."""
        dev_attr = DA()
        dev_attr.device = self.device
        dev_attr.network_instance_attr = {
            "b_vrf": self._make_ni("b_vrf", ni_type="L3VRF"),
            "a_vlan": self._make_ni("a_vlan", ni_type="L2VLAN", vlan=50),
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance a_vlan", output)
        self.assertIn("network-instance b_vrf", output)
        # a_vlan (sorted first) must appear before b_vrf in the output
        self.assertLess(
            output.index("network-instance a_vlan"),
            output.index("network-instance b_vrf"),
        )

    def test_device_build_config_empty_attr(self):
        dev_attr = DA()
        dev_attr.device = self.device
        dev_attr.network_instance_attr = {}

        result = dev_attr.build_config(apply=False)
        self.assertEqual(str(result.cli_config), "")

    def test_device_build_config_merges_fdb_block_dry_run(self):
        """apply=False (dry-run): FDB lines for NIs with FDB attrs are
        merged into the same returned CliConfig, appended after the main
        block."""
        dev_attr = DA()
        dev_attr.device = self.device
        dev_attr.network_instance_attr = {
            "eplan1": self._make_ni(
                "eplan1", ni_type="L2VLAN", fdb_maximum_entries=100,
            ),
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance eplan1", output)
        self.assertIn("type L2VLAN", output)
        self.assertIn("fdb maximum-entries 100", output)
        # FDB block is a second 'network-instance eplan1' stanza appended
        # after the main one.
        self.assertEqual(output.count("network-instance eplan1"), 2)

    def test_device_build_config_apply_true_two_commits_for_fdb(self):
        """apply=True with FDB attrs set -> device.configure() called
        twice: once for the main config, once for the FDB-only config."""
        dev_attr = DA()
        dev_attr.device = self.device
        dev_attr.network_instance_attr = {
            "eplan1": self._make_ni("eplan1", fdb_maximum_entries=500),
        }

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.assertEqual(self.device.configure.call_count, 2)
        first_call = self.device.configure.call_args_list[0][0][0]
        second_call = self.device.configure.call_args_list[1][0][0]
        self.assertIn("network-instance eplan1", first_call)
        self.assertNotIn("fdb", first_call)
        self.assertIn("fdb maximum-entries 500", second_call)

    def test_device_build_config_apply_true_single_commit_no_fdb(self):
        """apply=True without any FDB attrs -> device.configure() called
        exactly once."""
        dev_attr = DA()
        dev_attr.device = self.device
        dev_attr.network_instance_attr = {
            "vrf1": self._make_ni("vrf1", ni_type="L3VRF"),
        }

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args = self.device.configure.call_args[0][0]
        self.assertIn("network-instance vrf1", args)

    def test_device_build_unconfig_delegates_no_fdb_second_commit(self):
        """build_unconfig() must not trigger the FDB second-commit path
        even if the NI has FDB attributes set (guarded by `if not
        unconfig`), and every NI collapses to a single 'no
        network-instance <name>' line."""
        dev_attr = DA()
        dev_attr.device = self.device
        dev_attr.network_instance_attr = {
            "eplan1": self._make_ni("eplan1", fdb_maximum_entries=500),
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertEqual(output, "no network-instance eplan1")

    def test_device_build_unconfig_apply_true_single_commit(self):
        dev_attr = DA()
        dev_attr.device = self.device
        dev_attr.network_instance_attr = {
            "eplan1": self._make_ni("eplan1", fdb_maximum_entries=500),
        }

        result = dev_attr.build_unconfig(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args = self.device.configure.call_args[0][0]
        self.assertEqual(args, "no network-instance eplan1")


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
