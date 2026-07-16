"""Unit tests for ArcOS LDP configuration object (full coverage).

arcOS conf plugins use direct dispatch: the concrete arcos.ldp.Ldp class
(and its DeviceAttributes/InterfaceAttributes/NeighborAttributes) is
imported and instantiated directly, matching the ISIS/Interface/LAG
gold-standard pattern -- not the generic Genie conf factory.
"""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.ldp.arcos.ldp import Ldp

_NI_PREFIX = "network-instance default mpls signaling-protocols ldp"


class TestLdpDeviceAttributesGlobal(TestCase):
    """Unit tests for Ldp.DeviceAttributes build_config()/build_unconfig()
    -- global-level attributes."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_dev(self, **attrs):
        dev = Ldp.DeviceAttributes()
        dev.device = self.device
        for key, value in attrs.items():
            setattr(dev, key, value)
        return dev

    def test_lsr_id_and_enable(self):
        dev = self._make_dev(lsr_id="10.0.0.1", enable=True)
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(f"{_NI_PREFIX} global lsr-id 10.0.0.1", output)
        self.assertIn(f"{_NI_PREFIX} global enable true", output)

    def test_label_distribution_and_php(self):
        dev = self._make_dev(
            label_distribution_mode="ORDERED",
            php_enable=True,
            php_type="EXPLICIT",
            post_session_up_delay=30,
        )
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} global attributes label-distribution-mode "
            "ORDERED", output)
        self.assertIn(
            f"{_NI_PREFIX} global attributes php-enable true", output)
        self.assertIn(
            f"{_NI_PREFIX} global attributes php-type EXPLICIT", output)
        self.assertIn(
            f"{_NI_PREFIX} global attributes post-session-up-delay 30",
            output)

    def test_global_authentication(self):
        dev = self._make_dev(auth_enable=True, auth_key="mykey123")
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} global authentication enable true", output)
        self.assertIn(
            f"{_NI_PREFIX} global authentication authentication-key "
            "mykey123", output)

    def test_fec_filter_default_policy(self):
        dev = self._make_dev(fec_filter_default_export_policy="DENY_ROUTE")
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} global fec-filter default-export-policy "
            "DENY_ROUTE", output)

    def test_fec_filter_export_policy_list(self):
        dev = self._make_dev(
            fec_filter_export_policy=["POL1", "POL2"])
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} global fec-filter export-policy "
            "[ POL1 POL2 ]", output)

    def test_fec_filter_export_policy_scalar(self):
        dev = self._make_dev(fec_filter_export_policy="POL1")
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} global fec-filter export-policy [ POL1 ]",
            output)

    def test_transport_addresses(self):
        dev = self._make_dev(
            transport_address_ipv4="10.0.0.1",
            transport_address_ipv6="2001:db8::1",
        )
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} global transport-address ipv4 10.0.0.1", output)
        self.assertIn(
            f"{_NI_PREFIX} global transport-address ipv6 2001:db8::1",
            output)

    def test_maximum_local_binding(self):
        dev = self._make_dev(maximum_local_binding=1000)
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} global maximum-local-binding 1000", output)

    def test_rib_preference(self):
        dev = self._make_dev(rib_preference=20)
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(f"{_NI_PREFIX} global rib-preference 20", output)

    def test_session_protection(self):
        dev = self._make_dev(session_protection=60)
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(f"{_NI_PREFIX} global session-protection 60", output)

    def test_interface_attributes_global(self):
        dev = self._make_dev(hello_holdtime=15, hello_interval=5)
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} interface-attributes hello-holdtime 15", output)
        self.assertIn(
            f"{_NI_PREFIX} interface-attributes hello-interval 5", output)

    def test_targeted_global(self):
        dev = self._make_dev(
            targeted_hello_accept=True,
            targeted_hello_holdtime=45,
            targeted_hello_interval=15,
            targeted_strict=True,
        )
        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} targeted hello-accept true", output)
        self.assertIn(
            f"{_NI_PREFIX} targeted hello-holdtime 45", output)
        self.assertIn(
            f"{_NI_PREFIX} targeted hello-interval 15", output)
        self.assertIn(
            f"{_NI_PREFIX} targeted strict-targeted-hellos true", output)

    def test_no_attributes_empty_config(self):
        dev = self._make_dev()
        result = dev.build_config(apply=False)
        output = str(result.cli_config).strip()

        self.assertEqual(output, "")

    def test_build_unconfig(self):
        dev = self._make_dev(rib_preference=20, enable=True)
        result = dev.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"no {_NI_PREFIX} global rib-preference 20", output)
        self.assertIn(f"no {_NI_PREFIX} global enable true", output)

    def test_build_config_unconfig_true_directly(self):
        dev = self._make_dev(session_protection=0)
        result = dev.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn(
            f"no {_NI_PREFIX} global session-protection 0", output)

    def test_apply_true_calls_device_configure(self):
        dev = self._make_dev(lsr_id="10.0.0.1")
        result = dev.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn(f"{_NI_PREFIX} global lsr-id 10.0.0.1", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))

    def test_apply_true_empty_config_no_configure_call(self):
        dev = self._make_dev()
        result = dev.build_config(apply=True)

        self.assertIsNone(result)
        # configurations is empty CliConfigBuilder -> falsy -> no call
        self.device.configure.assert_not_called()


class TestLdpInterfaceAttributes(TestCase):
    """Unit tests for Ldp.DeviceAttributes.InterfaceAttributes
    build_config()/build_unconfig()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_intf(self, name, **attrs):
        intf = Ldp.DeviceAttributes.InterfaceAttributes()
        intf.device = self.device
        intf.interface_name = name
        for key, value in attrs.items():
            setattr(intf, key, value)
        return intf

    def test_link_hello_and_timers(self):
        intf = self._make_intf(
            "swp1", link_hello=True, intf_hello_holdtime=15,
            intf_hello_interval=5)
        result = intf.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} interface-attributes interface swp1", output)
        self.assertIn("link-hello true", output)
        self.assertIn("hello-holdtime 15", output)
        self.assertIn("hello-interval 5", output)

    def test_address_family_ipv4(self):
        intf = self._make_intf("swp1", ipv4_enabled=True)
        result = intf.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("address-family IPV4", output)
        self.assertIn("enabled true", output)

    def test_address_family_ipv6(self):
        intf = self._make_intf("swp1", ipv6_enabled=False)
        result = intf.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("address-family IPV6", output)
        self.assertIn("enabled false", output)

    def test_both_address_families(self):
        intf = self._make_intf(
            "swp1", ipv4_enabled=True, ipv6_enabled=True)
        result = intf.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("address-family IPV4", output)
        self.assertIn("address-family IPV6", output)

    def test_no_ni_prefix_defaults_empty(self):
        """When called directly with no ni_prefix, the submode context
        still opens on the bare interface-attributes path."""
        intf = self._make_intf("swp1", link_hello=True)
        result = intf.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface-attributes interface swp1", output)
        self.assertIn("link-hello true", output)

    def test_unconfig(self):
        intf = self._make_intf(
            "swp1", link_hello=True, intf_hello_holdtime=15)
        result = intf.build_unconfig(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} interface-attributes interface swp1", output)
        self.assertIn("no link-hello true", output)
        self.assertIn("no hello-holdtime 15", output)

    def test_build_config_unconfig_true_directly(self):
        intf = self._make_intf("swp1", ipv4_enabled=True)
        result = intf.build_config(
            apply=False, unconfig=True, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("no enabled true", output)


class TestLdpNeighborAttributes(TestCase):
    """Unit tests for Ldp.DeviceAttributes.NeighborAttributes
    build_config()/build_unconfig()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_nbr(self, neighbor_id, **attrs):
        nbr = Ldp.DeviceAttributes.NeighborAttributes()
        nbr.device = self.device
        nbr.neighbor_id = neighbor_id
        for key, value in attrs.items():
            setattr(nbr, key, value)
        return nbr

    def test_authentication(self):
        nbr = self._make_nbr(
            "1.1.1.1 0", nbr_auth_enable=True, nbr_auth_key="peerkey")
        result = nbr.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn(f"{_NI_PREFIX} neighbor 1.1.1.1 0", output)
        self.assertIn("authentication enable true", output)
        self.assertIn("authentication authentication-key peerkey", output)

    def test_max_remote_binding(self):
        nbr = self._make_nbr("1.1.1.1 0", nbr_max_remote_binding=500)
        result = nbr.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("maximum-remote-binding 500", output)

    def test_targeted_hello_timers(self):
        nbr = self._make_nbr(
            "1.1.1.1 0", nbr_targeted_hello_holdtime=60,
            nbr_targeted_hello_interval=20)
        result = nbr.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("targeted hello-holdtime 60", output)
        self.assertIn("targeted hello-interval 20", output)

    def test_targeted_ipv4(self):
        nbr = self._make_nbr(
            "1.1.1.1 0", nbr_targeted_ipv4_enabled=True,
            nbr_targeted_ipv4_dest="1.1.1.1")
        result = nbr.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("targeted address-family IPV4", output)
        self.assertIn("enabled true", output)
        self.assertIn("destination-address 1.1.1.1", output)

    def test_targeted_ipv6(self):
        nbr = self._make_nbr(
            "2001:db8::1 0", nbr_targeted_ipv6_enabled=False,
            nbr_targeted_ipv6_dest="2001:db8::1")
        result = nbr.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("targeted address-family IPV6", output)
        self.assertIn("enabled false", output)
        self.assertIn("destination-address 2001:db8::1", output)

    def test_no_attributes_still_opens_neighbor_context(self):
        nbr = self._make_nbr("1.1.1.1 0")
        result = nbr.build_config(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config).strip()

        # Only the neighbor context + exit line, no attribute-gated content
        self.assertNotIn("authentication", output)
        self.assertNotIn("maximum-remote-binding", output)

    def test_unconfig(self):
        nbr = self._make_nbr("1.1.1.1 0", nbr_max_remote_binding=500)
        result = nbr.build_unconfig(apply=False, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn(f"{_NI_PREFIX} neighbor 1.1.1.1 0", output)
        self.assertIn("no maximum-remote-binding 500", output)

    def test_build_config_unconfig_true_directly(self):
        nbr = self._make_nbr("1.1.1.1 0", nbr_auth_enable=True)
        result = nbr.build_config(
            apply=False, unconfig=True, ni_prefix=_NI_PREFIX)
        output = str(result.cli_config)

        self.assertIn("no authentication enable true", output)


class TestLdpDeviceAttributesDispatch(TestCase):
    """Unit tests for DeviceAttributes.build_config()'s dispatch to
    per-interface and per-neighbor sub-attribute mappings (interface_attr /
    neighbor_attr), matching the ISIS/LAG gold-standard's mapping_values()
    pattern. arcOS LDP's DeviceAttributes does not declare interface_attr/
    neighbor_attr as managedattributes -- a plain dict is assigned directly
    onto the instance, which AttributesHelper.mapping_values() accepts.
    """

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_dev(self, **attrs):
        dev = Ldp.DeviceAttributes()
        dev.device = self.device
        for key, value in attrs.items():
            setattr(dev, key, value)
        return dev

    def _make_intf(self, name, **attrs):
        intf = Ldp.DeviceAttributes.InterfaceAttributes()
        intf.device = self.device
        intf.interface_name = name
        for key, value in attrs.items():
            setattr(intf, key, value)
        return intf

    def _make_nbr(self, neighbor_id, **attrs):
        nbr = Ldp.DeviceAttributes.NeighborAttributes()
        nbr.device = self.device
        nbr.neighbor_id = neighbor_id
        for key, value in attrs.items():
            setattr(nbr, key, value)
        return nbr

    def test_device_build_config_aggregates_interface_attr(self):
        dev = self._make_dev(lsr_id="10.0.0.1")
        dev.interface_attr = {
            "swp1": self._make_intf("swp1", link_hello=True),
        }

        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(f"{_NI_PREFIX} global lsr-id 10.0.0.1", output)
        self.assertIn(
            f"{_NI_PREFIX} interface-attributes interface swp1", output)
        self.assertIn("link-hello true", output)

    def test_device_build_config_aggregates_neighbor_attr(self):
        dev = self._make_dev(enable=True)
        dev.neighbor_attr = {
            "1.1.1.1 0": self._make_nbr(
                "1.1.1.1 0", nbr_auth_enable=True),
        }

        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(f"{_NI_PREFIX} global enable true", output)
        self.assertIn(f"{_NI_PREFIX} neighbor 1.1.1.1 0", output)
        self.assertIn("authentication enable true", output)

    def test_device_build_config_empty_interface_attr_still_opens_block(self):
        """Unlike LLDP, the arcOS LDP InterfaceAttributes.build_config()
        unconditionally opens the `interface-attributes interface <intf>`
        submode context (submode_context is not gated behind an attribute
        check), so even a sub-interface with zero attributes set still
        emits its header + exit lines -- matching the LAG gold-standard's
        `test_lag_no_attributes_still_emits_interface_block`. The `if
        intf_config:` guard in DeviceAttributes.build_config only skips
        truly-empty (falsy) per-interface CliConfig objects, and this one
        is non-empty."""
        dev = self._make_dev()
        dev.interface_attr = {
            "swp1": self._make_intf("swp1"),  # no attributes set
        }

        result = dev.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} interface-attributes interface swp1", output)
        self.assertNotIn("link-hello", output)
        self.assertNotIn("hello-holdtime", output)
        self.assertNotIn("address-family", output)

    def test_device_build_unconfig_delegates_to_children(self):
        dev = self._make_dev()
        dev.interface_attr = {
            "swp1": self._make_intf("swp1", link_hello=True),
        }

        result = dev.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            f"{_NI_PREFIX} interface-attributes interface swp1", output)
        self.assertIn("no link-hello true", output)

    def test_device_build_config_apply_true_calls_configure(self):
        dev = self._make_dev()
        dev.neighbor_attr = {
            "1.1.1.1 0": self._make_nbr(
                "1.1.1.1 0", nbr_max_remote_binding=100),
        }

        result = dev.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("maximum-remote-binding 100", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
