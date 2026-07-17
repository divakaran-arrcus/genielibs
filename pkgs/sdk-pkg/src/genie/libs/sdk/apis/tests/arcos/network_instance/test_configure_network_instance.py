#!/usr/bin/env python3
"""Unit tests for arcOS Network Instance configure/unconfigure APIs
(full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.network_instance.configure builds an arcOS CLI
config list (starting with the `network-instance <ni_name>` context) and
calls `device.configure(config)`. Tests mock `device.configure` and assert
on a distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.network_instance import configure as ni_configure
from genie.libs.sdk.apis.arcos.network_instance.configure import (
    configure_network_instance,
    unconfigure_network_instance,
    configure_network_instance_interface,
    unconfigure_network_instance_interface,
    configure_network_instance_vni,
    unconfigure_network_instance_vni,
    configure_network_instance_evi,
    unconfigure_network_instance_evi,
    configure_network_instance_advertise_mac_routes,
    unconfigure_network_instance_advertise_mac_routes,
    configure_network_instance_vlan,
    unconfigure_network_instance_vlan,
    configure_network_instance_description,
    unconfigure_network_instance_description,
    configure_network_instance_evi_attributes,
    unconfigure_network_instance_evi_attributes,
    configure_network_instance_fdb,
    unconfigure_network_instance_fdb,
    configure_network_instance_rib_options,
    unconfigure_network_instance_rib_options,
    configure_network_instance_table_connection,
    unconfigure_network_instance_table_connection,
    configure_network_instance_vpws_service_id,
    unconfigure_network_instance_vpws_service_id,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class _RaisingDevice:
    """Device whose .configure() always raises SubCommandFailure."""

    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(side_effect=SubCommandFailure("boom"))


class TestNetworkInstanceBasicApis(unittest.TestCase):
    """configure_network_instance, unconfigure_network_instance"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_network_instance_no_type(self):
        configure_network_instance(self.d, "vlan100")
        c = self.d.cfg()
        self.assertIn("network-instance vlan100", c)
        self.assertNotIn("type", c)

    def test_network_instance_with_type(self):
        configure_network_instance(self.d, "vlan100", ni_type="L2VLAN")
        c = self.d.cfg()
        self.assertIn("network-instance vlan100", c)
        self.assertIn("type L2VLAN", c)

    def test_unconfigure_network_instance(self):
        unconfigure_network_instance(self.d, "vlan100")
        self.assertIn("no network-instance vlan100", self.d.cfg())


class TestNetworkInstanceInterfaceApis(unittest.TestCase):
    """configure_network_instance_interface, unconfigure_network_instance_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface(self):
        configure_network_instance_interface(self.d, "vlan100", "swp1.100")
        c = self.d.cfg()
        self.assertIn("network-instance vlan100", c)
        self.assertIn("interface swp1.100", c)

    def test_unconfigure_interface(self):
        unconfigure_network_instance_interface(self.d, "vlan100", "swp1.100")
        c = self.d.cfg()
        self.assertIn("network-instance vlan100", c)
        self.assertIn("no interface swp1.100", c)


class TestNetworkInstanceVniApis(unittest.TestCase):
    """configure_network_instance_vni, unconfigure_network_instance_vni"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_vni_default_ltep(self):
        configure_network_instance_vni(self.d, "vlan100", 100)
        c = self.d.cfg()
        self.assertIn("network-instance vlan100", c)
        self.assertIn("vni 100 local-tunnel-endpoint-id 0", c)

    def test_vni_explicit_ltep(self):
        configure_network_instance_vni(self.d, "vlan100", 100, ltep_id=5)
        self.assertIn("vni 100 local-tunnel-endpoint-id 5", self.d.cfg())

    def test_unconfigure_vni(self):
        unconfigure_network_instance_vni(self.d, "vlan100", 100)
        self.assertIn("no vni 100", self.d.cfg())


class TestNetworkInstanceEviApis(unittest.TestCase):
    """configure_network_instance_evi, unconfigure_network_instance_evi"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_evi(self):
        configure_network_instance_evi(self.d, "vlan100", 100)
        c = self.d.cfg()
        self.assertIn("network-instance vlan100", c)
        self.assertIn("evi 100", c)

    def test_unconfigure_evi(self):
        unconfigure_network_instance_evi(self.d, "vlan100", 100)
        self.assertIn("no evi 100", self.d.cfg())


class TestNetworkInstanceAdvertiseMacRoutesApis(unittest.TestCase):
    """configure_network_instance_advertise_mac_routes,
    unconfigure_network_instance_advertise_mac_routes"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_advertise_mac_routes_default_true(self):
        configure_network_instance_advertise_mac_routes(self.d, "vlan100")
        self.assertIn("advertise-mac-routes true", self.d.cfg())

    def test_advertise_mac_routes_false(self):
        configure_network_instance_advertise_mac_routes(
            self.d, "vlan100", enabled=False
        )
        self.assertIn("advertise-mac-routes false", self.d.cfg())

    def test_unconfigure_advertise_mac_routes(self):
        unconfigure_network_instance_advertise_mac_routes(self.d, "vlan100")
        self.assertIn("no advertise-mac-routes", self.d.cfg())


class TestNetworkInstanceVlanApis(unittest.TestCase):
    """configure_network_instance_vlan, unconfigure_network_instance_vlan"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_vlan(self):
        configure_network_instance_vlan(self.d, "vlan3500", 3500)
        c = self.d.cfg()
        self.assertIn("network-instance vlan3500", c)
        self.assertIn("vlan 3500", c)

    def test_unconfigure_vlan(self):
        unconfigure_network_instance_vlan(self.d, "vlan3500")
        self.assertIn("no vlan", self.d.cfg())


class TestNetworkInstanceDescriptionApis(unittest.TestCase):
    """configure_network_instance_description, unconfigure_network_instance_description"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_description(self):
        configure_network_instance_description(
            self.d, "VRF-1", "L3VPN for customer A"
        )
        c = self.d.cfg()
        self.assertIn("network-instance VRF-1", c)
        self.assertIn('description "L3VPN for customer A"', c)

    def test_unconfigure_description(self):
        unconfigure_network_instance_description(self.d, "VRF-1")
        self.assertIn("no description", self.d.cfg())


class TestNetworkInstanceEviAttributesApis(unittest.TestCase):
    """configure_network_instance_evi_attributes, unconfigure_network_instance_evi_attributes"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_evi_attributes_none_set(self):
        """Only evi_id passed - no optional sub-attribute lines emitted."""
        configure_network_instance_evi_attributes(self.d, "EPLAN-1", 2001)
        c = self.d.cfg()
        self.assertIn("network-instance EPLAN-1", c)
        self.assertIn("evi 2001", c)
        self.assertNotIn("arp-nd-suppression", c)
        self.assertNotIn("control-word", c)
        self.assertNotIn("flow-label", c)
        self.assertNotIn("advertise-irb-mac-ip", c)

    def test_evi_attributes_all_true(self):
        configure_network_instance_evi_attributes(
            self.d, "EPLAN-1", 2001,
            arp_nd_suppression=True,
            control_word=True,
            flow_label=True,
            advertise_irb_mac_ip=True,
        )
        c = self.d.cfg()
        self.assertIn("arp-nd-suppression true", c)
        self.assertIn("control-word true", c)
        self.assertIn("flow-label true", c)
        self.assertIn("advertise-irb-mac-ip true", c)

    def test_evi_attributes_all_false(self):
        configure_network_instance_evi_attributes(
            self.d, "EPLAN-1", 2001,
            arp_nd_suppression=False,
            control_word=False,
            flow_label=False,
            advertise_irb_mac_ip=False,
        )
        c = self.d.cfg()
        self.assertIn("arp-nd-suppression false", c)
        self.assertIn("control-word false", c)
        self.assertIn("flow-label false", c)
        self.assertIn("advertise-irb-mac-ip false", c)

    def test_unconfigure_evi_attributes(self):
        unconfigure_network_instance_evi_attributes(self.d, "EPLAN-1", 2001)
        c = self.d.cfg()
        self.assertIn("evi 2001", c)
        self.assertIn("no arp-nd-suppression", c)
        self.assertIn("no control-word", c)
        self.assertIn("no flow-label", c)
        self.assertIn("no advertise-irb-mac-ip", c)


class TestNetworkInstanceFdbApis(unittest.TestCase):
    """configure_network_instance_fdb, unconfigure_network_instance_fdb"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_fdb_none_set(self):
        """No optional args - only the NI context is opened."""
        configure_network_instance_fdb(self.d, "EPLAN-1")
        c = self.d.cfg()
        self.assertIn("network-instance EPLAN-1", c)
        self.assertNotIn("fdb", c)

    def test_fdb_all_set(self):
        configure_network_instance_fdb(
            self.d, "EPLAN-1",
            maximum_entries=2048,
            packet_action="FLOOD_ACTION",
            mac_learning=True,
        )
        c = self.d.cfg()
        self.assertIn("fdb maximum-entries 2048", c)
        self.assertIn("fdb packet-action FLOOD_ACTION", c)
        self.assertIn("fdb mac-learning true", c)

    def test_fdb_mac_learning_false(self):
        configure_network_instance_fdb(self.d, "EPLAN-1", mac_learning=False)
        self.assertIn("fdb mac-learning false", self.d.cfg())

    def test_unconfigure_fdb(self):
        unconfigure_network_instance_fdb(self.d, "EPLAN-1")
        c = self.d.cfg()
        self.assertIn("no fdb maximum-entries", c)
        self.assertIn("no fdb packet-action", c)
        self.assertIn("no fdb mac-learning", c)


class TestNetworkInstanceRibOptionsApis(unittest.TestCase):
    """configure_network_instance_rib_options, unconfigure_network_instance_rib_options"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_rib_options_default_af_none_set(self):
        """No optional args - only the NI context is opened, no rib-options line."""
        configure_network_instance_rib_options(self.d, "VRF-1")
        c = self.d.cfg()
        self.assertIn("network-instance VRF-1", c)
        self.assertNotIn("rib-options", c)

    def test_rib_options_ipv4(self):
        configure_network_instance_rib_options(
            self.d, "VRF-1", af="ipv4", max_prefix_limit=1000, threshold=90
        )
        c = self.d.cfg()
        self.assertIn("rib-options ipv4 max-prefix-limit 1000", c)
        self.assertIn("rib-options ipv4 threshold 90", c)

    def test_rib_options_ipv6(self):
        configure_network_instance_rib_options(
            self.d, "VRF-1", af="IPv6", max_prefix_limit=500
        )
        c = self.d.cfg()
        self.assertIn("rib-options ipv6 max-prefix-limit 500", c)
        self.assertNotIn("threshold", c)

    def test_unconfigure_rib_options_default(self):
        unconfigure_network_instance_rib_options(self.d, "VRF-1")
        c = self.d.cfg()
        self.assertIn("no rib-options ipv4 max-prefix-limit", c)
        self.assertIn("no rib-options ipv4 threshold", c)

    def test_unconfigure_rib_options_ipv6(self):
        unconfigure_network_instance_rib_options(self.d, "VRF-1", af="ipv6")
        c = self.d.cfg()
        self.assertIn("no rib-options ipv6 max-prefix-limit", c)
        self.assertIn("no rib-options ipv6 threshold", c)


class TestNetworkInstanceTableConnectionApis(unittest.TestCase):
    """configure_network_instance_table_connection, unconfigure_network_instance_table_connection"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_table_connection_minimal(self):
        """No optional src_dst_instance/import_policy - only the context header."""
        configure_network_instance_table_connection(
            self.d, "default", "STATIC", "ISIS", "IPV4"
        )
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("table-connection STATIC ISIS IPV4", c)
        self.assertNotIn("src-dst-instance", c)
        self.assertNotIn("import-policy", c)

    def test_table_connection_full(self):
        configure_network_instance_table_connection(
            self.d, "default", "STATIC", "ISIS", "IPV4",
            src_dst_instance="default default",
            import_policy="redis_static",
        )
        c = self.d.cfg()
        self.assertIn("src-dst-instance default default", c)
        self.assertIn("import-policy [ redis_static ]", c)

    def test_unconfigure_table_connection(self):
        unconfigure_network_instance_table_connection(
            self.d, "default", "STATIC", "ISIS", "IPV4"
        )
        self.assertIn("no table-connection STATIC ISIS IPV4", self.d.cfg())


class TestNetworkInstanceVpwsServiceIdApis(unittest.TestCase):
    """configure_network_instance_vpws_service_id, unconfigure_network_instance_vpws_service_id"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_vpws_service_id(self):
        configure_network_instance_vpws_service_id(
            self.d, "VPWS-1", "swp5.7001", local_id=1001, remote_id=2001
        )
        c = self.d.cfg()
        self.assertIn("network-instance VPWS-1", c)
        self.assertIn("interface swp5.7001", c)
        self.assertIn("vpws-service-id local 1001", c)
        self.assertIn("vpws-service-id remote 2001", c)

    def test_unconfigure_vpws_service_id(self):
        unconfigure_network_instance_vpws_service_id(
            self.d, "VPWS-1", "swp5.7001"
        )
        c = self.d.cfg()
        self.assertIn("no vpws-service-id local", c)
        self.assertIn("no vpws-service-id remote", c)


class TestNetworkInstanceExceptionHandling(unittest.TestCase):
    """Verify that SubCommandFailure raised by device.configure() is caught
    and re-raised with a descriptive message (try/except pattern shared by
    every configure_*/unconfigure_* helper in this module).
    """

    def setUp(self):
        self.d = _RaisingDevice()

    def test_configure_network_instance_raises(self):
        with self.assertRaises(SubCommandFailure) as ctx:
            configure_network_instance(self.d, "vlan100")
        self.assertIn("Could not create network-instance vlan100", str(ctx.exception))

    def test_unconfigure_network_instance_raises(self):
        with self.assertRaises(SubCommandFailure) as ctx:
            unconfigure_network_instance(self.d, "vlan100")
        self.assertIn("Could not remove network-instance vlan100", str(ctx.exception))

    def test_configure_network_instance_vni_raises(self):
        with self.assertRaises(SubCommandFailure) as ctx:
            configure_network_instance_vni(self.d, "vlan100", 100)
        self.assertIn("Could not configure VNI 100", str(ctx.exception))

    def test_configure_network_instance_table_connection_raises(self):
        with self.assertRaises(SubCommandFailure) as ctx:
            configure_network_instance_table_connection(
                self.d, "default", "STATIC", "ISIS", "IPV4"
            )
        self.assertIn("Could not configure table-connection", str(ctx.exception))

    def test_configure_network_instance_vpws_service_id_raises(self):
        with self.assertRaises(SubCommandFailure) as ctx:
            configure_network_instance_vpws_service_id(
                self.d, "VPWS-1", "swp5.7001", local_id=1, remote_id=2
            )
        self.assertIn("Could not configure VPWS service-id", str(ctx.exception))


class TestNetworkInstanceConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in network_instance/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ni_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ni_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Network Instance configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nNetwork Instance configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
