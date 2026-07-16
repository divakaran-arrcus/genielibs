#!/usr/bin/env python3
"""Unit tests for arcOS Interface configure APIs (full coverage).

Each helper builds an arcOS CLI config list under `interface <name>` (and, for
subinterface knobs, `subinterface <id>`) and calls device.configure(list). Tests
mock device.configure and assert the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.interface.configure import (
    configure_interface_mtu,
    configure_interface_description,
    configure_interface_port_speed,
    configure_interface_aggregate_id,
    configure_interface_lag,
    configure_interface_subinterface_ipv4,
    configure_interface_subinterface_ipv6,
    configure_interface_subinterface_vlan,
    configure_interface_debounce,
    configure_interface_bfd_micro,
    configure_interface_type,
    configure_interface_subinterface_vlan_double_tagged,
    configure_interface_subinterface_vlan_ingress_mapping,
    configure_interface_subinterface_vlan_egress_mapping,
    configure_interface_qos_service_policy,
    configure_interface_acl_binding,
    configure_interface_priority_vlan,
    configure_interface_subinterface_ipv4_enabled,
    configure_interface_subinterface_ipv6_enabled,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureInterface(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_mtu(self):
        configure_interface_mtu(self.d, "swp1", 9000)
        c = self.d.cfg(); self.assertIn("interface swp1", c); self.assertIn("mtu 9000", c)

    def test_description(self):
        configure_interface_description(self.d, "swp1", "Uplink")
        self.assertIn('description "Uplink"', self.d.cfg())

    def test_port_speed(self):
        configure_interface_port_speed(self.d, "swp1", "100G")
        self.assertIn("ethernet port-speed 100G", self.d.cfg())

    def test_aggregate_id(self):
        configure_interface_aggregate_id(self.d, "swp1", "bond1")
        self.assertIn("ethernet aggregate-id bond1", self.d.cfg())

    def test_lag(self):
        configure_interface_lag(self.d, "bond1", lag_type="LACP")
        self.assertIn("aggregation lag-type LACP", self.d.cfg())

    def test_subinterface_ipv4(self):
        configure_interface_subinterface_ipv4(self.d, "swp1", 1, "10.0.0.1", prefix_length=24)
        c = self.d.cfg()
        self.assertIn("subinterface 1", c); self.assertIn("ipv4 address 10.0.0.1", c)
        self.assertIn("prefix-length 24", c)

    def test_subinterface_ipv6(self):
        configure_interface_subinterface_ipv6(self.d, "swp1", 1, "2001:db8::1", prefix_length=64)
        c = self.d.cfg()
        self.assertIn("ipv6 address 2001:db8::1", c); self.assertIn("prefix-length 64", c)

    def test_subinterface_vlan(self):
        configure_interface_subinterface_vlan(self.d, "swp1", 1, 100)
        self.assertIn("vlan-id 100", self.d.cfg())

    def test_debounce(self):
        configure_interface_debounce(self.d, "swp1", up=100, down=200)
        c = self.d.cfg()
        self.assertIn("debounce-interval up 100", c); self.assertIn("debounce-interval down 200", c)

    def test_bfd_micro(self):
        configure_interface_bfd_micro(self.d, "swp1", remote_ipv4="10.0.0.2", enabled=True)
        self.assertIn("bfd micro remote-address ipv4 10.0.0.2", self.d.cfg())

    def test_type(self):
        configure_interface_type(self.d, "loopback0", "softwareLoopback")
        self.assertIn("type softwareLoopback", self.d.cfg())

    def test_vlan_double_tagged(self):
        configure_interface_subinterface_vlan_double_tagged(self.d, "swp1", 1, 10, 20)
        c = self.d.cfg()
        self.assertIn("inner-vlan-id 10", c); self.assertIn("outer-vlan-id 20", c)

    def test_vlan_ingress_mapping(self):
        configure_interface_subinterface_vlan_ingress_mapping(self.d, "swp1", 1, "PUSH")
        self.assertIn("vlan ingress-mapping vlan-stack-action PUSH", self.d.cfg())

    def test_vlan_egress_mapping(self):
        configure_interface_subinterface_vlan_egress_mapping(self.d, "swp1", 1, "POP")
        self.assertIn("vlan egress-mapping vlan-stack-action POP", self.d.cfg())

    def test_qos_service_policy(self):
        configure_interface_qos_service_policy(self.d, "swp1", "input", "p1")
        self.assertIn("qos service-policy input name p1", self.d.cfg())

    def test_acl_binding(self):
        configure_interface_acl_binding(self.d, "swp1", "ACL_L3", "a1")
        c = self.d.cfg()
        self.assertIn("acl-set ACL_L3", c); self.assertIn("set-name a1", c)

    def test_priority_vlan(self):
        configure_interface_priority_vlan(self.d, "swp1", sub_id=1)
        self.assertIn("interface swp1", self.d.cfg())

    def test_subinterface_ipv4_enabled(self):
        configure_interface_subinterface_ipv4_enabled(self.d, "swp1", sub_id=1, enabled=True)
        self.assertIn("ipv4 enabled true", self.d.cfg())

    def test_subinterface_ipv6_enabled(self):
        configure_interface_subinterface_ipv6_enabled(self.d, "swp1", sub_id=1, enabled=True)
        self.assertIn("ipv6 enabled true", self.d.cfg())


if __name__ == "__main__":
    unittest.main()
