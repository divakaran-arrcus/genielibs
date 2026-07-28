#!/usr/bin/env python3
"""Unit tests for arcOS Interface configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under `interface <name>` (and, for
subinterface knobs, `subinterface <id>`) and calls device.configure(list). Tests
mock device.configure and assert the emitted CLI.

shut_interface/unshut_interface additionally check `device.is_connected()`
before configuring (and call `connect_device()` if not connected); _CfgDevice
stubs `is_connected()` to return True so those helpers go straight to
device.configure().

A machine coverage check (test_zzz_all_functions_covered) asserts every
public function in genie.libs.sdk.apis.arcos.interface.configure was
exercised by some test in this file, and a SubCommandFailure class exercises
the re-raise path of every newly-added (shut/unshut/unconfigure_*) helper.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.interface.configure as configure_module
from genie.libs.sdk.apis.arcos.interface.configure import (
    shut_interface,
    unshut_interface,
    configure_interface_mtu,
    unconfigure_interface_mtu,
    configure_interface_description,
    unconfigure_interface_description,
    configure_interface_port_speed,
    unconfigure_interface_port_speed,
    configure_interface_aggregate_id,
    unconfigure_interface_aggregate_id,
    configure_interface_lag,
    unconfigure_interface_lag,
    configure_interface_subinterface_ipv4,
    unconfigure_interface_subinterface_ipv4,
    configure_interface_subinterface_ipv6,
    unconfigure_interface_subinterface_ipv6,
    configure_interface_subinterface_vlan,
    unconfigure_interface_subinterface_vlan,
    configure_interface_debounce,
    unconfigure_interface_debounce,
    configure_interface_bfd_micro,
    unconfigure_interface_bfd_micro,
    configure_interface_type,
    unconfigure_interface_type,
    configure_interface_subinterface_vlan_double_tagged,
    unconfigure_interface_subinterface_vlan_double_tagged,
    configure_interface_subinterface_vlan_ingress_mapping,
    unconfigure_interface_subinterface_vlan_ingress_mapping,
    configure_interface_subinterface_vlan_egress_mapping,
    unconfigure_interface_subinterface_vlan_egress_mapping,
    configure_interface_qos_service_policy,
    unconfigure_interface_qos_service_policy,
    configure_interface_acl_binding,
    unconfigure_interface_acl_binding,
    configure_interface_priority_vlan,
    unconfigure_interface_priority_vlan,
    configure_interface_subinterface_ipv4_enabled,
    configure_interface_subinterface_ipv6_enabled,
)

# ---------------------------------------------------------------------------
# Machine coverage tracking: wrap each imported function so calling it during
# a test records its name. The final test asserts every public function in
# the module was called at least once.
# ---------------------------------------------------------------------------
_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


shut_interface = _track("shut_interface", shut_interface)
unshut_interface = _track("unshut_interface", unshut_interface)
configure_interface_mtu = _track("configure_interface_mtu", configure_interface_mtu)
unconfigure_interface_mtu = _track(
    "unconfigure_interface_mtu", unconfigure_interface_mtu
)
configure_interface_description = _track(
    "configure_interface_description", configure_interface_description
)
unconfigure_interface_description = _track(
    "unconfigure_interface_description", unconfigure_interface_description
)
configure_interface_port_speed = _track(
    "configure_interface_port_speed", configure_interface_port_speed
)
unconfigure_interface_port_speed = _track(
    "unconfigure_interface_port_speed", unconfigure_interface_port_speed
)
configure_interface_aggregate_id = _track(
    "configure_interface_aggregate_id", configure_interface_aggregate_id
)
unconfigure_interface_aggregate_id = _track(
    "unconfigure_interface_aggregate_id", unconfigure_interface_aggregate_id
)
configure_interface_lag = _track("configure_interface_lag", configure_interface_lag)
unconfigure_interface_lag = _track(
    "unconfigure_interface_lag", unconfigure_interface_lag
)
configure_interface_subinterface_ipv4 = _track(
    "configure_interface_subinterface_ipv4", configure_interface_subinterface_ipv4
)
unconfigure_interface_subinterface_ipv4 = _track(
    "unconfigure_interface_subinterface_ipv4",
    unconfigure_interface_subinterface_ipv4,
)
configure_interface_subinterface_ipv6 = _track(
    "configure_interface_subinterface_ipv6", configure_interface_subinterface_ipv6
)
unconfigure_interface_subinterface_ipv6 = _track(
    "unconfigure_interface_subinterface_ipv6",
    unconfigure_interface_subinterface_ipv6,
)
configure_interface_subinterface_vlan = _track(
    "configure_interface_subinterface_vlan", configure_interface_subinterface_vlan
)
unconfigure_interface_subinterface_vlan = _track(
    "unconfigure_interface_subinterface_vlan",
    unconfigure_interface_subinterface_vlan,
)
configure_interface_debounce = _track(
    "configure_interface_debounce", configure_interface_debounce
)
unconfigure_interface_debounce = _track(
    "unconfigure_interface_debounce", unconfigure_interface_debounce
)
configure_interface_bfd_micro = _track(
    "configure_interface_bfd_micro", configure_interface_bfd_micro
)
unconfigure_interface_bfd_micro = _track(
    "unconfigure_interface_bfd_micro", unconfigure_interface_bfd_micro
)
configure_interface_type = _track("configure_interface_type", configure_interface_type)
unconfigure_interface_type = _track(
    "unconfigure_interface_type", unconfigure_interface_type
)
configure_interface_subinterface_vlan_double_tagged = _track(
    "configure_interface_subinterface_vlan_double_tagged",
    configure_interface_subinterface_vlan_double_tagged,
)
unconfigure_interface_subinterface_vlan_double_tagged = _track(
    "unconfigure_interface_subinterface_vlan_double_tagged",
    unconfigure_interface_subinterface_vlan_double_tagged,
)
configure_interface_subinterface_vlan_ingress_mapping = _track(
    "configure_interface_subinterface_vlan_ingress_mapping",
    configure_interface_subinterface_vlan_ingress_mapping,
)
unconfigure_interface_subinterface_vlan_ingress_mapping = _track(
    "unconfigure_interface_subinterface_vlan_ingress_mapping",
    unconfigure_interface_subinterface_vlan_ingress_mapping,
)
configure_interface_subinterface_vlan_egress_mapping = _track(
    "configure_interface_subinterface_vlan_egress_mapping",
    configure_interface_subinterface_vlan_egress_mapping,
)
unconfigure_interface_subinterface_vlan_egress_mapping = _track(
    "unconfigure_interface_subinterface_vlan_egress_mapping",
    unconfigure_interface_subinterface_vlan_egress_mapping,
)
configure_interface_qos_service_policy = _track(
    "configure_interface_qos_service_policy", configure_interface_qos_service_policy
)
unconfigure_interface_qos_service_policy = _track(
    "unconfigure_interface_qos_service_policy",
    unconfigure_interface_qos_service_policy,
)
configure_interface_acl_binding = _track(
    "configure_interface_acl_binding", configure_interface_acl_binding
)
unconfigure_interface_acl_binding = _track(
    "unconfigure_interface_acl_binding", unconfigure_interface_acl_binding
)
configure_interface_priority_vlan = _track(
    "configure_interface_priority_vlan", configure_interface_priority_vlan
)
unconfigure_interface_priority_vlan = _track(
    "unconfigure_interface_priority_vlan", unconfigure_interface_priority_vlan
)
configure_interface_subinterface_ipv4_enabled = _track(
    "configure_interface_subinterface_ipv4_enabled",
    configure_interface_subinterface_ipv4_enabled,
)
configure_interface_subinterface_ipv6_enabled = _track(
    "configure_interface_subinterface_ipv6_enabled",
    configure_interface_subinterface_ipv6_enabled,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)
        self.is_connected = Mock(return_value=True)

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


class TestShutUnshutInterface(unittest.TestCase):
    """shut_interface, unshut_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_shut_interface(self):
        shut_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("enabled false", c)

    def test_unshut_interface(self):
        unshut_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("enabled true", c)


class TestUnconfigureInterface(unittest.TestCase):
    """Every unconfigure_* helper: assert the no-form CLI it emits."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_unconfigure_mtu(self):
        unconfigure_interface_mtu(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("no mtu", c)

    def test_unconfigure_description(self):
        unconfigure_interface_description(self.d, "swp1")
        self.assertIn("no description", self.d.cfg())

    def test_unconfigure_port_speed(self):
        unconfigure_interface_port_speed(self.d, "swp1")
        self.assertIn("no ethernet port-speed", self.d.cfg())

    def test_unconfigure_aggregate_id(self):
        unconfigure_interface_aggregate_id(self.d, "swp1")
        self.assertIn("no ethernet aggregate-id", self.d.cfg())

    def test_unconfigure_lag(self):
        unconfigure_interface_lag(self.d, "bond1")
        c = self.d.cfg()
        self.assertIn("no aggregation lag-type", c)
        self.assertIn("no aggregation min-links", c)

    def test_unconfigure_subinterface_ipv4(self):
        unconfigure_interface_subinterface_ipv4(self.d, "swp1", 1, "10.0.0.1")
        c = self.d.cfg()
        self.assertIn("subinterface 1", c)
        self.assertIn("no ipv4 address 10.0.0.1", c)

    def test_unconfigure_subinterface_ipv6(self):
        unconfigure_interface_subinterface_ipv6(self.d, "swp1", 1, "2001:db8::1")
        self.assertIn("no ipv6 address 2001:db8::1", self.d.cfg())

    def test_unconfigure_subinterface_vlan(self):
        unconfigure_interface_subinterface_vlan(self.d, "swp1", 1)
        c = self.d.cfg()
        self.assertIn("subinterface 1", c)
        self.assertIn("no vlan", c)

    def test_unconfigure_debounce(self):
        unconfigure_interface_debounce(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("no debounce-interval up", c)
        self.assertIn("no debounce-interval down", c)

    def test_unconfigure_bfd_micro(self):
        unconfigure_interface_bfd_micro(self.d, "swp1")
        self.assertIn("no bfd micro", self.d.cfg())

    def test_unconfigure_type(self):
        unconfigure_interface_type(self.d, "loopback0")
        self.assertIn("no type", self.d.cfg())

    def test_unconfigure_vlan_double_tagged(self):
        unconfigure_interface_subinterface_vlan_double_tagged(self.d, "swp1", 1)
        self.assertIn("no vlan match double-tagged", self.d.cfg())

    def test_unconfigure_vlan_ingress_mapping(self):
        unconfigure_interface_subinterface_vlan_ingress_mapping(self.d, "swp1", 1)
        self.assertIn("no vlan ingress-mapping", self.d.cfg())

    def test_unconfigure_vlan_egress_mapping(self):
        unconfigure_interface_subinterface_vlan_egress_mapping(self.d, "swp1", 1)
        self.assertIn("no vlan egress-mapping", self.d.cfg())

    def test_unconfigure_qos_service_policy(self):
        unconfigure_interface_qos_service_policy(self.d, "swp1", "input")
        self.assertIn("no qos service-policy input", self.d.cfg())

    def test_unconfigure_acl_binding(self):
        unconfigure_interface_acl_binding(self.d, "swp1")
        self.assertIn("no acl-service-policies ingress-acl-sets", self.d.cfg())

    def test_unconfigure_priority_vlan(self):
        unconfigure_interface_priority_vlan(self.d, "swp1", sub_id=1)
        c = self.d.cfg()
        self.assertIn("subinterface 1", c)
        self.assertIn("no priority-vlan", c)


class TestInterfaceFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of shut/unshut and every
    unconfigure_* helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_shut_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            shut_interface(self.d, "swp1")

    def test_unshut_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            unshut_interface(self.d, "swp1")

    def test_unconfigure_mtu_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_mtu(self.d, "swp1")

    def test_unconfigure_description_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_description(self.d, "swp1")

    def test_unconfigure_port_speed_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_port_speed(self.d, "swp1")

    def test_unconfigure_aggregate_id_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_aggregate_id(self.d, "swp1")

    def test_unconfigure_lag_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_lag(self.d, "bond1")

    def test_unconfigure_subinterface_ipv4_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_subinterface_ipv4(self.d, "swp1", 1, "10.0.0.1")

    def test_unconfigure_subinterface_ipv6_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_subinterface_ipv6(self.d, "swp1", 1, "2001:db8::1")

    def test_unconfigure_subinterface_vlan_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_subinterface_vlan(self.d, "swp1", 1)

    def test_unconfigure_debounce_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_debounce(self.d, "swp1")

    def test_unconfigure_bfd_micro_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_bfd_micro(self.d, "swp1")

    def test_unconfigure_type_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_type(self.d, "loopback0")

    def test_unconfigure_vlan_double_tagged_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_subinterface_vlan_double_tagged(self.d, "swp1", 1)

    def test_unconfigure_vlan_ingress_mapping_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_subinterface_vlan_ingress_mapping(self.d, "swp1", 1)

    def test_unconfigure_vlan_egress_mapping_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_subinterface_vlan_egress_mapping(self.d, "swp1", 1)

    def test_unconfigure_qos_service_policy_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_qos_service_policy(self.d, "swp1", "input")

    def test_unconfigure_acl_binding_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_acl_binding(self.d, "swp1")

    def test_unconfigure_priority_vlan_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_interface_priority_vlan(self.d, "swp1")


class TestConfigureInterfaceCoverage(unittest.TestCase):
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in configure.py
        must have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(configure_module, inspect.isfunction)
            if obj.__module__ == configure_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in interface/configure.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
