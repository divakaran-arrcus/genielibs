#!/usr/bin/env python3
"""Unit tests for ArcOS StaticRouting conf object.

Tests exercise RouteAttributes and NextHopAttributes build_config(apply=False)
through the full Genie hierarchy and verify the generated CLI strings.
"""

from unittest import TestCase
from unittest.mock import Mock

from genie.conf.base import Testbed, Device
from genie.libs.conf.static_routing import StaticRouting


class _ArcosStaticRoutingBase(TestCase):
    """Common setUp for all static routing conf tests."""

    def setUp(self):
        self.testbed = Testbed()
        self.device = Device(testbed=self.testbed, name='R1', os='arcos')
        self.device.custom.setdefault('abstraction', {})['order'] = ['arcos']

    # ---- helpers ----
    def _build(self, static_routing):
        """Build config (apply=False) and return the CLI string for self.device."""
        cfgs = static_routing.build_config(apply=False, devices=[self.device])
        self.assertIn(self.device.name, cfgs)
        return str(cfgs[self.device.name])

    def _make_route(self, prefix, vrf='default', af='ipv4'):
        """Create a StaticRouting object and return (sr, route_attr)."""
        sr = StaticRouting(testbed=self.testbed)
        da = sr.device_attr[self.device]
        vrf_attr = da.vrf_attr[vrf]
        af_attr = vrf_attr.address_family_attr[af]
        route_attr = af_attr.route_attr[prefix]
        return sr, route_attr


class TestRouteBasic(_ArcosStaticRoutingBase):
    """Test 1: route prefix + description + preference."""

    def test_route_basic(self):
        sr, route = self._make_route('10.0.0.0/8')
        route.description = 'test route'
        route.preference = 10

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'

        output = self._build(sr)

        self.assertIn('network-instance default', output)
        self.assertIn('protocol STATIC default', output)
        self.assertIn('static-route 10.0.0.0/8', output)
        self.assertIn('description "test route"', output)
        self.assertIn('preference 10', output)
        self.assertIn('next-hop-index 1', output)
        self.assertIn('next-hop 10.1.1.1', output)


class TestRouteWithTag(_ArcosStaticRoutingBase):
    """Test 2: route with tag."""

    def test_route_with_tag(self):
        sr, route = self._make_route('172.16.0.0/16')
        route.tag = 500

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'

        output = self._build(sr)

        self.assertIn('static-route 172.16.0.0/16', output)
        self.assertIn('set-tag 500', output)


class TestRouteWithBfd(_ArcosStaticRoutingBase):
    """Test 3: route with bfd_profile."""

    def test_route_with_bfd(self):
        sr, route = self._make_route('10.20.0.0/16')
        route.bfd_profile = 'bfd-static-1'

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'

        output = self._build(sr)

        self.assertIn('static-route 10.20.0.0/16', output)
        self.assertIn('bfd profile bfd-static-1', output)


class TestRouteWithMplsLabel(_ArcosStaticRoutingBase):
    """Test 4: route with local_label_index."""

    def test_route_with_mpls_label(self):
        sr, route = self._make_route('10.30.0.0/16')
        route.local_label_index = 42

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'

        output = self._build(sr)

        self.assertIn('static-route 10.30.0.0/16', output)
        self.assertIn('local-label-index 42', output)


class TestNextHopBasic(_ArcosStaticRoutingBase):
    """Test 5: next-hop with IP address and interface."""

    def test_nexthop_basic(self):
        sr, route = self._make_route('192.168.100.0/24')

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'
        nh.interface = 'swp1'

        output = self._build(sr)

        self.assertIn('next-hop-index 1', output)
        self.assertIn('next-hop 10.1.1.1', output)
        self.assertIn('interface swp1', output)


class TestNextHopDrop(_ArcosStaticRoutingBase):
    """Test 6: next-hop DROP (blackhole)."""

    def test_nexthop_drop(self):
        sr, route = self._make_route('192.0.2.0/24')
        route.description = 'Blackhole'

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = 'DROP'

        output = self._build(sr)

        self.assertIn('static-route 192.0.2.0/24', output)
        self.assertIn('next-hop DROP', output)
        # DROP should not produce an interface line
        self.assertNotIn('interface', output)


class TestNextHopMplsLabels(_ArcosStaticRoutingBase):
    """Test 7: next-hop with remote_label_stack list."""

    def test_nexthop_mpls_labels(self):
        sr, route = self._make_route('10.50.0.0/16')

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'
        nh.interface = 'swp1'
        nh.remote_label_stack = [16001, 16002, 16003]

        output = self._build(sr)

        self.assertIn('next-hop 10.1.1.1', output)
        self.assertIn('remote-label-stack [ 16001 16002 16003 ]', output)


class TestNextHopBfdDestination(_ArcosStaticRoutingBase):
    """Test 8: next-hop with bfd_destination_address (IPv4)."""

    def test_nexthop_bfd_destination(self):
        sr, route = self._make_route('10.60.0.0/16')

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'
        nh.bfd_destination_address = '10.1.1.100'

        output = self._build(sr)

        self.assertIn('next-hop 10.1.1.1', output)
        self.assertIn('bfd destination-address ipv4 10.1.1.100', output)
        # Must be ipv4 flavour, not ipv6
        self.assertNotIn('ipv6', output)


class TestNextHopVrfLeaking(_ArcosStaticRoutingBase):
    """Test 9: next-hop with next_network_instance (VRF leaking)."""

    def test_nexthop_vrf_leaking(self):
        sr, route = self._make_route('10.70.0.0/16', vrf='vrfA')

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '192.168.1.1'
        nh.next_network_instance = 'vrfB'

        output = self._build(sr)

        self.assertIn('network-instance vrfA', output)
        self.assertIn('next-hop 192.168.1.1', output)
        self.assertIn('next-network-instance vrfB', output)


class TestNextHopMetric(_ArcosStaticRoutingBase):
    """Test 10: next-hop metric line."""

    def test_nexthop_metric(self):
        sr, route = self._make_route('10.80.0.0/16')

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'
        nh.metric = 50

        output = self._build(sr)

        self.assertIn('next-hop 10.1.1.1', output)
        self.assertIn('metric 50', output)


class TestNextHopMplsImplicitNull(_ArcosStaticRoutingBase):
    """Test 11: next-hop remote_label_stack as the 'IMPLICIT-NULL' string
    (as opposed to a list of label ints)."""

    def test_nexthop_mpls_implicit_null(self):
        sr, route = self._make_route('10.81.0.0/16')

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '10.1.1.1'
        nh.remote_label_stack = 'IMPLICIT-NULL'

        output = self._build(sr)

        self.assertIn('remote-label-stack IMPLICIT-NULL', output)
        self.assertNotIn('[ IMPLICIT-NULL ]', output)


class TestNextHopBfdDestinationIpv6(_ArcosStaticRoutingBase):
    """Test 12: next-hop with bfd_destination_address (IPv6)."""

    def test_nexthop_bfd_destination_ipv6(self):
        sr, route = self._make_route('2001:db8:10::/64')

        nh = route.next_hop_attr['1']
        nh.next_hop_index = '1'
        nh.nexthop = '2001:db8::1'
        nh.bfd_destination_address = '2001:db8::100'

        output = self._build(sr)

        self.assertIn('bfd destination-address ipv6 2001:db8::100', output)


class TestRouteEcmpMultipleNextHops(_ArcosStaticRoutingBase):
    """Test 13: ECMP -- a single route with multiple next_hop_attr entries.

    Ported from the legacy arcos/tests suite (test_iteration2_ecmp_*): every
    other test in this file builds a route with exactly one next-hop, so
    none of them exercise iterating over more than one entry in
    ``route.next_hop_attr``. This confirms multiple next-hops under the same
    route each render their own next-hop-index/next-hop/interface lines
    without clobbering one another.
    """

    def test_ecmp_dual_nexthop(self):
        sr, route = self._make_route('203.0.113.0/24')
        route.description = 'ECMP route with 2 next-hops'

        nh1 = route.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.1.1'
        nh1.interface = 'swp1'

        nh2 = route.next_hop_attr['2']
        nh2.next_hop_index = '2'
        nh2.nexthop = '192.168.1.2'
        nh2.interface = 'swp2'

        output = self._build(sr)

        self.assertIn('static-route 203.0.113.0/24', output)
        self.assertIn('next-hop-index 1', output)
        self.assertIn('next-hop 192.168.1.1', output)
        self.assertIn('interface swp1', output)
        self.assertIn('next-hop-index 2', output)
        self.assertIn('next-hop 192.168.1.2', output)
        self.assertIn('interface swp2', output)

    def test_ecmp_quad_nexthop_with_preference(self):
        sr, route = self._make_route('172.31.0.0/16')
        route.description = 'ECMP with admin distance'
        route.preference = 50

        for i in range(1, 5):
            nh = route.next_hop_attr[str(i)]
            nh.next_hop_index = str(i)
            nh.nexthop = f'10.20.1.{i}'

        output = self._build(sr)

        self.assertIn('static-route 172.31.0.0/16', output)
        self.assertIn('preference 50', output)
        for i in range(1, 5):
            self.assertIn(f'next-hop-index {i}', output)
            self.assertIn(f'next-hop 10.20.1.{i}', output)


# ---------------------------------------------------------------------------
# DIRECT dispatch tests: instantiate the arcOS-specific nested ABC classes
# directly (bypassing the Genie abstraction/attribute-mixing machinery), the
# same way pkgs/conf-pkg/.../lag/tests/arcos/test_lag.py does for Lag. This
# reaches branches the full-hierarchy tests above cannot:
#   - apply=True -> device.configure(..., fail_invalid=True) at every level
#   - build_unconfig() direct delegation at every level
#   - the "no route prefix" early-return guard in RouteAttributes
#   - the next_hop_index '1' default fallback (next_hop_index and nexthop
#     both falsy)
#   - the plain (non-managedattribute) `self.__dict__.get('nexthop')`
#     fallback branch (hit only when 'nexthop' was never wrapped by the
#     generic base class's managedattribute descriptor, i.e. exactly the
#     bare-instantiation scenario used here)
# ---------------------------------------------------------------------------

from genie.libs.conf.static_routing.arcos.static_routing import (
    StaticRouting as ArcosStaticRouting,
)


def _make_route_direct(prefix=None, **attrs):
    route = ArcosStaticRouting.DeviceAttributes.VrfAttributes.AddressFamilyAttributes.RouteAttributes()
    route.route = prefix
    for key, value in attrs.items():
        setattr(route, key, value)
    return route


def _make_nexthop_direct(**attrs):
    nh = ArcosStaticRouting.DeviceAttributes.VrfAttributes.AddressFamilyAttributes.RouteAttributes.NextHopAttributes()
    for key, value in attrs.items():
        setattr(nh, key, value)
    return nh


class TestRouteAttributesDirect(TestCase):
    """Direct instantiation of RouteAttributes (bypassing device_attr /
    vrf_attr / address_family_attr / route_attr dict indexing)."""

    def setUp(self):
        self.device = Mock()
        self.device.name = 'R1'

    def test_no_prefix_returns_empty_config(self):
        """`self.route` falsy -> early return with nothing emitted."""
        route = _make_route_direct(prefix=None)
        route.device = self.device

        result = route.build_config(apply=False)

        self.assertEqual(str(result.cli_config), '')

    def test_empty_prefix_string_returns_empty_config(self):
        route = _make_route_direct(prefix='')
        route.device = self.device

        result = route.build_config(apply=False)

        self.assertEqual(str(result.cli_config), '')

    def test_apply_true_calls_device_configure(self):
        route = _make_route_direct(prefix='10.0.0.0/8', preference=5)
        route.device = self.device

        result = route.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn('static-route 10.0.0.0/8', args[0])
        self.assertTrue(kwargs.get('fail_invalid'))

    def test_build_unconfig_direct(self):
        route = _make_route_direct(prefix='10.0.0.0/8', description='desc')
        route.device = self.device

        result = route.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn('static-route 10.0.0.0/8', output)
        self.assertIn('no description', output)


class TestNextHopAttributesDirect(TestCase):
    """Direct instantiation of NextHopAttributes."""

    def setUp(self):
        self.device = Mock()
        self.device.name = 'R1'

    def test_next_hop_index_defaults_to_1(self):
        """Neither next_hop_index nor nexthop set (nexthop explicitly
        falsy) -> falls back to the literal '1'."""
        nh = _make_nexthop_direct(interface='swp1')
        nh.device = self.device
        nh.nexthop = None  # explicit falsy value avoids AttributeError

        result = nh.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn('next-hop-index 1', output)

    def test_next_hop_index_falls_back_to_nexthop_key(self):
        nh = _make_nexthop_direct(interface='swp1')
        nh.device = self.device
        nh.nexthop = '10.2.2.2'  # no next_hop_index set -> used as index too

        result = nh.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn('next-hop-index 10.2.2.2', output)

    def test_bare_nexthop_dict_fallback_drop(self):
        """`nexthop` assigned as a plain (non-managedattribute) instance
        attribute -> exercises `self.__dict__.get('nexthop')` fallback."""
        nh = _make_nexthop_direct(next_hop_index='5')
        nh.device = self.device
        nh.nexthop = 'DROP'

        result = nh.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn('next-hop-index 5', output)
        self.assertIn('next-hop DROP', output)

    def test_apply_true_calls_device_configure(self):
        nh = _make_nexthop_direct(next_hop_index='1', interface='swp1')
        nh.device = self.device
        nh.nexthop = '10.1.1.1'

        result = nh.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn('next-hop-index 1', args[0])
        self.assertTrue(kwargs.get('fail_invalid'))

    def test_build_unconfig_direct(self):
        nh = _make_nexthop_direct(next_hop_index='1', interface='swp1')
        nh.device = self.device
        nh.nexthop = '10.1.1.1'

        result = nh.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn('next-hop-index 1', output)
        self.assertIn('no interface swp1', output)


class TestVrfAttributesDirect(TestCase):
    """Direct instantiation of VrfAttributes, manually wiring the
    address_family_attr mapping (mirrors Lag's bond_attr dict pattern)."""

    def setUp(self):
        self.device = Mock()
        self.device.name = 'R1'

    def _make_vrf(self, vrf_name, routes_by_af):
        vrf_attr = ArcosStaticRouting.DeviceAttributes.VrfAttributes()
        vrf_attr.device = self.device
        vrf_attr.vrf = vrf_name

        af_attr_map = {}
        for af, routes in routes_by_af.items():
            af_attr = ArcosStaticRouting.DeviceAttributes.VrfAttributes.AddressFamilyAttributes()
            af_attr.device = self.device
            af_attr.route_attr = routes
            af_attr_map[af] = af_attr
        vrf_attr.address_family_attr = af_attr_map
        return vrf_attr

    def test_apply_true_calls_device_configure(self):
        route = _make_route_direct(prefix='10.0.0.0/8')
        route.device = self.device
        vrf_attr = self._make_vrf('default', {'ipv4': {'10.0.0.0/8': route}})

        result = vrf_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn('network-instance default', args[0])
        self.assertTrue(kwargs.get('fail_invalid'))

    def test_build_unconfig_direct(self):
        route = _make_route_direct(prefix='10.0.0.0/8', description='desc')
        route.device = self.device
        vrf_attr = self._make_vrf('vrfA', {'ipv4': {'10.0.0.0/8': route}})

        result = vrf_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn('network-instance vrfA', output)
        self.assertIn('no description', output)


class TestDeviceAttributesDirect(TestCase):
    """Direct instantiation of DeviceAttributes, manually wiring the
    vrf_attr mapping."""

    def setUp(self):
        self.device = Mock()
        self.device.name = 'R1'

    def _make_device_attr(self, vrfs):
        dev_attr = ArcosStaticRouting.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.vrf_attr = vrfs
        return dev_attr

    def _make_vrf_with_route(self, vrf_name, prefix):
        vrf_attr = ArcosStaticRouting.DeviceAttributes.VrfAttributes()
        vrf_attr.device = self.device
        vrf_attr.vrf = vrf_name

        route = _make_route_direct(prefix=prefix, description='desc')
        route.device = self.device

        af_attr = ArcosStaticRouting.DeviceAttributes.VrfAttributes.AddressFamilyAttributes()
        af_attr.device = self.device
        af_attr.route_attr = {prefix: route}

        vrf_attr.address_family_attr = {'ipv4': af_attr}
        return vrf_attr

    def test_apply_true_calls_device_configure(self):
        vrf_attr = self._make_vrf_with_route('default', '10.0.0.0/8')
        dev_attr = self._make_device_attr({'default': vrf_attr})

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn('static-route 10.0.0.0/8', args[0])
        self.assertTrue(kwargs.get('fail_invalid'))

    def test_build_config_empty_vrf_attr(self):
        dev_attr = self._make_device_attr({})

        result = dev_attr.build_config(apply=False)

        self.assertEqual(str(result.cli_config), '')

    def test_build_unconfig_direct(self):
        vrf_attr = self._make_vrf_with_route('default', '10.0.0.0/8')
        dev_attr = self._make_device_attr({'default': vrf_attr})

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn('static-route 10.0.0.0/8', output)


if __name__ == '__main__':
    import unittest
    unittest.main()
