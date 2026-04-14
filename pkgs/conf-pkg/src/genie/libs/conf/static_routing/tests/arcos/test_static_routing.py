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


if __name__ == '__main__':
    import unittest
    unittest.main()
