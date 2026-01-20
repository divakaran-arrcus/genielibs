#!/usr/bin/env python3
"""
Unit tests for ARCOS Static Routing configuration.

Tests follow incremental development approach:
- Iteration 1: Basic static route
- Iteration 2: ECMP (multiple next-hops)
- Iteration 3: IPv6 and DROP
- Iteration 4: MPLS labels
- Iteration 5: BFD integration
- Iteration 6: VRF leaking and link-local IPv6
"""

import unittest

from genie.conf.base import Testbed, Device
from genie.libs.conf.static_routing import StaticRouting


class TestArcosStaticRoutingConfig(unittest.TestCase):
    """Test suite for ARCOS Static Routing configuration."""

    def setUp(self):
        """Set up test fixtures."""
        # Create testbed
        self.testbed = Testbed()
        self.device = Device(testbed=self.testbed, name='R1', os='arcos')
        self.device.custom.setdefault('abstraction', {})['order'] = ['arcos']

    def test_iteration1_basic_static_route(self):
        """
        Iteration 1: Test basic static route with single next-hop.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 192.168.100.0/24
               description "Basic static route test"
               next-hop-index 1
                next-hop 10.9.201.1
                interface swp1
        """
        # Create static routing instance
        static_routing = StaticRouting(testbed=self.testbed)

        # Configure device attributes
        device_attr = static_routing.device_attr[self.device]

        # Configure VRF (default)
        vrf_attr = device_attr.vrf_attr['default']

        # Configure address family (ipv4)
        af_attr = vrf_attr.address_family_attr['ipv4']

        # Configure route
        route_attr = af_attr.route_attr['192.168.100.0/24']
        route_attr.description = 'Basic static route test'

        # Configure next-hop
        nh_attr = route_attr.next_hop_attr['1']
        nh_attr.next_hop_index = '1'
        nh_attr.nexthop = '10.9.201.1'
        nh_attr.interface = 'swp1'

        # Build configuration
        cfg = static_routing.build_config(apply=False, devices=[self.device])
        self.assertIn(self.device.name, cfg)

        output = str(cfg[self.device.name])

        # Verify CLI output
        self.assertIn('network-instance default', output)
        self.assertIn('protocol STATIC default', output)
        self.assertIn('static-route 192.168.100.0/24', output)
        self.assertIn('description "Basic static route test"', output)
        self.assertIn('next-hop-index 1', output)
        self.assertIn('next-hop 10.9.201.1', output)
        self.assertIn('interface swp1', output)

        # Verify structure and indentation
        lines = output.strip().split('\n')
        self.assertTrue(any('network-instance default' in line for line in lines))
        self.assertTrue(any('protocol STATIC default' in line for line in lines))
        self.assertTrue(any('static-route 192.168.100.0/24' in line for line in lines))

        print("\n=== Iteration 1: Basic Static Route ===")
        print(output)

    def test_iteration1_with_preference_and_tag(self):
        """
        Iteration 1: Test basic static route with preference and tag.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 10.0.0.0/8
               description "Route with admin distance"
               preference 10
               tag 100
               next-hop-index 1
                next-hop 192.168.1.1
                interface swp2
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.0.0.0/8']
        route_attr.description = 'Route with admin distance'
        route_attr.preference = 10
        route_attr.tag = 100

        nh_attr = route_attr.next_hop_attr['1']
        nh_attr.next_hop_index = '1'
        nh_attr.nexthop = '192.168.1.1'
        nh_attr.interface = 'swp2'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('preference 10', output)
        self.assertIn('set-tag 100', output)
        self.assertIn('description "Route with admin distance"', output)

        print("\n=== Iteration 1: With Preference and Tag ===")
        print(output)

    def test_iteration1_different_vrf(self):
        """
        Iteration 1: Test static route in non-default VRF.
        
        Expected CLI:
            network-instance vrfA
             protocol STATIC default
              static-route 172.16.0.0/16
               next-hop-index 1
                next-hop 192.168.10.1
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['vrfA']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['172.16.0.0/16']

        nh_attr = route_attr.next_hop_attr['1']
        nh_attr.next_hop_index = '1'
        nh_attr.nexthop = '192.168.10.1'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('network-instance vrfA', output)
        self.assertIn('static-route 172.16.0.0/16', output)

        print("\n=== Iteration 1: Different VRF ===")
        print(output)


if __name__ == '__main__':
    unittest.main()
