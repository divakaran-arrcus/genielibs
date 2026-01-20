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

    def test_iteration2_ecmp_dual_nexthop(self):
        """
        Iteration 2: Test ECMP with 2 next-hops.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 203.0.113.0/24
               description "ECMP route with 2 next-hops"
               next-hop-index 1
                next-hop 192.168.1.1
                interface swp1
               next-hop-index 2
                next-hop 192.168.1.2
                interface swp2
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['203.0.113.0/24']
        route_attr.description = 'ECMP route with 2 next-hops'

        # First next-hop
        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.1.1'
        nh1.interface = 'swp1'

        # Second next-hop
        nh2 = route_attr.next_hop_attr['2']
        nh2.next_hop_index = '2'
        nh2.nexthop = '192.168.1.2'
        nh2.interface = 'swp2'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 203.0.113.0/24', output)
        self.assertIn('next-hop-index 1', output)
        self.assertIn('next-hop 192.168.1.1', output)
        self.assertIn('interface swp1', output)
        self.assertIn('next-hop-index 2', output)
        self.assertIn('next-hop 192.168.1.2', output)
        self.assertIn('interface swp2', output)

        print("\n=== Iteration 2: ECMP with 2 Next-Hops ===")
        print(output)

    def test_iteration2_ecmp_quad_nexthop(self):
        """
        Iteration 2: Test ECMP with 4 next-hops.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 198.51.100.0/24
               description "ECMP route with 4 next-hops"
               next-hop-index 1
                next-hop 10.1.1.1
                interface swp1
               next-hop-index 2
                next-hop 10.1.1.2
                interface swp2
               next-hop-index 3
                next-hop 10.1.1.3
                interface swp3
               next-hop-index 4
                next-hop 10.1.1.4
                interface swp4
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['198.51.100.0/24']
        route_attr.description = 'ECMP route with 4 next-hops'

        # Configure 4 next-hops
        for i in range(1, 5):
            nh = route_attr.next_hop_attr[str(i)]
            nh.next_hop_index = str(i)
            nh.nexthop = f'10.1.1.{i}'
            nh.interface = f'swp{i}'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 198.51.100.0/24', output)
        
        # Verify all 4 next-hops
        for i in range(1, 5):
            self.assertIn(f'next-hop-index {i}', output)
            self.assertIn(f'next-hop 10.1.1.{i}', output)
            self.assertIn(f'interface swp{i}', output)

        print("\n=== Iteration 2: ECMP with 4 Next-Hops ===")
        print(output)

    def test_iteration2_ecmp_with_preference(self):
        """
        Iteration 2: Test ECMP with preference and multiple next-hops.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 172.31.0.0/16
               description "ECMP with admin distance"
               preference 50
               next-hop-index 1
                next-hop 10.20.1.1
               next-hop-index 2
                next-hop 10.20.1.2
               next-hop-index 3
                next-hop 10.20.1.3
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['172.31.0.0/16']
        route_attr.description = 'ECMP with admin distance'
        route_attr.preference = 50

        # Configure 3 next-hops (no interface, just IP)
        for i in range(1, 4):
            nh = route_attr.next_hop_attr[str(i)]
            nh.next_hop_index = str(i)
            nh.nexthop = f'10.20.1.{i}'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 172.31.0.0/16', output)
        self.assertIn('preference 50', output)
        
        # Verify all 3 next-hops
        for i in range(1, 4):
            self.assertIn(f'next-hop-index {i}', output)
            self.assertIn(f'next-hop 10.20.1.{i}', output)

        print("\n=== Iteration 2: ECMP with Preference ===")
        print(output)

    def test_iteration3_ipv6_basic(self):
        """
        Iteration 3: Test basic IPv6 static route.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 2001:db8:100::/48
               description "IPv6 test route"
               next-hop-index 1
                next-hop 2001:db8::1
                interface swp1
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv6']

        route_attr = af_attr.route_attr['2001:db8:100::/48']
        route_attr.description = 'IPv6 test route'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '2001:db8::1'
        nh1.interface = 'swp1'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 2001:db8:100::/48', output)
        self.assertIn('next-hop 2001:db8::1', output)
        self.assertIn('interface swp1', output)

        print("\n=== Iteration 3: IPv6 Basic Route ===")
        print(output)

    def test_iteration3_ipv6_ecmp(self):
        """
        Iteration 3: Test IPv6 ECMP with multiple next-hops.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 2001:db8:200::/48
               description "IPv6 ECMP route"
               next-hop-index 1
                next-hop 2001:db8::10
               next-hop-index 2
                next-hop 2001:db8::20
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv6']

        route_attr = af_attr.route_attr['2001:db8:200::/48']
        route_attr.description = 'IPv6 ECMP route'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '2001:db8::10'

        nh2 = route_attr.next_hop_attr['2']
        nh2.next_hop_index = '2'
        nh2.nexthop = '2001:db8::20'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 2001:db8:200::/48', output)
        self.assertIn('next-hop 2001:db8::10', output)
        self.assertIn('next-hop 2001:db8::20', output)

        print("\n=== Iteration 3: IPv6 ECMP ===")
        print(output)

    def test_iteration3_drop_nexthop(self):
        """
        Iteration 3: Test DROP next-hop (blackhole route).
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 192.0.2.0/24
               description "Blackhole route"
               next-hop-index 1
                next-hop DROP
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['192.0.2.0/24']
        route_attr.description = 'Blackhole route'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = 'DROP'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 192.0.2.0/24', output)
        self.assertIn('next-hop DROP', output)

        print("\n=== Iteration 3: DROP Next-Hop ===")
        print(output)

    def test_iteration4_mpls_local_label(self):
        """
        Iteration 4: Test MPLS with local-label-index.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 10.1.1.0/24
               description "MPLS labeled route"
               local-label-index 100
               next-hop-index 1
                next-hop 192.168.10.1
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.1.1.0/24']
        route_attr.description = 'MPLS labeled route'
        route_attr.local_label_index = 100

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.10.1'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 10.1.1.0/24', output)
        self.assertIn('local-label-index 100', output)
        self.assertIn('next-hop 192.168.10.1', output)

        print("\n=== Iteration 4: MPLS Local Label ===")
        print(output)

    def test_iteration4_mpls_remote_label_stack(self):
        """
        Iteration 4: Test MPLS with remote-label-stack.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 10.2.2.0/24
               description "MPLS with label stack"
               next-hop-index 1
                next-hop 192.168.20.1
                interface swp1
                remote-label-stack [ 16001 16002 16003 ]
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.2.2.0/24']
        route_attr.description = 'MPLS with label stack'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.20.1'
        nh1.interface = 'swp1'
        nh1.remote_label_stack = [16001, 16002, 16003]

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 10.2.2.0/24', output)
        self.assertIn('next-hop 192.168.20.1', output)
        self.assertIn('interface swp1', output)
        self.assertIn('remote-label-stack [ 16001 16002 16003 ]', output)

        print("\n=== Iteration 4: MPLS Remote Label Stack ===")
        print(output)

    def test_iteration4_mpls_implicit_null(self):
        """
        Iteration 4: Test MPLS with IMPLICIT-NULL label.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 10.3.3.0/24
               description "MPLS implicit null"
               next-hop-index 1
                next-hop 192.168.30.1
                remote-label-stack IMPLICIT-NULL
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.3.3.0/24']
        route_attr.description = 'MPLS implicit null'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.30.1'
        nh1.remote_label_stack = 'IMPLICIT-NULL'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 10.3.3.0/24', output)
        self.assertIn('remote-label-stack IMPLICIT-NULL', output)

        print("\n=== Iteration 4: MPLS Implicit Null ===")
        print(output)

    def test_iteration5_bfd_profile_route_level(self):
        """
        Iteration 5: Test BFD profile at route level.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 10.4.4.0/24
               description "Route with BFD profile"
               bfd profile bfd-profile-1
               next-hop-index 1
                next-hop 192.168.40.1
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.4.4.0/24']
        route_attr.description = 'Route with BFD profile'
        route_attr.bfd_profile = 'bfd-profile-1'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.40.1'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 10.4.4.0/24', output)
        self.assertIn('bfd profile bfd-profile-1', output)
        self.assertIn('next-hop 192.168.40.1', output)

        print("\n=== Iteration 5: BFD Profile (Route Level) ===")
        print(output)

    def test_iteration5_bfd_destination_ipv4(self):
        """
        Iteration 5: Test BFD with IPv4 destination address at next-hop level.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 10.5.5.0/24
               description "BFD with IPv4 destination"
               next-hop-index 1
                next-hop 192.168.50.1
                bfd destination-address ipv4 192.168.50.100
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.5.5.0/24']
        route_attr.description = 'BFD with IPv4 destination'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.50.1'
        nh1.bfd_destination_address = '192.168.50.100'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 10.5.5.0/24', output)
        self.assertIn('next-hop 192.168.50.1', output)
        self.assertIn('bfd destination-address ipv4 192.168.50.100', output)

        print("\n=== Iteration 5: BFD IPv4 Destination ===")
        print(output)

    def test_iteration5_bfd_destination_ipv6(self):
        """
        Iteration 5: Test BFD with IPv6 destination address.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 2001:db8:300::/48
               description "BFD with IPv6 destination"
               next-hop-index 1
                next-hop 2001:db8::50
                bfd destination-address ipv6 2001:db8::100
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv6']

        route_attr = af_attr.route_attr['2001:db8:300::/48']
        route_attr.description = 'BFD with IPv6 destination'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '2001:db8::50'
        nh1.bfd_destination_address = '2001:db8::100'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 2001:db8:300::/48', output)
        self.assertIn('next-hop 2001:db8::50', output)
        self.assertIn('bfd destination-address ipv6 2001:db8::100', output)

        print("\n=== Iteration 5: BFD IPv6 Destination ===")
        print(output)

    def test_iteration6_vrf_leaking(self):
        """
        Iteration 6: Test VRF leaking with next-network-instance.
        
        Expected CLI:
            network-instance vrfA
             protocol STATIC default
              static-route 10.6.6.0/24
               description "VRF leaking to vrfB"
               next-hop-index 1
                next-hop 192.168.60.1
                next-network-instance vrfB
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['vrfA']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.6.6.0/24']
        route_attr.description = 'VRF leaking to vrfB'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.60.1'
        nh1.next_network_instance = 'vrfB'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('network-instance vrfA', output)
        self.assertIn('static-route 10.6.6.0/24', output)
        self.assertIn('next-hop 192.168.60.1', output)
        self.assertIn('next-network-instance vrfB', output)

        print("\n=== Iteration 6: VRF Leaking ===")
        print(output)

    def test_iteration6_linklocal_ipv6(self):
        """
        Iteration 6: Test link-local IPv6 route.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 2001:db8:400::/48
               description "Link-local IPv6 route"
               next-hop-index 1
                next-hop fe80::1
                interface swp1
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv6']

        route_attr = af_attr.route_attr['2001:db8:400::/48']
        route_attr.description = 'Link-local IPv6 route'

        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = 'fe80::1'
        nh1.interface = 'swp1'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        self.assertIn('static-route 2001:db8:400::/48', output)
        self.assertIn('next-hop fe80::1', output)
        self.assertIn('interface swp1', output)

        print("\n=== Iteration 6: Link-Local IPv6 ===")
        print(output)

    def test_iteration6_comprehensive(self):
        """
        Iteration 6: Comprehensive test with multiple advanced features.
        
        Expected CLI:
            network-instance default
             protocol STATIC default
              static-route 10.99.0.0/16
               description "Comprehensive route with multiple features"
               preference 100
               set-tag 999
               local-label-index 200
               bfd profile comprehensive-bfd
               next-hop-index 1
                next-hop 192.168.99.1
                interface swp10
                metric 50
                remote-label-stack 17001 17002
                bfd destination-address ipv4 192.168.99.100
               next-hop-index 2
                next-hop 192.168.99.2
                next-network-instance vrfB
        """
        static_routing = StaticRouting(testbed=self.testbed)
        device_attr = static_routing.device_attr[self.device]
        vrf_attr = device_attr.vrf_attr['default']
        af_attr = vrf_attr.address_family_attr['ipv4']

        route_attr = af_attr.route_attr['10.99.0.0/16']
        route_attr.description = 'Comprehensive route with multiple features'
        route_attr.preference = 100
        route_attr.tag = 999
        route_attr.local_label_index = 200
        route_attr.bfd_profile = 'comprehensive-bfd'

        # Next-hop 1: Full features
        nh1 = route_attr.next_hop_attr['1']
        nh1.next_hop_index = '1'
        nh1.nexthop = '192.168.99.1'
        nh1.interface = 'swp10'
        nh1.metric = 50
        nh1.remote_label_stack = [17001, 17002]
        nh1.bfd_destination_address = '192.168.99.100'

        # Next-hop 2: VRF leaking
        nh2 = route_attr.next_hop_attr['2']
        nh2.next_hop_index = '2'
        nh2.nexthop = '192.168.99.2'
        nh2.next_network_instance = 'vrfB'

        cfg = static_routing.build_config(apply=False, devices=[self.device])
        output = str(cfg[self.device.name])

        # Verify route-level attributes
        self.assertIn('static-route 10.99.0.0/16', output)
        self.assertIn('preference 100', output)
        self.assertIn('set-tag 999', output)
        self.assertIn('local-label-index 200', output)
        self.assertIn('bfd profile comprehensive-bfd', output)

        # Verify next-hop 1
        self.assertIn('next-hop-index 1', output)
        self.assertIn('next-hop 192.168.99.1', output)
        self.assertIn('interface swp10', output)
        self.assertIn('metric 50', output)
        self.assertIn('remote-label-stack [ 17001 17002 ]', output)
        self.assertIn('bfd destination-address ipv4 192.168.99.100', output)

        # Verify next-hop 2
        self.assertIn('next-hop-index 2', output)
        self.assertIn('next-hop 192.168.99.2', output)
        self.assertIn('next-network-instance vrfB', output)

        print("\n=== Iteration 6: Comprehensive Test ===")
        print(output)


if __name__ == '__main__':
    unittest.main()
