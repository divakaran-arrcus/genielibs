#!/usr/bin/env python3
"""
Unit tests for ArcOS BGP configuration object.
"""

import unittest
from unittest.mock import Mock

from genie.libs.conf.bgp.arcos.bgp import Bgp


class TestBgpDeviceAttributes(unittest.TestCase):
    """Tests for Bgp.DeviceAttributes build_config()."""

    def _make_da(self, instance_name='default', pid='default'):
        """Helper to create a DeviceAttributes instance with mocked device."""
        dev = Mock()
        dev.custom = {'instance_name': instance_name}

        da = Bgp.DeviceAttributes()
        da.device = dev
        da.pid = pid
        return da

    def test_global_scalars(self):
        """Test global AS, router-id, adj-rib-out-post, label-alloc, ignore-igp."""
        da = self._make_da()
        da.as_number = 65002
        da.router_id = '1.0.0.0'
        da.adj_rib_out_post = True
        da.label_allocation_mode = 'INSTANCE_LABEL'
        da.ignore_next_hop_igp_metric = True

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('global as 65002', output)
        self.assertIn('global router-id 1.0.0.0', output)
        self.assertIn('global adj-rib-out-post true', output)
        self.assertIn('global label-allocation-mode INSTANCE_LABEL', output)
        self.assertIn(
            'global route-selection-options ignore-next-hop-igp-metric true',
            output,
        )

    def test_global_afi_safi_ipv4_unicast(self):
        """Test global AFI-SAFI IPV4_UNICAST with networks and aggregates."""
        da = self._make_da()
        da.as_number = 65002
        da.global_afi_safis = {
            'IPV4_UNICAST': {
                'ibgp_maximum_paths': 8,
                'add_paths_calculate': 'MULTIPATHS',
                'networks': ['144.144.144.144/32', '10.0.0.0/8'],
                'aggregate_addresses': {
                    '201.0.0.0/8': {'summary_only': True},
                },
            },
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('global afi-safi IPV4_UNICAST', output)
        self.assertIn('use-maximum-paths ibgp maximum-paths 8', output)
        self.assertIn('add-paths calculate MULTIPATHS', output)
        self.assertIn('network 144.144.144.144/32', output)
        self.assertIn('network 10.0.0.0/8', output)
        self.assertIn('aggregate-address 201.0.0.0/8', output)
        self.assertIn('summary-only true', output)

    def test_global_afi_safi_bare(self):
        """Test bare AFI-SAFI (e.g., RTFILTER with no sub-attrs)."""
        da = self._make_da()
        da.as_number = 65002
        da.global_afi_safis = {
            'RTFILTER': {},
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('global afi-safi RTFILTER', output)

    def test_global_afi_safi_rtfilter_enabled(self):
        """Test RTFILTER with rtfilter_enabled attribute."""
        da = self._make_da()
        da.as_number = 65002
        da.global_afi_safis = {
            'RTFILTER': {
                'rtfilter_enabled': True,
            },
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('rtfilter enabled true', output)

    def test_neighbor_full(self):
        """Test neighbor with all attributes."""
        da = self._make_da()
        da.as_number = 65002
        da.neighbors = {
            '3.0.0.0': {
                'peer_as': 65002,
                'description': 'Enable only to bypass RR',
                'shutdown': True,
                'transport_local_address': '1.0.0.0',
                'bfd_enable': False,
                'afi_safis': {
                    'IPV4_UNICAST': {
                        'add_paths_receive': True,
                    },
                },
            },
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('neighbor 3.0.0.0', output)
        self.assertIn('peer-as 65002', output)
        self.assertIn('description "Enable only to bypass RR"', output)
        self.assertIn('shutdown true', output)
        self.assertIn('transport local-address 1.0.0.0', output)
        self.assertIn('bfd enable false', output)
        self.assertIn('afi-safi IPV4_UNICAST', output)
        self.assertIn('add-paths receive true', output)

    def test_neighbor_with_peer_group(self):
        """Test neighbor referencing a peer-group."""
        da = self._make_da()
        da.as_number = 65002
        da.neighbors = {
            '4.0.0.0': {
                'peer_group': 'RR-Peer-Group',
            },
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('neighbor 4.0.0.0', output)
        self.assertIn('peer-group RR-Peer-Group', output)

    def test_peer_group_full(self):
        """Test peer-group with all attributes."""
        da = self._make_da()
        da.as_number = 65002
        da.peer_groups = {
            'RR-Peer-Group': {
                'peer_as': 65002,
                'shutdown': False,
                'transport_local_address': '1.0.0.0',
                'bfd_enable': True,
                'bfd_profile': 'GLOBAL-200m',
                'afi_safis': {
                    'IPV4_UNICAST': {
                        'add_paths_receive': True,
                    },
                },
            },
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('peer-group RR-Peer-Group', output)
        self.assertIn('peer-as 65002', output)
        self.assertIn('shutdown false', output)
        self.assertIn('transport local-address 1.0.0.0', output)
        self.assertIn('bfd enable true', output)
        self.assertIn('bfd profile GLOBAL-200m', output)
        self.assertIn('afi-safi IPV4_UNICAST', output)
        self.assertIn('add-paths receive true', output)

    def test_unconfig(self):
        """Test unconfiguration removes entire BGP protocol."""
        da = self._make_da()
        da.as_number = 65002

        cfg = da.build_unconfig(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('network-instance default protocol BGP default', output)
        # Should NOT contain submode config lines
        self.assertNotIn('global as', output)

    def test_network_instance_custom(self):
        """Test custom network instance name."""
        da = self._make_da(instance_name='vrf-A')
        da.as_number = 100

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('network-instance vrf-A', output)

    def test_production_sample(self):
        """Full production sample matching the plan's expected CLI output."""
        da = self._make_da()
        da.as_number = 65002
        da.router_id = '1.0.0.0'
        da.adj_rib_out_post = True
        da.label_allocation_mode = 'INSTANCE_LABEL'
        da.ignore_next_hop_igp_metric = True

        da.global_afi_safis = {
            'IPV4_UNICAST': {
                'ibgp_maximum_paths': 8,
                'add_paths_calculate': 'MULTIPATHS',
                'networks': ['144.144.144.144/32'],
                'aggregate_addresses': {
                    '201.0.0.0/8': {'summary_only': True},
                },
            },
            'RTFILTER': {},
        }

        da.neighbors = {
            '3.0.0.0': {
                'peer_as': 65002,
                'description': 'Enable only to bypass RR',
                'shutdown': True,
                'transport_local_address': '1.0.0.0',
                'bfd_enable': False,
                'afi_safis': {
                    'IPV4_UNICAST': {
                        'add_paths_receive': True,
                    },
                },
            },
            '4.0.0.0': {
                'peer_group': 'RR-Peer-Group',
            },
        }

        da.peer_groups = {
            'RR-Peer-Group': {
                'peer_as': 65002,
                'shutdown': False,
                'transport_local_address': '1.0.0.0',
                'bfd_enable': True,
                'bfd_profile': 'GLOBAL-200m',
                'afi_safis': {
                    'IPV4_UNICAST': {
                        'add_paths_receive': True,
                    },
                },
            },
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        # Verify ordering: global scalars → AFI-SAFI → neighbors → peer-groups
        as_pos = output.index('global as 65002')
        afi_pos = output.index('global afi-safi IPV4_UNICAST')
        nbr_pos = output.index('neighbor 3.0.0.0')
        pg_pos = output.index('peer-group RR-Peer-Group')

        self.assertLess(as_pos, afi_pos)
        self.assertLess(afi_pos, nbr_pos)
        self.assertLess(nbr_pos, pg_pos)

        # Verify key lines present
        self.assertIn('global router-id 1.0.0.0', output)
        self.assertIn('use-maximum-paths ibgp maximum-paths 8', output)
        self.assertIn('network 144.144.144.144/32', output)
        self.assertIn('aggregate-address 201.0.0.0/8', output)
        self.assertIn('summary-only true', output)
        self.assertIn('global afi-safi RTFILTER', output)
        self.assertIn('description "Enable only to bypass RR"', output)
        self.assertIn('bfd profile GLOBAL-200m', output)

    def test_apply_true_calls_configure(self):
        """Test that apply=True calls device.configure()."""
        da = self._make_da()
        da.as_number = 65002

        da.build_config(apply=True)

        da.device.configure.assert_called_once()
        call_arg = da.device.configure.call_args[0][0]
        self.assertIn('global as 65002', call_arg)

    def test_empty_config(self):
        """Test that config with no attributes still produces valid structure."""
        da = self._make_da()

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('network-instance default', output)
        self.assertIn('protocol BGP default', output)

    def test_neighbor_afi_safi_with_policies(self):
        """Test neighbor AFI-SAFI with import/export policies."""
        da = self._make_da()
        da.as_number = 65002
        da.neighbors = {
            '10.0.0.1': {
                'peer_as': 65003,
                'afi_safis': {
                    'L2VPN_EVPN': {
                        'import_policy': ['ACCEPT-ALL'],
                        'export_policy': 'REJECT-ALL',
                        'add_paths_send': True,
                    },
                },
            },
        }

        cfg = da.build_config(apply=False)
        output = str(cfg.cli_config)

        self.assertIn('afi-safi L2VPN_EVPN', output)
        self.assertIn('import-policy [ ACCEPT-ALL ]', output)
        self.assertIn('export-policy [ REJECT-ALL ]', output)
        self.assertIn('add-paths send true', output)


if __name__ == '__main__':
    unittest.main()
