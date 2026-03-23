#!/usr/bin/env python3
"""
Native ArcOS BGP configuration plugin for Genie.

This implementation generates ArcOS BGP CLI under the standard
Genie conf BGP abstraction, following the same patterns as the
ISIS conf object (gold standard).
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class Bgp(ABC):
    """ArcOS-specific BGP implementation for Genie (native plugin)."""

    class DeviceAttributes(ABC):
        """Device-level BGP attributes for ArcOS."""

        # ========================================
        # GLOBAL SCALARS
        # ========================================

        as_number = managedattribute(
            name='as_number',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='BGP autonomous system number (e.g., 65002)')

        router_id = managedattribute(
            name='router_id',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='BGP router-id (e.g., "1.0.0.0")')

        adj_rib_out_post = managedattribute(
            name='adj_rib_out_post',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable adj-rib-out-post (stores post-policy adj-RIB-out)')

        label_allocation_mode = managedattribute(
            name='label_allocation_mode',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Label allocation mode (e.g., "INSTANCE_LABEL")')

        ignore_next_hop_igp_metric = managedattribute(
            name='ignore_next_hop_igp_metric',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Ignore next-hop IGP metric in route selection')

        # ========================================
        # GLOBAL AFI-SAFI (dict keyed by AFI name)
        # ========================================

        global_afi_safis = managedattribute(
            name='global_afi_safis',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Dict of global AFI-SAFI configs keyed by AFI name string '
                '(e.g., "IPV4_UNICAST"). Each value is a dict with optional keys: '
                'ibgp_maximum_paths (int), add_paths_calculate (str), '
                'networks (list of str), aggregate_addresses (dict), '
                'rtfilter_enabled (bool), null_label (str)')

        # ========================================
        # NEIGHBORS (dict keyed by neighbor address)
        # ========================================

        neighbors = managedattribute(
            name='neighbors',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Dict of neighbor configs keyed by neighbor address string. '
                'Each value is a dict with optional keys: '
                'peer_as (int), peer_group (str), description (str), '
                'shutdown (bool), transport_local_address (str), '
                'bfd_enable (bool), bfd_profile (str), '
                'afi_safis (dict keyed by AFI name)')

        # ========================================
        # PEER GROUPS (dict keyed by peer-group name)
        # ========================================

        peer_groups = managedattribute(
            name='peer_groups',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Dict of peer-group configs keyed by peer-group name. '
                'Each value is a dict with optional keys: '
                'peer_as (int), shutdown (bool), '
                'transport_local_address (str), bfd_enable (bool), '
                'bfd_profile (str), afi_safis (dict keyed by AFI name)')

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build BGP configuration for an ArcOS device.

            This follows the ArcOS OpenConfig-like hierarchy:

                network-instance <instance_name>
                 protocol BGP <pid>
                  ... global, afi-safi, neighbor, peer-group config ...
            """
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Get network instance name (usually 'default')
            instance_name = getattr(
                self.device, 'custom', {}
            ).get('instance_name', 'default')

            # Get protocol instance name (BGP process name, usually 'default')
            pid = attributes.value('pid') or 'default'

            if unconfig:
                configurations.append_line(
                    f'network-instance {instance_name} protocol BGP {pid}'
                )
            else:
                with configurations.submode_context(
                    f'network-instance {instance_name}'
                ):
                    with configurations.submode_context(f'protocol BGP {pid}'):

                        # ========================================
                        # GLOBAL SCALARS
                        # ========================================

                        as_number = attributes.value('as_number')
                        if as_number is not None:
                            configurations.append_line(f'global as {as_number}')

                        router_id = attributes.value('router_id')
                        if router_id is not None:
                            configurations.append_line(
                                f'global router-id {router_id}'
                            )

                        adj_rib_out_post = attributes.value('adj_rib_out_post')
                        if adj_rib_out_post is not None:
                            val = 'true' if adj_rib_out_post else 'false'
                            configurations.append_line(
                                f'global adj-rib-out-post {val}'
                            )

                        label_alloc = attributes.value('label_allocation_mode')
                        if label_alloc is not None:
                            configurations.append_line(
                                f'global label-allocation-mode {label_alloc}'
                            )

                        ignore_igp = attributes.value(
                            'ignore_next_hop_igp_metric'
                        )
                        if ignore_igp is not None:
                            val = 'true' if ignore_igp else 'false'
                            configurations.append_line(
                                'global route-selection-options '
                                f'ignore-next-hop-igp-metric {val}'
                            )

                        # ========================================
                        # GLOBAL AFI-SAFI BLOCKS
                        # ========================================

                        global_afis = attributes.value('global_afi_safis')
                        if global_afis and isinstance(global_afis, dict):
                            for afi_name in sorted(global_afis.keys()):
                                afi_attrs = global_afis[afi_name]
                                self._build_global_afi_safi(
                                    configurations, afi_name, afi_attrs
                                )

                        # ========================================
                        # NEIGHBOR BLOCKS
                        # ========================================

                        nbrs = attributes.value('neighbors')
                        if nbrs and isinstance(nbrs, dict):
                            for nbr_addr in sorted(nbrs.keys()):
                                nbr_attrs = nbrs[nbr_addr]
                                self._build_neighbor(
                                    configurations, nbr_addr, nbr_attrs
                                )

                        # ========================================
                        # PEER-GROUP BLOCKS
                        # ========================================

                        pgs = attributes.value('peer_groups')
                        if pgs and isinstance(pgs, dict):
                            for pg_name in sorted(pgs.keys()):
                                pg_attrs = pgs[pg_name]
                                self._build_peer_group(
                                    configurations, pg_name, pg_attrs
                                )

                    # End protocol BGP
                    configurations.append_line('!')
                # End network-instance
                configurations.append_line('!')

            if apply:
                if configurations:
                    self.device.configure(str(configurations))
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build unconfiguration commands."""
            return self.build_config(
                apply=apply, attributes=attributes, unconfig=True, **kwargs
            )

        # ========================================
        # PRIVATE HELPERS
        # ========================================

        def _build_global_afi_safi(self, configurations, afi_name, afi_attrs):
            """Build a global afi-safi block.

            Args:
                configurations: CliConfigBuilder instance
                afi_name: AFI-SAFI name string (e.g., "IPV4_UNICAST")
                afi_attrs: dict of AFI attributes (or None for bare AFI)
            """
            if not afi_attrs or not isinstance(afi_attrs, dict):
                # Bare AFI-SAFI with no sub-attributes
                configurations.append_line(f'global afi-safi {afi_name}')
                configurations.append_line('!')
                return

            has_content = False
            for key in ('ibgp_maximum_paths', 'add_paths_calculate',
                        'networks', 'aggregate_addresses', 'rtfilter_enabled',
                        'null_label'):
                if afi_attrs.get(key) is not None:
                    has_content = True
                    break

            if not has_content:
                configurations.append_line(f'global afi-safi {afi_name}')
                configurations.append_line('!')
                return

            with configurations.submode_context(
                f'global afi-safi {afi_name}'
            ):
                null_label = afi_attrs.get('null_label')
                if null_label is not None:
                    configurations.append_line(
                        f'null-label {null_label}'
                    )

                ibgp_max = afi_attrs.get('ibgp_maximum_paths')
                if ibgp_max is not None:
                    configurations.append_line(
                        f'use-maximum-paths ibgp maximum-paths {ibgp_max}'
                    )

                add_paths_calc = afi_attrs.get('add_paths_calculate')
                if add_paths_calc is not None:
                    configurations.append_line(
                        f'add-paths calculate {add_paths_calc}'
                    )

                networks = afi_attrs.get('networks')
                if networks:
                    for prefix in networks:
                        configurations.append_line(f'network {prefix}')

                aggregates = afi_attrs.get('aggregate_addresses')
                if aggregates and isinstance(aggregates, dict):
                    for agg_prefix in sorted(aggregates.keys()):
                        agg_attrs = aggregates[agg_prefix]
                        if agg_attrs and isinstance(agg_attrs, dict):
                            has_agg_content = False
                            for k in ('summary_only',):
                                if agg_attrs.get(k) is not None:
                                    has_agg_content = True
                                    break

                            if has_agg_content:
                                with configurations.submode_context(
                                    f'aggregate-address {agg_prefix}'
                                ):
                                    summary_only = agg_attrs.get('summary_only')
                                    if summary_only is not None:
                                        val = (
                                            'true' if summary_only else 'false'
                                        )
                                        configurations.append_line(
                                            f'summary-only {val}'
                                        )
                                configurations.append_line('!')
                            else:
                                configurations.append_line(
                                    f'aggregate-address {agg_prefix}'
                                )
                        else:
                            configurations.append_line(
                                f'aggregate-address {agg_prefix}'
                            )

                rtfilter = afi_attrs.get('rtfilter_enabled')
                if rtfilter is not None:
                    val = 'true' if rtfilter else 'false'
                    configurations.append_line(f'rtfilter enabled {val}')

            configurations.append_line('!')

        def _build_neighbor(self, configurations, nbr_addr, nbr_attrs):
            """Build a neighbor block.

            Args:
                configurations: CliConfigBuilder instance
                nbr_addr: Neighbor address string
                nbr_attrs: dict of neighbor attributes
            """
            if not nbr_attrs or not isinstance(nbr_attrs, dict):
                configurations.append_line(f'neighbor {nbr_addr}')
                configurations.append_line('!')
                return

            with configurations.submode_context(f'neighbor {nbr_addr}'):
                peer_as = nbr_attrs.get('peer_as')
                if peer_as is not None:
                    configurations.append_line(f'peer-as {peer_as}')

                peer_group = nbr_attrs.get('peer_group')
                if peer_group is not None:
                    configurations.append_line(f'peer-group {peer_group}')

                description = nbr_attrs.get('description')
                if description is not None:
                    configurations.append_line(
                        f'description "{description}"'
                    )

                shutdown = nbr_attrs.get('shutdown')
                if shutdown is not None:
                    val = 'true' if shutdown else 'false'
                    configurations.append_line(f'shutdown {val}')

                transport_addr = nbr_attrs.get('transport_local_address')
                if transport_addr is not None:
                    configurations.append_line(
                        f'transport local-address {transport_addr}'
                    )

                bfd_enable = nbr_attrs.get('bfd_enable')
                if bfd_enable is not None:
                    val = 'true' if bfd_enable else 'false'
                    configurations.append_line(f'bfd enable {val}')

                bfd_profile = nbr_attrs.get('bfd_profile')
                if bfd_profile is not None:
                    configurations.append_line(f'bfd profile {bfd_profile}')

                # Per-neighbor AFI-SAFI blocks
                afi_safis = nbr_attrs.get('afi_safis')
                if afi_safis and isinstance(afi_safis, dict):
                    for afi_name in sorted(afi_safis.keys()):
                        afi_cfg = afi_safis[afi_name]
                        self._build_entity_afi_safi(
                            configurations, afi_name, afi_cfg
                        )

            configurations.append_line('!')

        def _build_peer_group(self, configurations, pg_name, pg_attrs):
            """Build a peer-group block.

            Args:
                configurations: CliConfigBuilder instance
                pg_name: Peer-group name string
                pg_attrs: dict of peer-group attributes
            """
            if not pg_attrs or not isinstance(pg_attrs, dict):
                configurations.append_line(f'peer-group {pg_name}')
                configurations.append_line('!')
                return

            with configurations.submode_context(f'peer-group {pg_name}'):
                peer_as = pg_attrs.get('peer_as')
                if peer_as is not None:
                    configurations.append_line(f'peer-as {peer_as}')

                shutdown = pg_attrs.get('shutdown')
                if shutdown is not None:
                    val = 'true' if shutdown else 'false'
                    configurations.append_line(f'shutdown {val}')

                transport_addr = pg_attrs.get('transport_local_address')
                if transport_addr is not None:
                    configurations.append_line(
                        f'transport local-address {transport_addr}'
                    )

                bfd_enable = pg_attrs.get('bfd_enable')
                if bfd_enable is not None:
                    val = 'true' if bfd_enable else 'false'
                    configurations.append_line(f'bfd enable {val}')

                bfd_profile = pg_attrs.get('bfd_profile')
                if bfd_profile is not None:
                    configurations.append_line(f'bfd profile {bfd_profile}')

                # Per-peer-group AFI-SAFI blocks
                afi_safis = pg_attrs.get('afi_safis')
                if afi_safis and isinstance(afi_safis, dict):
                    for afi_name in sorted(afi_safis.keys()):
                        afi_cfg = afi_safis[afi_name]
                        self._build_entity_afi_safi(
                            configurations, afi_name, afi_cfg
                        )

            configurations.append_line('!')

        def _build_entity_afi_safi(self, configurations, afi_name, afi_cfg):
            """Build an afi-safi block for a neighbor or peer-group.

            Handles per-entity AFI-SAFI attributes:
                add_paths_send, add_paths_receive, import_policy, export_policy

            Args:
                configurations: CliConfigBuilder instance
                afi_name: AFI-SAFI name string
                afi_cfg: dict of per-entity AFI attributes (or None for bare)
            """
            if not afi_cfg or not isinstance(afi_cfg, dict):
                configurations.append_line(f'afi-safi {afi_name}')
                configurations.append_line('!')
                return

            has_content = False
            for key in ('add_paths_send', 'add_paths_receive',
                        'import_policy', 'export_policy'):
                if afi_cfg.get(key) is not None:
                    has_content = True
                    break

            if not has_content:
                configurations.append_line(f'afi-safi {afi_name}')
                configurations.append_line('!')
                return

            with configurations.submode_context(f'afi-safi {afi_name}'):
                add_send = afi_cfg.get('add_paths_send')
                if add_send is not None:
                    # String values like "BACKUP", "ALL" are passed through;
                    # bool True/False becomes "true"/"false"
                    if isinstance(add_send, bool):
                        val = 'true' if add_send else 'false'
                    else:
                        val = str(add_send)
                    configurations.append_line(f'add-paths send {val}')

                add_recv = afi_cfg.get('add_paths_receive')
                if add_recv is not None:
                    val = 'true' if add_recv else 'false'
                    configurations.append_line(f'add-paths receive {val}')

                import_pol = afi_cfg.get('import_policy')
                if import_pol is not None:
                    if isinstance(import_pol, (list, tuple)):
                        pol_str = ' '.join(str(p) for p in import_pol)
                        configurations.append_line(
                            f'apply-policy import-policy [ {pol_str} ]'
                        )
                    else:
                        configurations.append_line(
                            f'apply-policy import-policy [ {import_pol} ]'
                        )

                export_pol = afi_cfg.get('export_policy')
                if export_pol is not None:
                    if isinstance(export_pol, (list, tuple)):
                        pol_str = ' '.join(str(p) for p in export_pol)
                        configurations.append_line(
                            f'apply-policy export-policy [ {pol_str} ]'
                        )
                    else:
                        configurations.append_line(
                            f'apply-policy export-policy [ {export_pol} ]'
                        )

            configurations.append_line('!')
