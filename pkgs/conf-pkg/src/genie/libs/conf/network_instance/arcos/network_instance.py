#!/usr/bin/env python3
"""
Native ArcOS Network Instance configuration plugin for Genie.

Covers L3VRF (rib-options, table-connections, interface binding),
L2VLAN (type, vlan, EVI, FDB, interface binding), L2P2P_EVPN (VPWS),
and management/simple instances (interface binding only).
"""

import logging

from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class NetworkInstance:
    """ArcOS-specific Network Instance implementation for Genie (native plugin)."""

    class DeviceAttributes:
        """Device-level Network Instance attributes for ArcOS.

        Usage:
            dev_attr = NetworkInstance.DeviceAttributes()
            dev_attr.device = device
            dev_attr.network_instance_attr = {}

            ni = NetworkInstance.DeviceAttributes.NetworkInstanceAttributes()
            ni.ni_name = "Scale-L3VPN-1"
            ni.rib_ipv4_max_prefix_limit = 1000
            dev_attr.network_instance_attr["Scale-L3VPN-1"] = ni

            dev_attr.build_config(apply=True)
        """

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build Network Instance configuration for an ArcOS device.

            Iterates over all NetworkInstanceAttributes stored in
            self.network_instance_attr (dict keyed by NI name).

            When ``apply=True``, FDB configuration is applied in a
            separate commit because ArcOS requires the NI to exist
            as L2VLAN before FDB commands are accepted.
            """
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            configurations = CliConfigBuilder(unconfig=unconfig)
            fdb_configurations = CliConfigBuilder(unconfig=unconfig)

            ni_attr_map = getattr(self, 'network_instance_attr', {}) or {}

            for ni_name in sorted(ni_attr_map):
                ni_obj = ni_attr_map[ni_name]
                ni_config = ni_obj.build_config(
                    apply=False,
                    unconfig=unconfig,
                )
                if ni_config:
                    configurations.append_block(ni_config)

                # Collect FDB config separately for second commit
                if not unconfig and ni_obj._has_fdb_config():
                    fdb_cfg = CliConfigBuilder()
                    with fdb_cfg.submode_context(
                        f'network-instance {ni_name}'
                    ):
                        ni_obj._build_fdb_config(fdb_cfg)
                    fdb_cfg.append_line('!')
                    fdb_configurations.append_block(str(fdb_cfg))

            if apply:
                if configurations:
                    self.device.configure(str(configurations))
                # Second commit for FDB (requires NI to exist)
                if fdb_configurations:
                    self.device.configure(str(fdb_configurations))
            else:
                # For dry-run, merge everything into one output
                if fdb_configurations:
                    configurations.append_block(str(fdb_configurations))
                return CliConfig(
                    device=getattr(self, 'device', None),
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build unconfiguration commands."""
            return self.build_config(
                apply=apply, attributes=attributes, unconfig=True, **kwargs
            )

        class NetworkInstanceAttributes:
            """Per-network-instance attributes.

            Attributes:
                ni_name (str): Network instance name (set externally).
                ni_type (str): "L2VLAN", "L3VRF", "L2P2P_EVPN", or None.
                vlan (int): VLAN number (L2VLAN only).
                description (str): Network instance description.
                interfaces (list): List of interface names to bind.
                rib_ipv4_max_prefix_limit (int): IPv4 RIB max prefix limit.
                rib_ipv4_threshold (int): IPv4 RIB threshold percentage.
                rib_ipv6_max_prefix_limit (int): IPv6 RIB max prefix limit.
                rib_ipv6_threshold (int): IPv6 RIB threshold percentage.
                table_connections (list): List of dicts, each with keys:
                    src_proto, dst_proto, af, src_dst_instance, import_policy.
                advertise_mac_routes (bool): Advertise MAC routes (L2VLAN).
                evi_id (int): EVPN Instance ID.
                evi_arp_nd_suppression (bool): ARP/ND suppression in EVI.
                evi_advertise_irb_mac_ip (bool): Advertise IRB MAC-IP in EVI.
                evi_control_word (bool): Enable control-word in EVI.
                evi_flow_label (bool): Enable flow-label in EVI.
                fdb_maximum_entries (int): FDB max entries limit.
                fdb_packet_action (str): FDB packet action (e.g., FLOOD_ACTION).
                fdb_mac_learning (bool): Enable FDB MAC learning.
                vpws_interfaces (dict): VPWS service-id mapping per interface.
                    Key: interface name, value: dict with 'local' and 'remote'.
            """

            def __init__(self):
                self.ni_name = None
                self.ni_type = None
                self.vlan = None
                self.description = None
                self.interfaces = None
                self.rib_ipv4_max_prefix_limit = None
                self.rib_ipv4_threshold = None
                self.rib_ipv6_max_prefix_limit = None
                self.rib_ipv6_threshold = None
                self.table_connections = None
                # EVPN / L2VLAN attributes
                self.advertise_mac_routes = None
                self.evi_id = None
                self.evi_arp_nd_suppression = None
                self.evi_advertise_irb_mac_ip = None
                self.evi_control_word = None
                self.evi_flow_label = None
                # FDB attributes
                self.fdb_maximum_entries = None
                self.fdb_packet_action = None
                self.fdb_mac_learning = None
                # VPWS attributes (L2P2P_EVPN)
                self.vpws_interfaces = None

            def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                """Build configuration for a single network instance.

                For L2VLAN, the referenced VLAN object must be created
                before the NI can reference it.

                FDB configuration requires the NI to already exist as
                L2VLAN (committed), so FDB lines are emitted in a
                separate block after the main NI config.
                """
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                configurations = CliConfigBuilder(unconfig=unconfig)

                ni_name = str(self.ni_name)

                if unconfig:
                    configurations.append_line(f'network-instance {ni_name}')
                else:
                    # For L2VLAN: create the VLAN object first
                    if self.vlan is not None:
                        with configurations.submode_context(
                            f'vlan {self.vlan}'
                        ):
                            configurations.append_line(
                                f'vlan-id {self.vlan}'
                            )
                        configurations.append_line('!')

                    # Main NI config (type, vlan, evi, interfaces, etc.)
                    with configurations.submode_context(
                        f'network-instance {ni_name}'
                    ):
                        self._build_ni_config(configurations)
                    configurations.append_line('!')

                    # Note: FDB config is handled separately by
                    # DeviceAttributes.build_config() in a second commit,
                    # because ArcOS requires the NI to exist as L2VLAN
                    # before FDB commands are accepted.

                return CliConfig(
                    device=getattr(self, 'device', None),
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def _build_ni_config(self, configurations):
                """Build the body of a network-instance stanza."""

                # Type (L2VLAN, L3VRF, L2P2P_EVPN)
                if self.ni_type:
                    configurations.append_line(f'type {self.ni_type}')

                # Description
                if self.description:
                    configurations.append_line(f'description "{self.description}"')

                # VLAN (L2VLAN)
                if self.vlan is not None:
                    configurations.append_line(f'vlan {self.vlan}')

                # Advertise MAC routes (L2VLAN)
                if self.advertise_mac_routes is not None:
                    adv_str = 'true' if self.advertise_mac_routes else 'false'
                    configurations.append_line(
                        f'advertise-mac-routes {adv_str}'
                    )

                # EVI (EVPN Instance)
                if self.evi_id is not None:
                    has_evi_attrs = any([
                        self.evi_arp_nd_suppression is not None,
                        self.evi_advertise_irb_mac_ip is not None,
                        self.evi_control_word is not None,
                        self.evi_flow_label is not None,
                    ])

                    if has_evi_attrs:
                        with configurations.submode_context(
                            f'evi {self.evi_id}'
                        ):
                            if self.evi_arp_nd_suppression is not None:
                                arp_str = (
                                    'true'
                                    if self.evi_arp_nd_suppression
                                    else 'false'
                                )
                                configurations.append_line(
                                    f'arp-nd-suppression {arp_str}'
                                )
                            if self.evi_advertise_irb_mac_ip is not None:
                                irb_str = (
                                    'true'
                                    if self.evi_advertise_irb_mac_ip
                                    else 'false'
                                )
                                configurations.append_line(
                                    f'advertise-irb-mac-ip {irb_str}'
                                )
                            if self.evi_control_word is not None:
                                cw_str = (
                                    'true'
                                    if self.evi_control_word
                                    else 'false'
                                )
                                configurations.append_line(
                                    f'control-word {cw_str}'
                                )
                            if self.evi_flow_label is not None:
                                fl_str = (
                                    'true'
                                    if self.evi_flow_label
                                    else 'false'
                                )
                                configurations.append_line(
                                    f'flow-label {fl_str}'
                                )
                        configurations.append_line('!')
                    else:
                        configurations.append_line(f'evi {self.evi_id}')
                        configurations.append_line('!')

                # RIB options — IPv4
                if self.rib_ipv4_max_prefix_limit is not None:
                    configurations.append_line(
                        f'rib-options ipv4 max-prefix-limit '
                        f'{self.rib_ipv4_max_prefix_limit}'
                    )

                if self.rib_ipv4_threshold is not None:
                    configurations.append_line(
                        f'rib-options ipv4 threshold {self.rib_ipv4_threshold}'
                    )

                # RIB options — IPv6
                if self.rib_ipv6_max_prefix_limit is not None:
                    configurations.append_line(
                        f'rib-options ipv6 max-prefix-limit '
                        f'{self.rib_ipv6_max_prefix_limit}'
                    )

                if self.rib_ipv6_threshold is not None:
                    configurations.append_line(
                        f'rib-options ipv6 threshold {self.rib_ipv6_threshold}'
                    )

                # Table connections
                if self.table_connections:
                    for tc in self.table_connections:
                        src_proto = tc.get('src_proto', '')
                        dst_proto = tc.get('dst_proto', '')
                        af = tc.get('af', '')
                        src_dst_instance = tc.get('src_dst_instance')
                        import_policy = tc.get('import_policy')

                        with configurations.submode_context(
                            f'table-connection {src_proto} {dst_proto} {af}'
                        ):
                            if src_dst_instance:
                                configurations.append_line(
                                    f'src-dst-instance {src_dst_instance}'
                                )
                            if import_policy:
                                configurations.append_line(
                                    f'import-policy [ {import_policy} ]'
                                )
                        configurations.append_line('!')

                # Interface bindings (with optional VPWS service-id)
                vpws = self.vpws_interfaces or {}

                if self.interfaces:
                    for intf_name in self.interfaces:
                        vpws_cfg = vpws.get(intf_name)
                        if vpws_cfg:
                            with configurations.submode_context(
                                f'interface {intf_name}'
                            ):
                                local_id = vpws_cfg.get('local')
                                remote_id = vpws_cfg.get('remote')
                                if local_id is not None:
                                    configurations.append_line(
                                        f'vpws-service-id local {local_id}'
                                    )
                                if remote_id is not None:
                                    configurations.append_line(
                                        f'vpws-service-id remote {remote_id}'
                                    )
                            configurations.append_line('!')
                        else:
                            configurations.append_line(f'interface {intf_name}')
                            configurations.append_line('!')

            def _has_fdb_config(self):
                """Check if any FDB attributes are set."""
                return any([
                    self.fdb_maximum_entries is not None,
                    self.fdb_packet_action is not None,
                    self.fdb_mac_learning is not None,
                ])

            def _build_fdb_config(self, configurations):
                """Build FDB configuration lines."""
                if self.fdb_maximum_entries is not None:
                    configurations.append_line(
                        f'fdb maximum-entries {self.fdb_maximum_entries}'
                    )

                if self.fdb_packet_action is not None:
                    configurations.append_line(
                        f'fdb packet-action {self.fdb_packet_action}'
                    )

                if self.fdb_mac_learning is not None:
                    learn_str = 'true' if self.fdb_mac_learning else 'false'
                    configurations.append_line(
                        f'fdb mac-learning {learn_str}'
                    )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build unconfiguration commands."""
                return self.build_config(
                    apply=apply, attributes=attributes, unconfig=True, **kwargs
                )
