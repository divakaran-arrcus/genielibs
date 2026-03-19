#!/usr/bin/env python3
"""
Native ArcOS Network Instance configuration plugin for Genie.

Covers L3VRF (rib-options, table-connections, interface binding),
L2VLAN (type, vlan, interface binding), and management/simple
instances (interface binding only).

BGP protocol config inside NI and EVPN (EVI, FDB) are separate conf objects.
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
            """
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            configurations = CliConfigBuilder(unconfig=unconfig)

            ni_attr_map = getattr(self, 'network_instance_attr', {}) or {}

            for ni_name in sorted(ni_attr_map):
                ni_obj = ni_attr_map[ni_name]
                ni_config = ni_obj.build_config(
                    apply=False,
                    unconfig=unconfig,
                )
                if ni_config:
                    configurations.append_block(ni_config)

            if apply:
                if configurations:
                    self.device.configure(str(configurations))
            else:
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
                ni_type (str): "L2VLAN", "L3VRF", or None (implicit default).
                vlan (int): VLAN number (L2VLAN only).
                description (str): Network instance description.
                interfaces (list): List of interface names to bind.
                rib_ipv4_max_prefix_limit (int): IPv4 RIB max prefix limit.
                rib_ipv4_threshold (int): IPv4 RIB threshold percentage.
                rib_ipv6_max_prefix_limit (int): IPv6 RIB max prefix limit.
                rib_ipv6_threshold (int): IPv6 RIB threshold percentage.
                table_connections (list): List of dicts, each with keys:
                    src_proto, dst_proto, af, src_dst_instance, import_policy.
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

            def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                """Build configuration for a single network instance."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                configurations = CliConfigBuilder(unconfig=unconfig)

                ni_name = str(self.ni_name)

                if unconfig:
                    configurations.append_line(f'network-instance {ni_name}')
                else:
                    with configurations.submode_context(f'network-instance {ni_name}'):
                        self._build_ni_config(configurations)
                    configurations.append_line('!')

                return CliConfig(
                    device=getattr(self, 'device', None),
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def _build_ni_config(self, configurations):
                """Build the body of a network-instance stanza."""

                # Type (L2VLAN, L3VRF)
                if self.ni_type:
                    configurations.append_line(f'type {self.ni_type}')

                # Description
                if self.description:
                    configurations.append_line(f'description "{self.description}"')

                # VLAN (L2VLAN)
                if self.vlan is not None:
                    configurations.append_line(f'vlan {self.vlan}')

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

                # Interface bindings
                if self.interfaces:
                    for intf_name in self.interfaces:
                        configurations.append_line(f'interface {intf_name}')
                        configurations.append_line('!')

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build unconfiguration commands."""
                return self.build_config(
                    apply=apply, attributes=attributes, unconfig=True, **kwargs
                )
