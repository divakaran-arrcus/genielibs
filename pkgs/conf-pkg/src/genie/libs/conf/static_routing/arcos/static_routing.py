#!/usr/bin/env python3
"""
Native ArcOS Static Routing configuration plugin for Genie.

This implementation provides ARCOS static routing CLI generation under the
standard Genie conf StaticRouting abstraction.
"""

from abc import ABC
import logging

from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class StaticRouting(ABC):
    """ARCOS-specific Static Routing implementation for Genie (native plugin)."""

    class DeviceAttributes(ABC):
        """Device-level static routing attributes for ARCOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build static routing configuration for ARCOS device."""
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Iterate over VRFs (network-instances)
            for sub, vrf_attributes in attributes.mapping_values('vrf_attr', sort=True):
                configurations.append_block(
                    sub.build_config(apply=False, attributes=vrf_attributes, unconfig=unconfig)
                )

            if apply:
                if configurations:
                    self.device.configure(str(configurations), fail_invalid=True)
            else:
                return CliConfig(device=self.device, unconfig=unconfig, cli_config=configurations)

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build static routing unconfiguration for ARCOS device."""
            return self.build_config(apply=apply, attributes=attributes, unconfig=True)

        class VrfAttributes(ABC):
            """VRF-level static routing attributes for ARCOS."""

            def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
                """Build VRF-level static routing configuration."""
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                vrf_name = self.vrf or 'default'

                # Enter network-instance context
                with configurations.submode_context(f'network-instance {vrf_name}'):
                    # Enter protocol STATIC default context
                    with configurations.submode_context('protocol STATIC default'):
                        # Build static routes configuration
                        # For ARCOS, we don't use address-family - routes are directly under protocol
                        for af_sub, af_attributes in attributes.mapping_values('address_family_attr', sort=True):
                            for route_sub, route_attributes in af_attributes.mapping_values('route_attr', sort=True):
                                configurations.append_block(
                                    route_sub.build_config(
                                        apply=False,
                                        attributes=route_attributes,
                                        unconfig=unconfig
                                    )
                                )

                if apply:
                    if configurations:
                        self.device.configure(str(configurations), fail_invalid=True)
                else:
                    return CliConfig(device=self.device, unconfig=unconfig, cli_config=configurations)

            def build_unconfig(self, apply=True, attributes=None, **kwargs):
                """Build VRF-level static routing unconfiguration."""
                return self.build_config(apply=apply, attributes=attributes, unconfig=True)

            class AddressFamilyAttributes(ABC):
                """Address family attributes (flattened for ARCOS - no AF in CLI)."""

                class RouteAttributes(ABC):
                    """Static route attributes for ARCOS."""

                    def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
                        """Build static route configuration."""
                        attributes = AttributesHelper(self, attributes)
                        configurations = CliConfigBuilder(unconfig=unconfig)

                        route_prefix = self.route
                        if not route_prefix:
                            return CliConfig(device=self.device, unconfig=unconfig, cli_config=configurations)

                        # Enter static-route context
                        with configurations.submode_context(f'static-route {route_prefix}'):
                            # Description
                            description = attributes.value('description')
                            if description is not None:
                                configurations.append_line(f'description "{description}"')

                            # Preference (administrative distance)
                            preference = attributes.value('preference')
                            if preference is not None:
                                configurations.append_line(f'preference {preference}')

                            # Tag
                            tag = attributes.value('tag')
                            if tag is not None:
                                configurations.append_line(f'set-tag {tag}')

                            # Local label index (for MPLS)
                            local_label_index = attributes.value('local_label_index')
                            if local_label_index is not None:
                                configurations.append_line(f'local-label-index {local_label_index}')

                            # BFD profile (at route level)
                            bfd_profile = attributes.value('bfd_profile')
                            if bfd_profile is not None:
                                configurations.append_line(f'bfd profile {bfd_profile}')

                            # Build next-hop configurations
                            for nh_sub, nh_attributes in attributes.mapping_values('next_hop_attr', sort=True):
                                configurations.append_block(
                                    nh_sub.build_config(
                                        apply=False,
                                        attributes=nh_attributes,
                                        unconfig=unconfig
                                    )
                                )

                        if apply:
                            if configurations:
                                self.device.configure(str(configurations), fail_invalid=True)
                        else:
                            return CliConfig(device=self.device, unconfig=unconfig, cli_config=configurations)

                    def build_unconfig(self, apply=True, attributes=None, **kwargs):
                        """Build static route unconfiguration."""
                        return self.build_config(apply=apply, attributes=attributes, unconfig=True)

                    class NextHopAttributes(ABC):
                        """Next-hop attributes for ARCOS static routes."""

                        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
                            """Build next-hop configuration."""
                            attributes = AttributesHelper(self, attributes)
                            configurations = CliConfigBuilder(unconfig=unconfig)

                            # Next-hop index is the identifier
                            next_hop_index = attributes.value('next_hop_index') or self.nexthop or '1'

                            # Enter next-hop-index context
                            with configurations.submode_context(f'next-hop-index {next_hop_index}'):
                                # Next-hop IP address or DROP
                                # Genie stores managed attribute values with underscore prefix
                                # Get from backing field which has the user-set value
                                nh_value = self.__dict__.get('_nexthop')
                                if not nh_value or nh_value == next_hop_index:
                                    # Fallback to non-prefixed if backing field not set
                                    nh_value = self.__dict__.get('nexthop')
                                
                                # Output next-hop if it's set and looks like an IP or DROP
                                if nh_value and str(nh_value) != str(next_hop_index):
                                    nh_str = str(nh_value)
                                    if nh_str.upper() == 'DROP' or '.' in nh_str or ':' in nh_str:
                                        if nh_str.upper() == 'DROP':
                                            configurations.append_line('next-hop DROP')
                                        else:
                                            configurations.append_line(f'next-hop {nh_value}')

                                # Interface
                                interface = attributes.value('interface')
                                subinterface = attributes.value('subinterface')
                                if interface is not None:
                                    if subinterface is not None:
                                        configurations.append_line(f'interface {interface} subinterface {subinterface}')
                                    else:
                                        configurations.append_line(f'interface {interface}')

                                # Metric
                                metric = attributes.value('metric')
                                if metric is not None:
                                    configurations.append_line(f'metric {metric}')

                                # Next network instance (VRF leaking)
                                next_network_instance = attributes.value('next_network_instance')
                                if next_network_instance is not None:
                                    configurations.append_line(f'next-network-instance {next_network_instance}')

                                # Remote label stack (MPLS)
                                remote_label_stack = attributes.value('remote_label_stack')
                                if remote_label_stack is not None:
                                    if isinstance(remote_label_stack, str):
                                        # IMPLICIT-NULL
                                        configurations.append_line(f'remote-label-stack {remote_label_stack}')
                                    elif isinstance(remote_label_stack, (list, tuple)):
                                        # Array of labels
                                        labels_str = ' '.join(str(label) for label in remote_label_stack)
                                        configurations.append_line(f'remote-label-stack [ {labels_str} ]')

                                # BFD destination address (at next-hop level)
                                bfd_destination_address = attributes.value('bfd_destination_address')
                                if bfd_destination_address is not None:
                                    # Determine if IPv4 or IPv6
                                    if ':' in bfd_destination_address:
                                        configurations.append_line(f'bfd destination-address ipv6 {bfd_destination_address}')
                                    else:
                                        configurations.append_line(f'bfd destination-address ipv4 {bfd_destination_address}')

                            if apply:
                                if configurations:
                                    self.device.configure(str(configurations), fail_invalid=True)
                            else:
                                return CliConfig(device=self.device, unconfig=unconfig, cli_config=configurations)

                        def build_unconfig(self, apply=True, attributes=None, **kwargs):
                            """Build next-hop unconfiguration."""
                            return self.build_config(apply=apply, attributes=attributes, unconfig=True)
