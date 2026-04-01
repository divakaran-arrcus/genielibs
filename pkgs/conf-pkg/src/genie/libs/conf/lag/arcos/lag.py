#!/usr/bin/env python3
"""
Native ArcOS LAG (Bond/LACP) configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles bond interface creation, LACP settings, member assignment,
L2 switched-vlan config, L3 IP addressing, and LACP fallback.

Bond config goes under ``interface bond<N>``.
Member assignment goes under ``interface <member>`` with
``ethernet aggregate-id bond<N>``.
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


class Lag(ABC):
    """ArcOS-specific LAG (Bond/LACP) implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level LAG attributes for ArcOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build LAG configuration for an ArcOS device."""
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Delegate to per-bond children
            for sub, bond_attributes in attributes.mapping_values(
                'bond_attr', sort=True
            ):
                bond_config = sub.build_config(
                    apply=False,
                    attributes=bond_attributes,
                    unconfig=unconfig,
                )
                if bond_config:
                    configurations.append_block(bond_config)

            if apply:
                if configurations:
                    self.device.configure(str(configurations),
                                          fail_invalid=True)
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build LAG unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        # =============================================================
        # BOND ATTRIBUTES
        # =============================================================

        class BondAttributes(ABC):
            """Per-bond interface LAG attributes for ArcOS."""

            enabled = managedattribute(
                name='enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable the bond interface')

            lag_type = managedattribute(
                name='lag_type',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Aggregation type: LACP or STATIC')

            min_links = managedattribute(
                name='min_links',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Minimum links for bond to be up')

            custom_mac = managedattribute(
                name='custom_mac',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable custom MAC on bond interface')

            members = managedattribute(
                name='members',
                default=None,
                type=(None, managedattribute.test_istype(list)),
                doc='Member interface names (e.g., [swp10, swp20])')

            lacp_fallback_mode = managedattribute(
                name='lacp_fallback_mode',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='LACP fallback mode: INDIVIDUAL')

            lacp_fallback_timeout = managedattribute(
                name='lacp_fallback_timeout',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='LACP fallback timeout in seconds (default 3)')

            lacp_fallback_primary = managedattribute(
                name='lacp_fallback_primary',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Primary interface for LACP fallback')

            l2_mode = managedattribute(
                name='l2_mode',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Switched-vlan interface-mode: ACCESS or TRUNK')

            l2_access_vlan = managedattribute(
                name='l2_access_vlan',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Access VLAN ID')

            l2_trunk_vlans = managedattribute(
                name='l2_trunk_vlans',
                default=None,
                type=(None, managedattribute.test_istype(list)),
                doc='Trunk VLAN IDs')

            ipv4_address = managedattribute(
                name='ipv4_address',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='L3 IPv4 address (applied via subinterface 0)')

            ipv4_prefix_length = managedattribute(
                name='ipv4_prefix_length',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='IPv4 prefix length')

            ipv6_address = managedattribute(
                name='ipv6_address',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='L3 IPv6 address (applied via subinterface 0)')

            ipv6_prefix_length = managedattribute(
                name='ipv6_prefix_length',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='IPv6 prefix length')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, **kwargs):
                """Build per-bond LAG configuration.

                Generates:
                1. Bond interface config (aggregation, L2/L3, fallback)
                2. Member interface config (ethernet aggregate-id)
                """
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                bond_name = self.bond_name

                # --- Bond interface config ---
                with configurations.submode_context(
                    f'interface {bond_name}'
                ):
                    # Enabled
                    v = attributes.value('enabled')
                    if v is not None:
                        configurations.append_line(
                            f'enabled {"true" if v else "false"}'
                        )

                    # LAG type
                    v = attributes.value('lag_type')
                    if v is not None:
                        configurations.append_line(
                            f'aggregation lag-type {v}'
                        )

                    # Min links
                    v = attributes.value('min_links')
                    if v is not None:
                        configurations.append_line(
                            f'aggregation min-links {v}'
                        )

                    # Custom MAC
                    v = attributes.value('custom_mac')
                    if v is not None:
                        configurations.append_line(
                            f'custom-mac {"true" if v else "false"}'
                        )

                    # L2 switched-vlan config
                    l2_mode = attributes.value('l2_mode')
                    if l2_mode is not None:
                        configurations.append_line(
                            f'aggregation switched-vlan '
                            f'interface-mode {l2_mode}'
                        )

                        if l2_mode == 'ACCESS':
                            vlan = attributes.value('l2_access_vlan')
                            if vlan is not None:
                                configurations.append_line(
                                    f'aggregation switched-vlan '
                                    f'access-vlan {vlan}'
                                )

                        elif l2_mode == 'TRUNK':
                            vlans = attributes.value('l2_trunk_vlans')
                            if vlans is not None:
                                if isinstance(vlans, (list, tuple)):
                                    vlan_str = ' '.join(
                                        str(v) for v in vlans
                                    )
                                else:
                                    vlan_str = str(vlans)
                                configurations.append_line(
                                    f'aggregation switched-vlan '
                                    f'trunk-vlans [ {vlan_str} ]'
                                )

                    # LACP fallback
                    fb_mode = attributes.value('lacp_fallback_mode')
                    if fb_mode is not None:
                        configurations.append_line(
                            f'aggregation lacp fallback mode {fb_mode}'
                        )

                    fb_timeout = attributes.value('lacp_fallback_timeout')
                    if fb_timeout is not None:
                        configurations.append_line(
                            f'aggregation lacp fallback timeout '
                            f'{fb_timeout}'
                        )

                    fb_primary = attributes.value('lacp_fallback_primary')
                    if fb_primary is not None:
                        configurations.append_line(
                            f'aggregation lacp fallback '
                            f'primary-interface {fb_primary}'
                        )

                    # L3 IP addressing (subinterface 0)
                    ipv4 = attributes.value('ipv4_address')
                    ipv4_pl = attributes.value('ipv4_prefix_length')
                    ipv6 = attributes.value('ipv6_address')
                    ipv6_pl = attributes.value('ipv6_prefix_length')

                    if ipv4 or ipv6:
                        with configurations.submode_context(
                            'subinterface 0'
                        ):
                            if ipv4 and ipv4_pl is not None:
                                with configurations.submode_context(
                                    f'ipv4 address {ipv4}'
                                ):
                                    configurations.append_line(
                                        f'prefix-length {ipv4_pl}'
                                    )

                            if ipv6 and ipv6_pl is not None:
                                with configurations.submode_context(
                                    f'ipv6 address {ipv6}'
                                ):
                                    configurations.append_line(
                                        f'prefix-length {ipv6_pl}'
                                    )

                # --- Member interface config ---
                member_list = attributes.value('members')
                if member_list:
                    for member in member_list:
                        with configurations.submode_context(
                            f'interface {member}'
                        ):
                            configurations.append_line('enabled true')
                            configurations.append_line(
                                f'ethernet aggregate-id {bond_name}'
                            )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None,
                               **kwargs):
                """Build per-bond LAG unconfiguration."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )
