#!/usr/bin/env python3
"""
Native ArcOS VRRP configuration plugin for Genie.

Handles VRRP group configuration under interface address context.

CLI structure:
    interface <intf>
     subinterface <sub>
      ipv4 address <ip>
       prefix-length <len>
       vrrp vrrp-group <vrid>
        virtual-address [ <vip1> <vip2> ]
        priority <0-255>
        advertisement-interval <centiseconds>
        accept-mode <true|false>
        vrrp-version <VRRP_V2|VRRP_V3|VRRP_V2_V3>
       !
"""

from abc import ABC
import logging
from typing import Any, Dict

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


class Vrrp(ABC):
    """ArcOS-specific VRRP implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level VRRP attributes for ArcOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build VRRP configuration for an ArcOS device."""
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            for sub, grp_attributes in attributes.mapping_values(
                'vrrp_group_attr', sort=True
            ):
                grp_config = sub.build_config(
                    apply=False,
                    attributes=grp_attributes,
                    unconfig=unconfig,
                )
                if grp_config:
                    configurations.append_block(grp_config)

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
            return self.build_config(
                apply=apply, attributes=attributes,
                unconfig=True, **kwargs,
            )

        class VrrpGroupAttributes(ABC):
            """Per-VRRP-group attributes for ArcOS."""

            interface = managedattribute(
                name='interface',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Interface name (e.g., swp10)')

            sub_id = managedattribute(
                name='sub_id',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Subinterface ID (e.g., 0)')

            af = managedattribute(
                name='af',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Address family: ipv4 or ipv6')

            address = managedattribute(
                name='address',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Interface IP address')

            prefix_length = managedattribute(
                name='prefix_length',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Prefix length (mandatory)')

            vrid = managedattribute(
                name='vrid',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Virtual router ID (1-255)')

            virtual_addresses = managedattribute(
                name='virtual_addresses',
                default=None,
                type=(None, managedattribute.test_istype(list)),
                doc='Virtual IP addresses')

            priority = managedattribute(
                name='priority',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='VRRP priority (1-254, default 100)')

            advertisement_interval = managedattribute(
                name='advertisement_interval',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Advertisement interval in centiseconds (default 100)')

            accept_mode = managedattribute(
                name='accept_mode',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Accept mode (default true)')

            vrrp_version = managedattribute(
                name='vrrp_version',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='VRRP version: VRRP_V2, VRRP_V3, VRRP_V2_V3 (IPv4 only)')

            virtual_link_local = managedattribute(
                name='virtual_link_local',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Virtual IPv6 link-local address (IPv6 only)')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, **kwargs):
                """Build per-VRRP-group configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                intf = attributes.value('interface')
                sub = attributes.value('sub_id')
                af = attributes.value('af') or 'ipv4'
                addr = attributes.value('address')
                pl = attributes.value('prefix_length')
                vrid = attributes.value('vrid')

                if not all([intf, addr, pl is not None, vrid is not None]):
                    return CliConfig(
                        device=self.device, unconfig=unconfig,
                        cli_config=configurations,
                    )

                sub_str = sub if sub is not None else 0

                # Build deeply nested context
                with configurations.submode_context(
                    f'interface {intf}'
                ):
                    with configurations.submode_context(
                        f'subinterface {sub_str}'
                    ):
                        with configurations.submode_context(
                            f'{af} address {addr}'
                        ):
                            configurations.append_line(
                                f'prefix-length {pl}'
                            )

                            with configurations.submode_context(
                                f'vrrp vrrp-group {vrid}'
                            ):
                                # Virtual addresses
                                vips = attributes.value('virtual_addresses')
                                if vips:
                                    if isinstance(vips, (list, tuple)):
                                        vips_str = ' '.join(
                                            str(v) for v in vips
                                        )
                                    else:
                                        vips_str = str(vips)
                                    configurations.append_line(
                                        f'virtual-address [ {vips_str} ]'
                                    )

                                v = attributes.value('priority')
                                if v is not None:
                                    configurations.append_line(
                                        f'priority {v}'
                                    )

                                v = attributes.value('advertisement_interval')
                                if v is not None:
                                    configurations.append_line(
                                        f'advertisement-interval {v}'
                                    )

                                v = attributes.value('accept_mode')
                                if v is not None:
                                    configurations.append_line(
                                        f'accept-mode '
                                        f'{"true" if v else "false"}'
                                    )

                                v = attributes.value('vrrp_version')
                                if v is not None:
                                    configurations.append_line(
                                        f'vrrp-version {v}'
                                    )

                                v = attributes.value('virtual_link_local')
                                if v is not None:
                                    configurations.append_line(
                                        f'virtual-link-local {v}'
                                    )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None,
                               **kwargs):
                return self.build_config(
                    apply=apply, attributes=attributes,
                    unconfig=True, **kwargs,
                )
