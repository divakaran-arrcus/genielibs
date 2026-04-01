#!/usr/bin/env python3
"""
Native ArcOS LLDP configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles global LLDP hello-timer and per-interface mode/enabled settings.

ArcOS LLDP CLI is flat (no network-instance or protocol wrapping):

    lldp hello-timer <seconds>
    lldp interface <name> mode <TX_RX|TX_ONLY|RX_ONLY>
    lldp interface <name> enabled <true|false>
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class Lldp(ABC):
    """ArcOS-specific LLDP implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level LLDP attributes for ArcOS."""

        hello_timer = managedattribute(
            name='hello_timer',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='LLDP hello timer interval in seconds (default 30)')

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build LLDP configuration for an ArcOS device.

            ArcOS LLDP commands are global (no network-instance wrapping):
                lldp hello-timer <seconds>
                lldp interface <name> mode <mode>
                lldp interface <name> enabled <true|false>
            """
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Global hello-timer
            hello_timer = attributes.value('hello_timer')
            if hello_timer is not None:
                configurations.append_line(
                    f'lldp hello-timer {hello_timer}'
                )

            # Per-interface LLDP configuration
            for sub, intf_attributes in attributes.mapping_values(
                'interface_attr', sort=True
            ):
                intf_config = sub.build_config(
                    apply=False,
                    attributes=intf_attributes,
                    unconfig=unconfig,
                )
                if intf_config:
                    configurations.append_block(intf_config)

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
            """Build LLDP unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        # ============================================================
        # INTERFACE ATTRIBUTES
        # ============================================================

        class InterfaceAttributes(ABC):
            """Per-interface LLDP attributes for ArcOS."""

            enabled = managedattribute(
                name='enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable/disable LLDP on this interface (default true)')

            mode = managedattribute(
                name='mode',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='LLDP operation mode: TX_RX, TX_ONLY, or RX_ONLY')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, **kwargs):
                """Build per-interface LLDP configuration.

                Generates flat commands:
                    lldp interface <name> mode <mode>
                    lldp interface <name> enabled <true|false>
                """
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                intf_name = self.interface_name

                # Interface mode
                intf_mode = attributes.value('mode')
                if intf_mode:
                    configurations.append_line(
                        f'lldp interface {intf_name} mode {intf_mode}'
                    )

                # Interface enabled
                intf_enabled = attributes.value('enabled')
                if intf_enabled is not None:
                    enabled_str = 'true' if intf_enabled else 'false'
                    configurations.append_line(
                        f'lldp interface {intf_name} enabled {enabled_str}'
                    )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build per-interface LLDP unconfiguration."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )
