#!/usr/bin/env python3
"""
Arcos Interface Configuration Support for Genie
Implements device-specific DeviceAttributes for Arcos routers.

Supported attributes (via AttributesHelper):
- interface_attr: per-interface attribute container
- enabled: interface admin enabled/disabled flag
- ipv4 / ipv4_prefix_length: IPv4 address and prefix length
- ipv6 / ipv6_prefix_length: IPv6 address and prefix length
"""

from abc import ABC
import logging

from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


class Interface(ABC):
    """Arcos-specific Interface implementation for Genie.

    This class provides OpenConfig-based configuration for Arrcus routers.
    """

    class DeviceAttributes(ABC):
        """DeviceAttributes for Arcos Interface configuration.

        Generates OpenConfig format configuration by iterating over
        per-interface attributes.
        """

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build interface configuration for an Arcos device.

            Args:
                apply: If True, apply config to device. If False, return config.
                attributes: AttributesHelper object with configuration attributes.
                unconfig: If True, build unconfiguration commands.

            Returns:
                CliConfig object or None (if apply=True).
            """
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Iterate through all interfaces on this device
            for sub, intf_attributes in attributes.mapping_values(
                "interface_attr", keys=self.interfaces, sort=True
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
                    self.device.configure(str(configurations))
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build interface unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        class InterfaceAttributes(ABC):
            """Individual interface attributes for Arcos.

            This class is responsible for generating per-interface
            OpenConfig-style CLI.
            """

            def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                """Build configuration for a specific interface.

                Args:
                    apply: Not used at interface level.
                    attributes: Configuration attributes.
                    unconfig: Whether this is an unconfiguration.

                Returns:
                    CliConfig containing configuration for this interface.
                """
                attributes = AttributesHelper(self, attributes)
                # Use explicit "no ..." lines for unconfig rather than relying on
                # automatic top-level "no interface" behavior, which is not
                # allowed for front-panel ports on ArcOS.
                configurations = CliConfigBuilder(unconfig=False)

                # Get interface name from associated Interface object
                intf_name = self.interface.name

                with configurations.submode_context(f"interface {intf_name}", cancel_empty=True):
                    if unconfig:
                        # Unconfigure interface-level attributes first.
                        description = attributes.value("description")
                        if description:
                            configurations.append_line("no description")

                        mtu = attributes.value("mtu")
                        if mtu is not None:
                            configurations.append_line("no mtu")

                        # Unconfigure IP addresses under subinterface 0.
                        ipv4_addr = attributes.value("ipv4")
                        ipv6_addr = attributes.value("ipv6")

                        if ipv4_addr or ipv6_addr:
                            with configurations.submode_context("subinterface 0", cancel_empty=True):
                                # IPv6 address
                                if ipv6_addr:
                                    ipv6_str = str(ipv6_addr)
                                    ipv6_ip = ipv6_str
                                    if "/" in ipv6_str:
                                        base, _, _ = ipv6_str.partition("/")
                                        ipv6_ip = base
                                    configurations.append_line(
                                        f"no ipv6 address {ipv6_ip}"
                                    )

                                # IPv4 address
                                if ipv4_addr:
                                    ipv4_str = str(ipv4_addr)
                                    ipv4_ip = ipv4_str
                                    if "/" in ipv4_str:
                                        base, _, _ = ipv4_str.partition("/")
                                        ipv4_ip = base
                                    configurations.append_line(
                                        f"no ipv4 address {ipv4_ip}"
                                    )
                    else:
                        # Configure interface
                        # Note: Interface type is read-only, determined by name
                        #   swp*     -> ethernetCsmacd
                        #   loopback -> softwareLoopback

                        # ========================================
                        # ENABLED STATE
                        # ========================================

                        enabled = attributes.value("enabled")
                        if enabled is not None:
                            enabled_str = "true" if enabled else "false"
                            configurations.append_line(f"enabled {enabled_str}")
                        elif "loopback" not in intf_name.lower():
                            # Enable by default for non-loopback interfaces
                            configurations.append_line("enabled true")

                        # Optional interface description
                        description = attributes.value("description")
                        if description:
                            configurations.append_line(f'description "{description}"')

                        # Optional interface MTU
                        mtu = attributes.value("mtu")
                        if mtu is not None:
                            configurations.append_line(f"mtu {mtu}")

                        # ========================================
                        # SUBINTERFACES
                        # ========================================

                        # Typically subinterface 0 for addresses
                        ipv4_addr = attributes.value("ipv4")
                        ipv6_addr = attributes.value("ipv6")
                        ipv4_prefix_attr = attributes.value("ipv4_prefix_length")
                        ipv6_prefix_attr = attributes.value("ipv6_prefix_length")

                        if ipv4_addr or ipv6_addr:
                            with configurations.submode_context("subinterface 0"):
                                # IPv6 address (appears first in config)
                                if ipv6_addr:
                                    ipv6_str = str(ipv6_addr)
                                    ipv6_ip = ipv6_str
                                    local_ipv6_prefix = ipv6_prefix_attr
                                    if "/" in ipv6_str:
                                        base, _, pref = ipv6_str.partition("/")
                                        ipv6_ip = base
                                        if local_ipv6_prefix is None:
                                            try:
                                                local_ipv6_prefix = int(pref)
                                            except ValueError:
                                                local_ipv6_prefix = None
                                    if local_ipv6_prefix is None:
                                        local_ipv6_prefix = 64

                                    # ArcOS hierarchical syntax:
                                    #   ipv6 address <ip>
                                    #    prefix-length <len>
                                    with configurations.submode_context(
                                        f"ipv6 address {ipv6_ip}"
                                    ):
                                        configurations.append_line(
                                            f"prefix-length {local_ipv6_prefix}"
                                        )
                                    configurations.append_line("!")

                                # IPv4 address
                                if ipv4_addr:
                                    ipv4_str = str(ipv4_addr)
                                    ipv4_ip = ipv4_str
                                    local_ipv4_prefix = ipv4_prefix_attr
                                    if "/" in ipv4_str:
                                        base, _, pref = ipv4_str.partition("/")
                                        ipv4_ip = base
                                        if local_ipv4_prefix is None:
                                            try:
                                                local_ipv4_prefix = int(pref)
                                            except ValueError:
                                                local_ipv4_prefix = None
                                    if local_ipv4_prefix is None:
                                        local_ipv4_prefix = 24

                                    # ArcOS hierarchical syntax:
                                    #   ipv4 address <ip>
                                    #    prefix-length <len>
                                    with configurations.submode_context(
                                        f"ipv4 address {ipv4_ip}"
                                    ):
                                        configurations.append_line(
                                            f"prefix-length {local_ipv4_prefix}"
                                        )
                                    configurations.append_line("!")

                                # Subinterface enabled
                                configurations.append_line("enabled true")

                                # Add closing ! for interface context
                            configurations.append_line("!")

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build unconfiguration for this interface."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )
