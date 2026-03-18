#!/usr/bin/env python3
"""
Arcos Interface Configuration Support for Genie.

Supports physical interfaces (swp*), bond/LAG interfaces (bond*),
loopback interfaces, and VLAN L3 interfaces (vlan*).

Features:
- Interface-level: enabled, description, mtu, port-speed, aggregate-id,
  debounce-interval
- Bond-specific: aggregation lag-type, min-links, BFD micro
- Subinterface support: numbered subinterfaces with IPv4/IPv6 addresses,
  VLAN tagging (single/double-tagged), ingress/egress mapping, priority-vlan
"""

from abc import ABC
import logging

from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


class Interface(ABC):
    """Arcos-specific Interface implementation for Genie.

    Handles physical (swp*), bond (bond*), loopback, and VLAN L3 (vlan*)
    interfaces with full subinterface and VLAN tagging support.
    """

    class DeviceAttributes(ABC):
        """DeviceAttributes for Arcos Interface configuration."""

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build interface configuration for an Arcos device."""
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

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
            """Per-interface attributes for Arcos.

            Generates CLI for physical, bond, loopback, and VLAN L3 interfaces.
            Supports numbered subinterfaces with VLAN tagging.
            """

            def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                """Build configuration for a specific interface."""
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=False)

                intf_name = self.interface.name

                with configurations.submode_context(f"interface {intf_name}", cancel_empty=True):
                    if unconfig:
                        self._build_unconfig(attributes, configurations, intf_name)
                    else:
                        self._build_config(attributes, configurations, intf_name)

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def _build_config(self, attributes, configurations, intf_name):
                """Build configure commands inside the interface context."""

                # ── Interface type (informational, auto-determined by name) ──
                # ArcOS infers type from name but we emit it for bond/vlan
                if intf_name.startswith("bond"):
                    configurations.append_line("type        ieee8023adLag")
                elif intf_name.startswith("vlan"):
                    configurations.append_line("type    l3ipvlan")
                elif intf_name.startswith("loopback"):
                    configurations.append_line("type    softwareLoopback")
                else:
                    configurations.append_line("type    ethernetCsmacd")

                # ── Description ──
                description = attributes.value("description")
                if description:
                    configurations.append_line(f'description "{description}"')

                # ── MTU ──
                mtu = attributes.value("mtu")
                if mtu is not None:
                    configurations.append_line(f"mtu {mtu}")

                # ── Enabled ──
                enabled = attributes.value("enabled")
                if enabled is not None:
                    configurations.append_line(f"enabled {'true' if enabled else 'false'}")
                elif "loopback" not in intf_name.lower():
                    configurations.append_line("enabled true")

                # ── Ethernet port-speed ──
                port_speed = attributes.value("port_speed")
                if port_speed:
                    configurations.append_line(f"ethernet port-speed {port_speed}")

                # ── Ethernet aggregate-id (LAG member) ──
                aggregate_id = attributes.value("aggregate_id")
                if aggregate_id:
                    configurations.append_line(f"ethernet aggregate-id {aggregate_id}")

                # ── Debounce intervals ──
                debounce_up = attributes.value("debounce_up")
                if debounce_up is not None:
                    configurations.append_line(f"debounce-interval up {debounce_up}")

                debounce_down = attributes.value("debounce_down")
                if debounce_down is not None:
                    configurations.append_line(f"debounce-interval down {debounce_down}")

                # ── Bond/LAG-specific: BFD micro ──
                bfd_micro_enabled = attributes.value("bfd_micro_enabled")
                bfd_micro_remote_ipv4 = attributes.value("bfd_micro_remote_ipv4")
                if bfd_micro_remote_ipv4:
                    configurations.append_line(
                        f"bfd micro remote-address ipv4 {bfd_micro_remote_ipv4}"
                    )
                if bfd_micro_enabled is not None:
                    configurations.append_line(
                        f"bfd micro enabled {'true' if bfd_micro_enabled else 'false'}"
                    )

                # ── Subinterfaces ──
                # Three paths, in priority order:
                #  1. subinterface_configs: list of dicts (simple wrapper path)
                #  2. subinterface_attr mapping (full Genie conf path)
                #  3. Backward compat: top-level ipv4/ipv6 → subinterface 0
                sub_configs = getattr(self, "subinterface_configs", None)
                subinterfaces = getattr(self, "subinterfaces", None)

                if sub_configs:
                    # Simple path: list of dicts, each with sub_id + attributes
                    _build_subinterfaces_from_dicts(
                        sub_configs, configurations, unconfig=False
                    )
                elif subinterfaces:
                    for sub, sub_attributes in attributes.mapping_values(
                        "subinterface_attr", keys=subinterfaces, sort=True
                    ):
                        sub_config = sub.build_config(
                            apply=False,
                            attributes=sub_attributes,
                            unconfig=False,
                        )
                        if sub_config:
                            configurations.append_block(sub_config)
                else:
                    # Backward compat: ipv4/ipv6 on InterfaceAttributes → subinterface 0
                    self._build_subinterface_0_compat(attributes, configurations)

                # ── Bond/LAG-specific: aggregation ──
                lag_type = attributes.value("lag_type")
                if lag_type:
                    configurations.append_line(f"aggregation lag-type {lag_type}")

                min_links = attributes.value("min_links")
                if min_links is not None:
                    configurations.append_line(f"aggregation min-links {min_links}")

            def _build_subinterface_0_compat(self, attributes, configurations):
                """Backward-compatible subinterface 0 from top-level ipv4/ipv6 attrs."""
                ipv4_addr = attributes.value("ipv4")
                ipv6_addr = attributes.value("ipv6")
                ipv4_prefix_attr = attributes.value("ipv4_prefix_length")
                ipv6_prefix_attr = attributes.value("ipv6_prefix_length")

                if not ipv4_addr and not ipv6_addr:
                    return

                with configurations.submode_context("subinterface 0"):
                    if ipv6_addr:
                        ipv6_ip, ipv6_plen = _parse_addr(str(ipv6_addr), ipv6_prefix_attr, 64)
                        with configurations.submode_context(f"ipv6 address {ipv6_ip}"):
                            configurations.append_line(f"prefix-length {ipv6_plen}")
                        configurations.append_line("!")

                    if ipv4_addr:
                        ipv4_ip, ipv4_plen = _parse_addr(str(ipv4_addr), ipv4_prefix_attr, 24)
                        with configurations.submode_context(f"ipv4 address {ipv4_ip}"):
                            configurations.append_line(f"prefix-length {ipv4_plen}")
                        configurations.append_line("!")

                    configurations.append_line("enabled true")
                configurations.append_line("!")

            def _build_unconfig(self, attributes, configurations, intf_name):
                """Build unconfigure commands inside the interface context."""
                description = attributes.value("description")
                if description:
                    configurations.append_line("no description")

                mtu = attributes.value("mtu")
                if mtu is not None:
                    configurations.append_line("no mtu")

                port_speed = attributes.value("port_speed")
                if port_speed:
                    configurations.append_line("no ethernet port-speed")

                aggregate_id = attributes.value("aggregate_id")
                if aggregate_id:
                    configurations.append_line("no ethernet aggregate-id")

                debounce_up = attributes.value("debounce_up")
                if debounce_up is not None:
                    configurations.append_line("no debounce-interval up")

                debounce_down = attributes.value("debounce_down")
                if debounce_down is not None:
                    configurations.append_line("no debounce-interval down")

                bfd_micro_enabled = attributes.value("bfd_micro_enabled")
                if bfd_micro_enabled is not None:
                    configurations.append_line("no bfd micro")

                lag_type = attributes.value("lag_type")
                if lag_type:
                    configurations.append_line("no aggregation lag-type")

                min_links = attributes.value("min_links")
                if min_links is not None:
                    configurations.append_line("no aggregation min-links")

                # Unconfigure subinterfaces
                sub_configs = getattr(self, "subinterface_configs", None)
                subinterfaces = getattr(self, "subinterfaces", None)

                if sub_configs:
                    _build_subinterfaces_from_dicts(
                        sub_configs, configurations, unconfig=True
                    )
                elif subinterfaces:
                    for sub, sub_attributes in attributes.mapping_values(
                        "subinterface_attr", keys=subinterfaces, sort=True
                    ):
                        sub_config = sub.build_config(
                            apply=False,
                            attributes=sub_attributes,
                            unconfig=True,
                        )
                        if sub_config:
                            configurations.append_block(sub_config)
                else:
                    # Backward compat: unconfigure ipv4/ipv6 on subinterface 0
                    ipv4_addr = attributes.value("ipv4")
                    ipv6_addr = attributes.value("ipv6")
                    if ipv4_addr or ipv6_addr:
                        with configurations.submode_context("subinterface 0", cancel_empty=True):
                            if ipv6_addr:
                                ipv6_ip = str(ipv6_addr).partition("/")[0]
                                configurations.append_line(f"no ipv6 address {ipv6_ip}")
                            if ipv4_addr:
                                ipv4_ip = str(ipv4_addr).partition("/")[0]
                                configurations.append_line(f"no ipv4 address {ipv4_ip}")

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build unconfiguration for this interface."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )

            class SubinterfaceAttributes(ABC):
                """Per-subinterface attributes.

                Each subinterface is identified by its index (0, 10, 5001, etc.)
                and can have IPv4/IPv6 addresses, VLAN tagging, and other config.
                """

                def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                    """Build configuration for a specific subinterface."""
                    attributes = AttributesHelper(self, attributes)
                    configurations = CliConfigBuilder(unconfig=False)

                    sub_id = self.subinterface_id

                    with configurations.submode_context(
                        f"subinterface {sub_id}", cancel_empty=True
                    ):
                        if unconfig:
                            self._build_sub_unconfig(attributes, configurations)
                        else:
                            self._build_sub_config(attributes, configurations)

                    return CliConfig(
                        device=self.device,
                        unconfig=unconfig,
                        cli_config=configurations,
                    )

                def _build_sub_config(self, attributes, configurations):
                    """Build subinterface configure commands.

                    Order matters for confd: VLAN match must come before IP
                    addresses on non-zero subinterfaces.
                    """

                    # ── VLAN tagging (must come first for non-zero subinterfaces) ──
                    vlan_match_type = attributes.value("vlan_match_type")
                    vlan_id = attributes.value("vlan_id")
                    vlan_outer_id = attributes.value("vlan_outer_id")
                    vlan_inner_id = attributes.value("vlan_inner_id")

                    if vlan_match_type == "single-tagged" and vlan_id is not None:
                        configurations.append_line(
                            f"vlan match single-tagged vlan-id {vlan_id}"
                        )
                    elif vlan_match_type == "double-tagged":
                        if vlan_inner_id is not None:
                            configurations.append_line(
                                f"vlan match double-tagged inner-vlan-id {vlan_inner_id}"
                            )
                        if vlan_outer_id is not None:
                            configurations.append_line(
                                f"vlan match double-tagged outer-vlan-id {vlan_outer_id}"
                            )
                    elif vlan_id is not None and vlan_match_type is None:
                        # Simple vlan vlan-id (no match keyword)
                        configurations.append_line(f"vlan vlan-id {vlan_id}")

                    # ── VLAN ingress mapping ──
                    vlan_ingress_action = attributes.value("vlan_ingress_action")
                    if vlan_ingress_action:
                        configurations.append_line(
                            f"vlan ingress-mapping vlan-stack-action {vlan_ingress_action}"
                        )

                    # ── VLAN egress mapping ──
                    vlan_egress_action = attributes.value("vlan_egress_action")
                    if vlan_egress_action:
                        configurations.append_line(
                            f"vlan egress-mapping vlan-stack-action {vlan_egress_action}"
                        )

                    vlan_egress_vlan_id = attributes.value("vlan_egress_vlan_id")
                    if vlan_egress_vlan_id is not None:
                        configurations.append_line(
                            f"vlan egress-mapping vlan-id {vlan_egress_vlan_id}"
                        )

                    vlan_egress_inner_id = attributes.value("vlan_egress_inner_id")
                    if vlan_egress_inner_id is not None:
                        configurations.append_line(
                            f"vlan egress-mapping inner-vlan-id {vlan_egress_inner_id}"
                        )

                    # ── IPv6 address ──
                    ipv6_addr = attributes.value("ipv6")
                    ipv6_prefix_attr = attributes.value("ipv6_prefix_length")
                    if ipv6_addr:
                        ipv6_ip, ipv6_plen = _parse_addr(str(ipv6_addr), ipv6_prefix_attr, 64)
                        with configurations.submode_context(f"ipv6 address {ipv6_ip}"):
                            configurations.append_line(f"prefix-length {ipv6_plen}")
                        configurations.append_line("!")

                    # ── IPv4 address ──
                    ipv4_addr = attributes.value("ipv4")
                    ipv4_prefix_attr = attributes.value("ipv4_prefix_length")
                    if ipv4_addr:
                        ipv4_ip, ipv4_plen = _parse_addr(str(ipv4_addr), ipv4_prefix_attr, 24)
                        with configurations.submode_context(f"ipv4 address {ipv4_ip}"):
                            configurations.append_line(f"prefix-length {ipv4_plen}")
                        configurations.append_line("!")

                    # ── IPv4/IPv6 enabled flags ──
                    ipv4_enabled = attributes.value("ipv4_enabled")
                    if ipv4_enabled is not None:
                        configurations.append_line(
                            f"ipv4 enabled {'true' if ipv4_enabled else 'false'}"
                        )

                    ipv6_enabled = attributes.value("ipv6_enabled")
                    if ipv6_enabled is not None:
                        configurations.append_line(
                            f"ipv6 enabled {'true' if ipv6_enabled else 'false'}"
                        )

                    # ── Description ──
                    description = attributes.value("description")
                    if description:
                        configurations.append_line(f'description "{description}"')

                    # ── Enabled ──
                    enabled = attributes.value("enabled")
                    if enabled is not None:
                        configurations.append_line(
                            f"enabled {'true' if enabled else 'false'}"
                        )

                    # ── Priority VLAN ──
                    priority_vlan = attributes.value("priority_vlan")
                    if priority_vlan is not None:
                        configurations.append_line(
                            f"priority-vlan {'true' if priority_vlan else 'false'}"
                        )

                def _build_sub_unconfig(self, attributes, configurations):
                    """Build subinterface unconfigure commands."""
                    ipv4_addr = attributes.value("ipv4")
                    if ipv4_addr:
                        ipv4_ip = str(ipv4_addr).partition("/")[0]
                        configurations.append_line(f"no ipv4 address {ipv4_ip}")

                    ipv6_addr = attributes.value("ipv6")
                    if ipv6_addr:
                        ipv6_ip = str(ipv6_addr).partition("/")[0]
                        configurations.append_line(f"no ipv6 address {ipv6_ip}")

                    vlan_match_type = attributes.value("vlan_match_type")
                    if vlan_match_type:
                        configurations.append_line("no vlan")

                    vlan_id = attributes.value("vlan_id")
                    if vlan_id is not None and vlan_match_type is None:
                        configurations.append_line("no vlan")

                def build_unconfig(self, apply=False, attributes=None, **kwargs):
                    """Build unconfiguration for this subinterface."""
                    return self.build_config(
                        apply=apply,
                        attributes=attributes,
                        unconfig=True,
                        **kwargs,
                    )


def _build_subinterfaces_from_dicts(sub_configs, configurations, unconfig=False):
    """Build subinterface CLI from a list of dicts (simple wrapper path).

    Each dict in sub_configs should contain:
        sub_id (int): Subinterface index (required)
        Plus any SubinterfaceAttributes fields: ipv4, ipv4_prefix_length,
        ipv6, ipv6_prefix_length, ipv4_enabled, ipv6_enabled, enabled,
        description, priority_vlan, vlan_id, vlan_match_type, vlan_outer_id,
        vlan_inner_id, vlan_ingress_action, vlan_egress_action,
        vlan_egress_vlan_id, vlan_egress_inner_id
    """
    for sub_cfg in sorted(sub_configs, key=lambda d: d.get("sub_id", 0)):
        sub_id = sub_cfg.get("sub_id", 0)

        if unconfig and sub_id != 0:
            # For non-zero subinterfaces, remove the entire subinterface.
            # You cannot remove individual VLAN match attributes while
            # the subinterface exists (confd rejects it).
            configurations.append_line(f"no subinterface {sub_id}")
        elif unconfig:
            with configurations.submode_context(
                f"subinterface {sub_id}", cancel_empty=True
            ):
                _build_sub_unconfig_from_dict(sub_cfg, configurations)
        else:
            with configurations.submode_context(
                f"subinterface {sub_id}", cancel_empty=True
            ):
                _build_sub_config_from_dict(sub_cfg, configurations)


def _build_sub_config_from_dict(cfg, configurations):
    """Build subinterface config lines from a dict of attributes.

    Order matters for confd: VLAN match must come before IP addresses
    on non-zero subinterfaces.
    """

    # VLAN tagging (must come first for non-zero subinterfaces)
    vlan_match_type = cfg.get("vlan_match_type")
    vlan_id = cfg.get("vlan_id")
    vlan_outer_id = cfg.get("vlan_outer_id")
    vlan_inner_id = cfg.get("vlan_inner_id")

    if vlan_match_type == "single-tagged" and vlan_id is not None:
        configurations.append_line(
            f"vlan match single-tagged vlan-id {vlan_id}"
        )
    elif vlan_match_type == "double-tagged":
        if vlan_inner_id is not None:
            configurations.append_line(
                f"vlan match double-tagged inner-vlan-id {vlan_inner_id}"
            )
        if vlan_outer_id is not None:
            configurations.append_line(
                f"vlan match double-tagged outer-vlan-id {vlan_outer_id}"
            )
    elif vlan_id is not None and vlan_match_type is None:
        configurations.append_line(f"vlan vlan-id {vlan_id}")

    # VLAN ingress mapping
    vlan_ingress_action = cfg.get("vlan_ingress_action")
    if vlan_ingress_action:
        configurations.append_line(
            f"vlan ingress-mapping vlan-stack-action {vlan_ingress_action}"
        )

    # VLAN egress mapping
    vlan_egress_action = cfg.get("vlan_egress_action")
    if vlan_egress_action:
        configurations.append_line(
            f"vlan egress-mapping vlan-stack-action {vlan_egress_action}"
        )

    vlan_egress_vlan_id = cfg.get("vlan_egress_vlan_id")
    if vlan_egress_vlan_id is not None:
        configurations.append_line(
            f"vlan egress-mapping vlan-id {vlan_egress_vlan_id}"
        )

    vlan_egress_inner_id = cfg.get("vlan_egress_inner_id")
    if vlan_egress_inner_id is not None:
        configurations.append_line(
            f"vlan egress-mapping inner-vlan-id {vlan_egress_inner_id}"
        )

    # IPv6 address (after VLAN config)
    ipv6_addr = cfg.get("ipv6")
    if ipv6_addr:
        ipv6_ip, ipv6_plen = _parse_addr(
            str(ipv6_addr), cfg.get("ipv6_prefix_length"), 64
        )
        with configurations.submode_context(f"ipv6 address {ipv6_ip}"):
            configurations.append_line(f"prefix-length {ipv6_plen}")
        configurations.append_line("!")

    # IPv4 address (after VLAN config)
    ipv4_addr = cfg.get("ipv4")
    if ipv4_addr:
        ipv4_ip, ipv4_plen = _parse_addr(
            str(ipv4_addr), cfg.get("ipv4_prefix_length"), 24
        )
        with configurations.submode_context(f"ipv4 address {ipv4_ip}"):
            configurations.append_line(f"prefix-length {ipv4_plen}")
        configurations.append_line("!")

    # IPv4/IPv6 enabled flags
    ipv4_enabled = cfg.get("ipv4_enabled")
    if ipv4_enabled is not None:
        configurations.append_line(
            f"ipv4 enabled {'true' if ipv4_enabled else 'false'}"
        )

    ipv6_enabled = cfg.get("ipv6_enabled")
    if ipv6_enabled is not None:
        configurations.append_line(
            f"ipv6 enabled {'true' if ipv6_enabled else 'false'}"
        )

    # Description
    description = cfg.get("description")
    if description:
        configurations.append_line(f'description "{description}"')

    # Enabled
    enabled = cfg.get("enabled")
    if enabled is not None:
        configurations.append_line(f"enabled {'true' if enabled else 'false'}")

    # Priority VLAN
    priority_vlan = cfg.get("priority_vlan")
    if priority_vlan is not None:
        configurations.append_line(
            f"priority-vlan {'true' if priority_vlan else 'false'}"
        )


def _build_sub_unconfig_from_dict(cfg, configurations):
    """Build subinterface unconfig lines from a dict."""
    ipv4_addr = cfg.get("ipv4")
    if ipv4_addr:
        ipv4_ip = str(ipv4_addr).partition("/")[0]
        configurations.append_line(f"no ipv4 address {ipv4_ip}")

    ipv6_addr = cfg.get("ipv6")
    if ipv6_addr:
        ipv6_ip = str(ipv6_addr).partition("/")[0]
        configurations.append_line(f"no ipv6 address {ipv6_ip}")

    vlan_match_type = cfg.get("vlan_match_type")
    if vlan_match_type:
        configurations.append_line("no vlan")

    vlan_id = cfg.get("vlan_id")
    if vlan_id is not None and vlan_match_type is None:
        configurations.append_line("no vlan")


def _parse_addr(addr_str, explicit_prefix, default_prefix):
    """Parse an address string that may contain /prefix notation.

    Returns (ip, prefix_length) tuple.
    """
    if "/" in addr_str:
        base, _, pref = addr_str.partition("/")
        ip = base
        if explicit_prefix is not None:
            prefix = explicit_prefix
        else:
            try:
                prefix = int(pref)
            except ValueError:
                prefix = default_prefix
    else:
        ip = addr_str
        prefix = explicit_prefix if explicit_prefix is not None else default_prefix
    return ip, prefix
