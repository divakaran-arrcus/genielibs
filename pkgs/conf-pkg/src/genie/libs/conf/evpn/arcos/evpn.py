#!/usr/bin/env python3
"""
Native ArcOS EVPN configuration plugin for Genie.

Covers global EVPN settings (anycast gateway MAC, DF election timer,
duplicate MAC detection), overlay local tunnel endpoint (LTEP), and
per-interface ESI configuration.

Per-network-instance EVPN configuration (EVI, VNI, FDB, VPWS, interface
binding) is handled by the NetworkInstance conf object — not here.

Supported attributes on evpn.device_attr[device]:

Global EVPN:
- anycast_gateway_mac: str — anycast gateway MAC (e.g., "aa:bb:cc:01:02:03")
- df_election_time: int — DF election hold timer in seconds
- duplicate_mac_window: int — duplicate MAC detection window in seconds
- duplicate_mac_threshold: int — duplicate MAC detection threshold (move count)
- duplicate_mac_auto_recovery_time: int — auto-recovery time in seconds (0 disables)

Overlay LTEP:
- overlay_ltep_id: int — local tunnel endpoint ID (e.g., 0)
- overlay_ltep_source_interface: str — source interface (e.g., "loopback0")

Per-interface ESI:
- esi_interfaces: dict mapping interface-name -> dict with keys:
      esi (str) — 10-octet ESI value (e.g., "00:01:02:03:04:05:06:07:08:09")
"""

from abc import ABC
import logging

from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class Evpn(ABC):
    """ArcOS-specific EVPN implementation for Genie (native plugin)."""

    class DeviceAttributes(ABC):
        """Device-level EVPN attributes for ArcOS.

        Usage::

            dev_attr = Evpn.DeviceAttributes()
            dev_attr.device = device
            dev_attr.anycast_gateway_mac = "aa:bb:cc:01:02:03"
            dev_attr.df_election_time = 15
            dev_attr.duplicate_mac_window = 60
            dev_attr.duplicate_mac_threshold = 7
            dev_attr.duplicate_mac_auto_recovery_time = 5
            dev_attr.overlay_ltep_id = 0
            dev_attr.overlay_ltep_source_interface = "loopback0"
            dev_attr.esi_interfaces = {
                "bond0": {"esi": "00:01:02:03:04:05:06:07:08:09"},
            }
            dev_attr.build_config(apply=True)
        """

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build EVPN configuration for an ArcOS device.

            Generates CLI under three top-level contexts:
              1. ``evpn ...`` — global scalars
              2. ``overlay local-tunnel-endpoint <id>`` — LTEP config
              3. ``interface <name>`` — per-interface ESI
            """
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            configurations = CliConfigBuilder(unconfig=unconfig)

            if unconfig:
                self._build_unconfig_lines(configurations)
            else:
                self._build_config_lines(configurations)

            if apply:
                device = getattr(self, "device", None)
                if configurations and device is not None:
                    device.configure(str(configurations), fail_invalid=True)
            else:
                return CliConfig(
                    device=getattr(self, "device", None),
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def _build_config_lines(self, configurations):
            """Build the configuration lines (non-unconfig branch)."""

            # ========================================
            # EVPN Global Scalars
            # ========================================

            anycast_mac = getattr(self, "anycast_gateway_mac", None)
            if anycast_mac is not None:
                configurations.append_line(
                    f"evpn anycast-gateway-mac {anycast_mac}"
                )

            df_time = getattr(self, "df_election_time", None)
            if df_time is not None:
                configurations.append_line(
                    f"evpn df-election-time {df_time}"
                )

            dup_window = getattr(self, "duplicate_mac_window", None)
            if dup_window is not None:
                configurations.append_line(
                    f"evpn duplicate-mac-detection window {dup_window}"
                )

            dup_threshold = getattr(self, "duplicate_mac_threshold", None)
            if dup_threshold is not None:
                configurations.append_line(
                    f"evpn duplicate-mac-detection threshold {dup_threshold}"
                )

            dup_recovery = getattr(self, "duplicate_mac_auto_recovery_time", None)
            if dup_recovery is not None:
                configurations.append_line(
                    f"evpn duplicate-mac-detection auto-recovery-time {dup_recovery}"
                )

            # Separator after global EVPN lines
            has_evpn_globals = any([
                anycast_mac is not None,
                df_time is not None,
                dup_window is not None,
                dup_threshold is not None,
                dup_recovery is not None,
            ])
            if has_evpn_globals:
                configurations.append_line("!")

            # ========================================
            # Overlay Local Tunnel Endpoint (LTEP)
            # ========================================

            ltep_id = getattr(self, "overlay_ltep_id", None)
            if ltep_id is not None:
                ltep_source = getattr(self, "overlay_ltep_source_interface", None)

                if ltep_source is not None:
                    with configurations.submode_context(
                        f"overlay local-tunnel-endpoint {ltep_id}"
                    ):
                        configurations.append_line(
                            f"source-interface {ltep_source}"
                        )
                else:
                    configurations.append_line(
                        f"overlay local-tunnel-endpoint {ltep_id}"
                    )
                configurations.append_line("!")

            # ========================================
            # Per-Interface ESI
            # ========================================

            esi_interfaces = getattr(self, "esi_interfaces", None)
            if esi_interfaces and hasattr(esi_interfaces, "items"):
                for intf_name, intf_attrs in sorted(esi_interfaces.items()):
                    if not intf_name or intf_attrs is None:
                        continue

                    def _get(attr_name):
                        if isinstance(intf_attrs, dict):
                            return intf_attrs.get(attr_name)
                        return getattr(intf_attrs, attr_name, None)

                    esi_value = _get("esi")
                    if esi_value is not None:
                        with configurations.submode_context(
                            f"interface {intf_name}"
                        ):
                            configurations.append_line(
                                f"evpn esi {esi_value}"
                            )
                        configurations.append_line("!")

        def _build_unconfig_lines(self, configurations):
            """Build the unconfiguration lines."""

            # ========================================
            # EVPN Global Scalars
            # ========================================

            anycast_mac = getattr(self, "anycast_gateway_mac", None)
            if anycast_mac is not None:
                configurations.append_line("no evpn anycast-gateway-mac")

            df_time = getattr(self, "df_election_time", None)
            if df_time is not None:
                configurations.append_line("no evpn df-election-time")

            dup_window = getattr(self, "duplicate_mac_window", None)
            if dup_window is not None:
                configurations.append_line(
                    "no evpn duplicate-mac-detection window"
                )

            dup_threshold = getattr(self, "duplicate_mac_threshold", None)
            if dup_threshold is not None:
                configurations.append_line(
                    "no evpn duplicate-mac-detection threshold"
                )

            dup_recovery = getattr(self, "duplicate_mac_auto_recovery_time", None)
            if dup_recovery is not None:
                configurations.append_line(
                    "no evpn duplicate-mac-detection auto-recovery-time"
                )

            # ========================================
            # Overlay Local Tunnel Endpoint (LTEP)
            # ========================================

            ltep_id = getattr(self, "overlay_ltep_id", None)
            if ltep_id is not None:
                configurations.append_line(
                    f"no overlay local-tunnel-endpoint {ltep_id}"
                )

            # ========================================
            # Per-Interface ESI
            # ========================================

            esi_interfaces = getattr(self, "esi_interfaces", None)
            if esi_interfaces and hasattr(esi_interfaces, "items"):
                for intf_name, intf_attrs in sorted(esi_interfaces.items()):
                    if not intf_name or intf_attrs is None:
                        continue
                    configurations.append_line(
                        f"no interface {intf_name} evpn esi"
                    )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build unconfiguration commands for EVPN."""
            return self.build_config(
                apply=apply, attributes=attributes, unconfig=True, **kwargs
            )
