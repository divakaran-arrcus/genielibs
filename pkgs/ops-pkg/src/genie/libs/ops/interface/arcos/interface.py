"""ArcOS Interface Genie Ops Object.

Provides a Genie Interface Ops object for Arrcus devices based on
OpenConfig JSON ``show interface`` output parsed by
``genie.libs.parser.arcos.show_interface.ShowInterface``.
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.interface.interface import Interface as SuperInterface

from genie.libs.parser.arcos.show_interface import ShowInterface


class Interface(SuperInterface):
    """ArcOS Interface Genie Ops Object."""

    def learn(self, interface: str | None = None, **kwargs: Any) -> None:  # type: ignore[override]
        """Learn interface operational state on ArcOS devices.

        Args:
            interface: Optional specific interface name. If None, learn all
                interfaces visible to the underlying parser.
        """

        parser = ShowInterface(device=self.device)
        if interface:
            parsed = parser.cli(interface=interface)
        else:
            parsed = parser.cli()

        # Ensure we always have a dict to work with
        parsed = parsed or {}

        # Reset info and rebuild according to Genie Interface schema
        self.info = {}

        for intf_name, data in parsed.items():
            if interface and intf_name != interface:
                continue

            intf_info: Dict[str, Any] = {}

            # Basic attributes (schema: description, type, oper_status,
            # last_change, phys_address, mtu, enabled, mac_address)
            intf_info["description"] = data.get("description")
            intf_info["type"] = data.get("type")
            intf_info["mtu"] = data.get("mtu")
            intf_info["enabled"] = data.get("enabled")
            intf_info["oper_status"] = data.get("oper_status")

            mac = data.get("mac_address")
            if mac is not None:
                intf_info["mac_address"] = mac
                intf_info["phys_address"] = mac

            intf_info["last_change"] = data.get("last_change")

            # Counters subtree (populate the fields we have and leave the rest absent)
            counters = data.get("counters") or {}
            if counters:
                cnt: Dict[str, Any] = {}

                if "in_octets" in counters:
                    cnt["in_octets"] = counters["in_octets"]
                if "out_octets" in counters:
                    cnt["out_octets"] = counters["out_octets"]
                if "in_unicast_pkts" in counters:
                    cnt["in_unicast_pkts"] = counters["in_unicast_pkts"]
                if "out_unicast_pkts" in counters:
                    cnt["out_unicast_pkts"] = counters["out_unicast_pkts"]
                if "in_errors" in counters:
                    cnt["in_errors"] = counters["in_errors"]
                if "out_errors" in counters:
                    cnt["out_errors"] = counters["out_errors"]

                if cnt:
                    intf_info["counters"] = cnt

            # IPv4 subtree (schema: ipv4[ip] -> {ip, prefix_length,...})
            ipv4_addrs = data.get("ipv4_addresses") or {}
            if ipv4_addrs:
                ipv4_dict: Dict[str, Dict[str, Any]] = {}
                for ip, addr_data in ipv4_addrs.items():
                    ipv4_dict[ip] = {
                        "ip": addr_data.get("ip", ip),
                        "prefix_length": addr_data.get("prefix_length"),
                    }
                if ipv4_dict:
                    intf_info["ipv4"] = ipv4_dict

            # IPv6 subtree (schema: ipv6[ip] -> {ip, prefix_length,...})
            ipv6_addrs = data.get("ipv6_addresses") or {}
            if ipv6_addrs:
                ipv6_dict: Dict[str, Dict[str, Any]] = {}
                for ip, addr_data in ipv6_addrs.items():
                    ipv6_dict[ip] = {
                        "ip": addr_data.get("ip", ip),
                        "prefix_length": addr_data.get("prefix_length"),
                    }
                if ipv6_dict:
                    intf_info["ipv6"] = ipv6_dict

            # Attach per-interface dictionary under top-level 'interface' key
            # following the base Interface Ops schema.
            self.info.setdefault("interface", {}).setdefault("info", {})[
                intf_name
            ] = intf_info
