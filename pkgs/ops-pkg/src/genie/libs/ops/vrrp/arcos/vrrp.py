"""ArcOS VRRP Genie Ops Object.

Provides a Genie VRRP Ops object for Arrcus devices based on
OpenConfig JSON VRRP output parsed by
``genie.libs.parser.arcos.show_vrrp.ShowVrrp``.

There is no XR/XE VRRP ops model to mirror (XR/XE uses HSRP), so this
defines a custom ``self.info`` schema tailored to arcOS VRRP groups.

``self.info`` structure::

    info = {
        "vrrp_groups": {
            "<key>": {
                "interface": str,
                "sub_id": int,
                "group_id": int,
                "address_family": str,
                "address": str,
                "virtual_addresses": list,
                "priority": int,
                "preempt": bool,
                "accept_mode": bool,
                "state": str,
                "advertisement_interval": int,
                "version": str,
                "virtual_mac_address": str,
            }
        }
    }
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.vrrp.vrrp import Vrrp as SuperVrrp

from genie.libs.parser.arcos.show_vrrp import ShowVrrp


class Vrrp(SuperVrrp):
    """ArcOS VRRP Genie Ops Object."""

    def learn(
        self,
        interface: str = "",
        sub_id: int = 0,
        af: str = "",
        address: str = "",
        **kwargs: Any,
    ) -> None:  # type: ignore[override]
        """Learn VRRP operational state on ArcOS devices.

        On arcOS, the VRRP show command requires a specific interface.
        When ``interface`` is provided, queries that interface. When empty,
        queries with wildcards (``*``) which may not return data on all
        platforms.

        Queries both IPv4 and IPv6 when ``af`` is empty.

        Args:
            interface: Interface name (e.g. "swp1"). Empty for wildcard.
            sub_id: Subinterface ID (default: 0).
            af: Address family — "ipv4", "ipv6", or "" for both.
            address: IP address filter. Empty for wildcard.
        """
        self.info = {}
        all_groups: Dict[str, Any] = {}

        intf = interface or "*"
        addr = address or "*"

        # Query both address families when af is empty
        af_list = ["ipv4", "ipv6"] if not af else [af]

        for af_name in af_list:
            parsed = self._parse_vrrp(intf, sub_id, af_name, addr)
            if parsed:
                raw = parsed.get("vrrp-groups", {})
                all_groups.update(raw)

        if not all_groups:
            return

        groups_raw = all_groups

        vrrp_groups: Dict[str, Any] = {}

        for key, group_data in groups_raw.items():
            group_entry: Dict[str, Any] = {}

            # Interface identification
            intf = group_data.get("interface")
            if intf is not None:
                group_entry["interface"] = str(intf)

            sub = group_data.get("sub-id")
            if sub is not None:
                group_entry["sub_id"] = int(sub)

            # Group ID (virtual-router-id -> group_id)
            vrid = group_data.get("virtual-router-id")
            if vrid is not None:
                group_entry["group_id"] = int(vrid)

            # Address family (af -> address_family)
            af_val = group_data.get("af")
            if af_val is not None:
                group_entry["address_family"] = str(af_val)

            addr = group_data.get("address")
            if addr is not None:
                group_entry["address"] = str(addr)

            # Virtual addresses (virtual-address -> virtual_addresses)
            vaddrs = group_data.get("virtual-address")
            if vaddrs is not None:
                group_entry["virtual_addresses"] = list(vaddrs)

            # Priority
            priority = group_data.get("priority")
            if priority is not None:
                group_entry["priority"] = int(priority)

            # Preempt
            preempt = group_data.get("preempt")
            if preempt is not None:
                group_entry["preempt"] = bool(preempt)

            # Accept mode
            accept = group_data.get("accept-mode")
            if accept is not None:
                group_entry["accept_mode"] = bool(accept)

            # State (virtual-router-mode -> state)
            mode = group_data.get("virtual-router-mode")
            if mode is not None:
                group_entry["state"] = str(mode)

            # Advertisement interval
            adv_interval = group_data.get("advertisement-interval")
            if adv_interval is not None:
                group_entry["advertisement_interval"] = int(adv_interval)

            # Version (vrrp-version -> version)
            version = group_data.get("vrrp-version")
            if version is not None:
                group_entry["version"] = str(version)

            # Virtual MAC address
            vmac = group_data.get("virtual-mac-address")
            if vmac is not None:
                group_entry["virtual_mac_address"] = str(vmac)

            if group_entry:
                vrrp_groups[key] = group_entry

        if vrrp_groups:
            self.info = {"vrrp_groups": vrrp_groups}

    # ------------------------------------------------------------------
    # Parser helpers
    # ------------------------------------------------------------------

    def _parse_vrrp(
        self,
        interface: str,
        sub_id: int,
        af: str,
        address: str,
    ) -> Dict[str, Any]:
        """Parse VRRP output using ShowVrrp parser."""
        try:
            parser = ShowVrrp(device=self.device)
            return parser.parse(
                interface=interface,
                sub_id=sub_id,
                af=af,
                address=address,
            )
        except Exception:
            return {}
