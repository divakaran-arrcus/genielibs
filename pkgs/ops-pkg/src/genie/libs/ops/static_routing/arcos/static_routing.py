"""ArcOS Static Routing Genie Ops Object.

Provides a Genie Static Routing Ops object for Arrcus devices based on
OpenConfig JSON parser output. The ``self.info`` structure matches
the IOS-XE/XR Static Routing Ops schema for cross-platform
``learn()``/``diff()``.

Parser used:
    - ShowStaticRoutingConfig — static routes with next-hops, preferences,
      interfaces, metrics, labels
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.static_routing.static_routing import (
    StaticRouting as SuperStaticRouting,
)

from genie.libs.parser.arcos.show_static_routing import ShowStaticRoutingConfig


class StaticRouting(SuperStaticRouting):
    """ArcOS Static Routing Genie Ops Object.

    ``self.info`` follows the IOS-XE/XR schema::

        info[vrf][<vrf>][address_family][<af>][routes][<prefix>]
            ├─ route (prefix string)
            └─ next_hop
                ├─ outgoing_interface[<intf>].{outgoing_interface, preference}
                └─ next_hop_list[<index>].{index, next_hop, outgoing_interface, preference}
    """

    def learn(self, vrf: str = "default",
              **kwargs: Any) -> None:  # type: ignore[override]
        """Learn static routing operational state on ArcOS devices.

        Args:
            vrf: Network-instance / VRF name (default: "default").
        """
        self.info = {}

        parsed = self._parse_static_routes(vrf)
        if not parsed:
            return

        ni_data = parsed.get("network-instances", {}).get(vrf, {})
        protocols = ni_data.get("protocols", {})

        for pi_name, pi_data in protocols.items():
            static_routes = pi_data.get("static-routes", {})
            if not static_routes:
                continue

            for prefix, route_data in static_routes.items():
                af = _detect_af(prefix)

                # Build XE-compatible route entry
                route_entry: Dict[str, Any] = {
                    "route": prefix,
                }

                next_hops = route_data.get("next-hops", {})
                if next_hops:
                    nh_info = self._map_next_hops(next_hops)
                    if nh_info:
                        route_entry["next_hop"] = nh_info

                # Place in hierarchy: info[vrf][<vrf>][address_family][<af>][routes][<prefix>]
                (
                    self.info
                    .setdefault("vrf", {})
                    .setdefault(vrf, {})
                    .setdefault("address_family", {})
                    .setdefault(af, {})
                    .setdefault("routes", {})
                )[prefix] = route_entry

    # ------------------------------------------------------------------
    # Parser helper
    # ------------------------------------------------------------------

    def _parse_static_routes(self, ni: str) -> Dict[str, Any]:
        try:
            parser = ShowStaticRoutingConfig(device=self.device)
            return parser.parse(network_instance=ni)
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Next-hop mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _map_next_hops(next_hops: Dict[str, Any]) -> Dict[str, Any]:
        """Map arcOS next-hops to XE schema.

        XE schema has two sub-dicts:
        - outgoing_interface[<intf>] — for interface-only routes
        - next_hop_list[<index>] — for routes with a next-hop IP

        arcOS stores all next-hops under index keys with optional
        next-hop, interface, metric, etc.
        """
        result: Dict[str, Any] = {}
        intf_dict: Dict[str, Any] = {}
        hop_dict: Dict[str, Any] = {}

        for idx, nh_data in next_hops.items():
            nh_addr = nh_data.get("next-hop")
            intf = nh_data.get("interface")
            pref = nh_data.get("preference") or nh_data.get("metric")

            # Strip namespace prefix (e.g. "openconfig-local-routing:DROP" → "DROP")
            # but NOT IPv6 addresses (which also contain ":")
            if nh_addr and nh_addr.startswith("openconfig-"):
                nh_addr = nh_addr.split(":")[-1]

            if nh_addr and nh_addr.upper() != "DROP":
                # next_hop_list entry
                entry: Dict[str, Any] = {"index": idx}
                entry["next_hop"] = nh_addr
                if intf:
                    entry["outgoing_interface"] = intf
                entry["active"] = True
                if pref is not None:
                    entry["preference"] = pref
                hop_dict[idx] = entry
            elif intf:
                # outgoing_interface entry (no next-hop IP)
                entry = {"outgoing_interface": intf}
                entry["active"] = True
                if pref is not None:
                    entry["preference"] = pref
                intf_dict[intf] = entry
            elif nh_addr and nh_addr.upper() == "DROP":
                # Drop route
                entry = {"index": idx, "next_hop": "DROP", "active": True}
                hop_dict[idx] = entry

        if intf_dict:
            result["outgoing_interface"] = intf_dict
        if hop_dict:
            result["next_hop_list"] = hop_dict

        return result


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _detect_af(prefix: str) -> str:
    """Detect address family from prefix string."""
    if ":" in prefix:
        return "ipv6"
    return "ipv4"
