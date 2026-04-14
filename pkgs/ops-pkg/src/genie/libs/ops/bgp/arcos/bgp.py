"""ArcOS BGP Genie Ops Object.

Provides a Genie BGP Ops object for Arrcus devices based on
OpenConfig JSON parser output. The ``self.info`` structure matches
the IOS-XE/XR BGP Ops schema for cross-platform ``learn()``/``diff()``.

Parsers used:
    - ShowBgpGlobalState — AS, router-id, cluster-id, total paths/prefixes
    - ShowBgpGlobalAfiSafi — per-AFI totals (paths, prefixes, received/sent)
    - ShowBgpNeighbor — session state, peer-as, transport, messages, AFI-SAFIs
    - ShowBgpRibRoute — loc-RIB routes with path attributes
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from genie.libs.ops.bgp.bgp import Bgp as SuperBgp

from genie.libs.parser.arcos.show_bgp import (
    ShowBgpGlobalState,
    ShowBgpGlobalAfiSafi,
    ShowBgpNeighbor,
    ShowBgpRibRoute,
)


class Bgp(SuperBgp):
    """ArcOS BGP Genie Ops Object.

    ``self.info`` follows the IOS-XE/XR schema::

        info[instance][default]
            ├─ bgp_id
            └─ vrf[<vrf>]
                ├─ cluster_id, router_id
                ├─ address_family[<af>]
                │   ├─ total_paths, total_prefixes
                │   └─ prefixes[<prefix>] (from RIB)
                └─ neighbor[<addr>]
                    ├─ session_state, remote_as, local_as
                    ├─ description, shutdown
                    ├─ bgp_negotiated_capabilities
                    ├─ transport
                    └─ address_family[<af>].enabled
    """

    def learn(self, vrf: str = "default", instance: str = "default",
              address_family: str = "", neighbor: str = "",
              **kwargs: Any) -> None:  # type: ignore[override]
        """Learn BGP operational state on ArcOS devices.

        Args:
            vrf: Network-instance / VRF name (default: "default").
            instance: BGP protocol instance name (default: "default").
            address_family: Optional AF filter (e.g. "IPV4_UNICAST").
            neighbor: Optional neighbor address filter.
        """
        self.info = {}

        inst_dict: Dict[str, Any] = {}

        # --- Section 1: Global state ---
        global_data = self._parse_global(vrf, instance)
        if global_data:
            as_num = global_data.get("as")
            if as_num is not None:
                inst_dict["bgp_id"] = int(as_num)

        # --- Section 2: VRF-level data ---
        vrf_dict: Dict[str, Any] = {}

        if global_data:
            rid = global_data.get("router-id")
            if rid:
                vrf_dict["router_id"] = rid
            cid = global_data.get("cluster-id")
            if cid:
                vrf_dict["cluster_id"] = cid

        # --- Section 3: Address families ---
        afi_data = self._parse_afi_safi(vrf, instance)
        if afi_data:
            af_dict: Dict[str, Any] = {}
            for af_name, af_info in afi_data.items():
                if address_family and af_name != address_family:
                    continue
                af_entry: Dict[str, Any] = {}

                tp = af_info.get("total-paths")
                if tp is not None:
                    af_entry["total_paths"] = int(tp)
                tpfx = af_info.get("total-prefixes")
                if tpfx is not None:
                    af_entry["total_prefixes"] = int(tpfx)

                if af_entry:
                    af_dict[_map_afi_name(af_name)] = af_entry

            if af_dict:
                vrf_dict["address_family"] = af_dict

        # --- Section 4: Neighbors ---
        nbr_data = self._parse_neighbors(vrf, instance, neighbor)
        if nbr_data:
            nbr_dict: Dict[str, Any] = {}
            for addr, n in nbr_data.items():
                nbr_entry: Dict[str, Any] = {}

                state = n.get("session-state")
                if state:
                    nbr_entry["session_state"] = _map_session_state(state)

                remote_as = n.get("peer-as")
                if remote_as is not None:
                    nbr_entry["remote_as"] = int(remote_as)

                local_as = n.get("local-as")
                if local_as is not None:
                    nbr_entry["local_as"] = int(local_as)

                desc = n.get("description")
                if desc:
                    nbr_entry["description"] = desc

                shut = n.get("shutdown")
                if shut is not None:
                    nbr_entry["shutdown"] = shut

                peer_group = n.get("peer-group")
                if peer_group:
                    nbr_entry["bgp_peer_group"] = peer_group

                # Transport
                transport = n.get("transport")
                if transport:
                    t_dict: Dict[str, Any] = {}
                    for tk, ok in (
                        ("local-address", "local_host"),
                        ("local-port", "local_port"),
                        ("remote-address", "foreign_host"),
                        ("remote-port", "foreign_port"),
                    ):
                        v = transport.get(tk)
                        if v is not None:
                            t_dict[ok] = v
                    if t_dict:
                        nbr_entry["bgp_session_transport"] = {
                            "connection": t_dict,
                        }

                # Messages
                msgs_sent = n.get("messages-sent")
                msgs_rcvd = n.get("messages-received")
                if msgs_sent or msgs_rcvd:
                    nbr_entry["bgp_neighbor_counters"] = {
                        "messages": {}
                    }
                    if msgs_sent:
                        sent: Dict[str, Any] = {}
                        for mk, mv in msgs_sent.items():
                            sent[mk.lower()] = int(mv) if mv is not None else 0
                        nbr_entry["bgp_neighbor_counters"]["messages"]["sent"] = sent
                    if msgs_rcvd:
                        rcvd: Dict[str, Any] = {}
                        for mk, mv in msgs_rcvd.items():
                            rcvd[mk.lower()] = int(mv) if mv is not None else 0
                        nbr_entry["bgp_neighbor_counters"]["messages"]["received"] = rcvd

                # Per-neighbor AFI-SAFIs
                nbr_afis = n.get("afi-safis") or []
                if nbr_afis:
                    nbr_af_dict: Dict[str, Any] = {}
                    for afi in nbr_afis:
                        nbr_af_dict[_map_afi_name(afi)] = {"enabled": True}
                    if nbr_af_dict:
                        nbr_entry["address_family"] = nbr_af_dict

                if nbr_entry:
                    nbr_dict[addr] = nbr_entry

            if nbr_dict:
                vrf_dict["neighbor"] = nbr_dict

        # --- Section 5: Routes (optional, only if AF specified) ---
        if address_family:
            routes = self._parse_routes(vrf, instance, address_family)
            if routes:
                af_key = _map_afi_name(address_family)
                af_entry = vrf_dict.setdefault(
                    "address_family", {}
                ).setdefault(af_key, {})

                prefixes: Dict[str, Any] = {}
                for prefix, route_data in routes.items():
                    prefix_entry: Dict[str, Any] = {}
                    paths = route_data.get("paths") or []
                    if paths:
                        index_dict: Dict[str, Any] = {}
                        for idx, path in enumerate(paths):
                            path_entry: Dict[str, Any] = {}
                            nh = path.get("next-hop")
                            if nh is not None:
                                path_entry["next_hop"] = str(nh)
                            origin = path.get("origin")
                            if origin:
                                path_entry["origin_codes"] = origin
                            if path_entry:
                                index_dict[str(idx)] = path_entry
                        if index_dict:
                            prefix_entry["index"] = index_dict
                    if prefix_entry:
                        prefixes[prefix] = prefix_entry

                if prefixes:
                    af_entry["prefixes"] = prefixes

        # --- Assemble full hierarchy ---
        if vrf_dict:
            inst_dict.setdefault("vrf", {})[vrf] = vrf_dict

        if inst_dict:
            self.info = {"instance": {"default": inst_dict}}

    # ------------------------------------------------------------------
    # Parser helpers
    # ------------------------------------------------------------------

    def _parse_global(self, ni: str, pi: str) -> Dict[str, Any]:
        try:
            parser = ShowBgpGlobalState(device=self.device)
            return parser.parse(network_instance=ni, protocol_instance=pi)
        except Exception:
            return {}

    def _parse_afi_safi(self, ni: str, pi: str) -> Dict[str, Any]:
        try:
            parser = ShowBgpGlobalAfiSafi(device=self.device)
            result = parser.parse(network_instance=ni, protocol_instance=pi)
            return result.get("afi-safis", {})
        except Exception:
            return {}

    def _parse_neighbors(
        self, ni: str, pi: str, neighbor: str = "",
    ) -> Dict[str, Any]:
        try:
            parser = ShowBgpNeighbor(device=self.device)
            if neighbor:
                result = parser.parse(
                    network_instance=ni, protocol_instance=pi,
                    neighbor=neighbor,
                )
            else:
                result = parser.parse(
                    network_instance=ni, protocol_instance=pi,
                )
            return result.get("neighbors", {})
        except Exception:
            return {}

    def _parse_routes(
        self, ni: str, pi: str, afi_safi: str,
    ) -> Dict[str, Any]:
        try:
            parser = ShowBgpRibRoute(device=self.device)
            result = parser.parse(
                network_instance=ni, protocol_instance=pi,
                afi_safi=afi_safi,
            )
            return result.get("routes", {})
        except Exception:
            return {}


# ------------------------------------------------------------------
# Static mapping helpers
# ------------------------------------------------------------------

def _map_afi_name(raw: str) -> str:
    """Map arcOS AFI name to XR/XE ops-schema AF name.

    Examples:
        IPV4_UNICAST → ipv4 unicast
        IPV6_UNICAST → ipv6 unicast
        L2VPN_EVPN → l2vpn evpn
    """
    return raw.lower().replace("_", " ")


def _map_session_state(raw: str) -> str:
    """Map arcOS session state to XR/XE ops-schema value.

    arcOS: ESTABLISHED, ACTIVE, IDLE, CONNECT, OPENCONFIRM, OPENSENT
    XR/XE: Established, Active, Idle, Connect, OpenConfirm, OpenSent
    """
    mapping = {
        "ESTABLISHED": "Established",
        "ACTIVE": "Active",
        "IDLE": "Idle",
        "CONNECT": "Connect",
        "OPENCONFIRM": "OpenConfirm",
        "OPENSENT": "OpenSent",
    }
    return mapping.get(raw, raw.capitalize() if raw else "")
