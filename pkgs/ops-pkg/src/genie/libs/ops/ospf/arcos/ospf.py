"""ArcOS OSPF Genie Ops Object.

Provides a Genie OSPF Ops object for Arrcus devices based on
OpenConfig JSON parser output. The ``self.info`` structure matches
the IOS-XE/XR OSPF Ops schema for cross-platform ``learn()``/``diff()``.

Supports both OSPFv2 (address_family: ipv4) and OSPFv3 (address_family: ipv6)
in a single ops model, matching the XR/XE approach where ``device.learn('ospf')``
returns both v2 and v3 data.

Parsers used:
    OSPFv2:
    - ShowOspfGlobal — router-id, ABR/ASBR flags
    - ShowOspfSpfThrottle — SPF timer values
    - ShowOspfArea — area type, stub cost, neighbor/interface counts
    - ShowOspfInterface — network-type, metric, passive, interface state
    - ShowOspfNeighbor — neighbor RID, IP, adjacency state, timestamps
    - ShowOspfLsdb — LSA types, router/summary LSA bodies
    - ShowNetworkInstance — table-connections (redistribution)

    OSPFv3:
    - ShowOspfv3Global — router-id, ABR/ASBR flags (IPv6)
    - ShowOspfv3Neighbor — neighbor RID, IP, adjacency state (IPv6)
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.ospf.ospf import Ospf as SuperOspf

from genie.libs.parser.arcos.show_ospf import (
    ShowOspfGlobal,
    ShowOspfNeighbor,
    ShowOspfArea,
    ShowOspfInterface,
    ShowOspfSpfThrottle,
    ShowOspfLsdb,
    ShowOspfRunningConfig,
)
from genie.libs.parser.arcos.show_network_instance import ShowNetworkInstance
from genie.libs.parser.arcos.show_ospfv3 import (
    ShowOspfv3Global,
    ShowOspfv3Neighbor,
)


class Ospf(SuperOspf):
    """ArcOS OSPF Genie Ops Object (OSPFv2 + OSPFv3).

    ``self.info`` follows the IOS-XE/XR schema::

        info[vrf][<vrf>][address_family]
            ├─ [ipv4][instance][<instance>]  ← OSPFv2
            │   ├─ router_id
            │   ├─ spf_control.throttle.spf.{start,hold,maximum}
            │   ├─ redistribution[<protocol>].enabled
            │   └─ areas[<area_id>]
            │       ├─ area_id, area_type, default_cost, statistics
            │       ├─ database.lsa_types[<type>].lsas[<lsa>]
            │       └─ interfaces[<intf>].neighbors[<rid>]
            └─ [ipv6][instance][<instance>]  ← OSPFv3
                ├─ router_id
                └─ areas[<area_id>]
                    └─ interfaces[<intf>].neighbors[<rid>]
    """

    def learn(self, vrf: str = "default", instance: str = "default",
              **kwargs: Any) -> None:  # type: ignore[override]
        """Learn OSPF operational state on ArcOS devices.

        Args:
            vrf: Network-instance / VRF name (default: "default").
            instance: OSPF protocol instance name (default: "default").
        """
        self.info = {}

        # Build the XR/XE-compatible hierarchy
        inst_dict: Dict[str, Any] = {}

        # --- Section 1: Global state ---
        global_data = self._parse_global()
        if global_data:
            rid = global_data.get("router-id")
            if rid:
                inst_dict["router_id"] = rid

        # --- Section 2: SPF throttle timers ---
        spf_data = self._parse_spf_throttle()
        if spf_data:
            spf_timers: Dict[str, Any] = {}
            v = spf_data.get("spf-initial-delay")
            if v is not None:
                spf_timers["start"] = v
            v = spf_data.get("spf-short-delay")
            if v is not None:
                spf_timers["hold"] = v
            v = spf_data.get("spf-long-delay")
            if v is not None:
                spf_timers["maximum"] = v
            if spf_timers:
                inst_dict.setdefault("spf_control", {}).setdefault(
                    "throttle", {}
                )["spf"] = spf_timers

        # --- Section 3: Running config (route-preference, interface timers) ---
        run_cfg = self._parse_running_config()
        if run_cfg:
            rp = run_cfg.get("global", {}).get("route-preference", {})
            if rp:
                pref_dict: Dict[str, Any] = {}
                intra = rp.get("intra-area")
                if intra is not None:
                    pref_dict.setdefault("single_value", {})["all"] = intra
                    pref_dict.setdefault("multi_values", {}).setdefault(
                        "granularity", {}
                    ).setdefault("detail", {})["intra_area"] = intra
                inter = rp.get("inter-area")
                if inter is not None:
                    pref_dict.setdefault("multi_values", {}).setdefault(
                        "granularity", {}
                    ).setdefault("detail", {})["inter_area"] = inter
                ext = rp.get("external")
                if ext is not None:
                    pref_dict.setdefault("multi_values", {})["external"] = ext
                if pref_dict:
                    inst_dict["preference"] = pref_dict

        # --- Section 4: Redistribution from table-connections ---
        redistribution = self._parse_redistribution(vrf)
        if redistribution:
            inst_dict["redistribution"] = redistribution

        # --- Section 4: Areas ---
        area_state = self._parse_areas()
        intf_state = self._parse_interfaces()
        nbr_state = self._parse_neighbors()
        lsdb_state = self._parse_lsdb()

        areas_dict: Dict[str, Any] = {}

        # Merge area IDs from all sources
        all_area_ids = set()
        all_area_ids.update(area_state.keys())
        all_area_ids.update(intf_state.keys())
        all_area_ids.update(nbr_state.keys())
        all_area_ids.update(lsdb_state.keys())

        for area_id in sorted(all_area_ids):
            area_entry: Dict[str, Any] = {"area_id": area_id}

            # Area-level fields
            a_data = area_state.get(area_id, {})
            area_type = a_data.get("area-type")
            if area_type:
                area_entry["area_type"] = _map_area_type(area_type)

            default_cost = a_data.get("stub-default-cost")
            if default_cost is not None:
                area_entry["default_cost"] = default_cost

            # Area statistics
            stats: Dict[str, Any] = {}
            for sk in ("configured-interface-count", "up-interface-count",
                       "neighbor-count", "full-neighbor-count"):
                v = a_data.get(sk)
                if v is not None:
                    stats[sk.replace("-", "_")] = v
            if stats:
                area_entry["statistics"] = stats

            # Interfaces within this area
            intfs_data = intf_state.get(area_id, {}).get("interfaces", {})
            if intfs_data:
                interfaces_dict: Dict[str, Any] = {}
                for intf_name, i_data in intfs_data.items():
                    intf_entry: Dict[str, Any] = {"name": intf_name}

                    net_type = i_data.get("network-type")
                    if net_type:
                        intf_entry["interface_type"] = _map_network_type(
                            net_type
                        )

                    passive = i_data.get("passive")
                    if passive is not None:
                        intf_entry["passive"] = passive

                    metric = i_data.get("metric")
                    if metric is not None:
                        intf_entry["cost"] = metric

                    enable = i_data.get("interface-up")
                    if enable is not None:
                        intf_entry["enable"] = enable

                    # Merge timers from running-config (not in operational state)
                    if run_cfg:
                        rc_areas = run_cfg.get("areas", {})
                        rc_intfs = rc_areas.get(area_id, {}).get(
                            "interfaces", {}
                        )
                        rc_intf = rc_intfs.get(intf_name, {})
                        hi = rc_intf.get("hello-interval")
                        if hi is not None:
                            intf_entry["hello_interval"] = hi
                        di = rc_intf.get("dead-interval")
                        if di is not None:
                            intf_entry["dead_interval"] = di

                    # Neighbors on this interface
                    intf_nbrs = nbr_state.get(area_id, {}).get(
                        intf_name, {}
                    )
                    if intf_nbrs:
                        neighbors_dict: Dict[str, Any] = {}
                        for nbr_rid, nbr_data in intf_nbrs.items():
                            nbr_entry: Dict[str, Any] = {
                                "neighbor_router_id": nbr_rid,
                            }
                            addr = nbr_data.get("neighbor-ip-address")
                            if addr:
                                nbr_entry["address"] = addr
                            neighbors_dict[nbr_rid] = nbr_entry
                        if neighbors_dict:
                            intf_entry["neighbors"] = neighbors_dict

                    interfaces_dict[intf_name] = intf_entry

                if interfaces_dict:
                    area_entry["interfaces"] = interfaces_dict

            # LSDB for this area
            lsdb_data = lsdb_state.get(area_id, {}).get("lsa-types", {})
            if lsdb_data:
                lsa_types_dict: Dict[str, Any] = {}
                for lsa_type_name, lt_data in lsdb_data.items():
                    lt_entry: Dict[str, Any] = {"lsa_type": lsa_type_name}
                    lsas_raw = lt_data.get("lsas", {})
                    if lsas_raw:
                        lsas_dict: Dict[str, Any] = {}
                        for lsa_key, lsa_data in lsas_raw.items():
                            lsa_entry: Dict[str, Any] = {}

                            # Header
                            lsa_id = lsa_data.get("link-state-id")
                            if lsa_id:
                                lsa_entry["lsa_id"] = lsa_id
                            adv = lsa_data.get("advertising-router")
                            if adv:
                                lsa_entry["adv_router"] = adv

                            header: Dict[str, Any] = {}
                            for hk, ok in (
                                ("age", "age"),
                                ("sequence-number", "seq_num"),
                                ("checksum", "checksum"),
                                ("link-state-id", "lsa_id"),
                                ("advertising-router", "adv_router"),
                            ):
                                v = lsa_data.get(hk)
                                if v is not None:
                                    header[ok] = v
                            if header:
                                lsa_entry.setdefault("ospfv2", {})[
                                    "header"
                                ] = header

                            # Router LSA body
                            rlsa = lsa_data.get("router-lsa", {})
                            if rlsa:
                                body_router: Dict[str, Any] = {}
                                flags = rlsa.get("flags")
                                if flags:
                                    body_router["flags"] = flags
                                nl = rlsa.get("num-links")
                                if nl is not None:
                                    body_router["num_of_links"] = nl

                                links = rlsa.get("links", {})
                                if links:
                                    links_out: Dict[str, Any] = {}
                                    for lidx, lnk in links.items():
                                        link_entry: Dict[str, Any] = {}
                                        for lk, ok in (
                                            ("link-id", "link_id"),
                                            ("link-data", "link_data"),
                                            ("type", "type"),
                                        ):
                                            v = lnk.get(lk)
                                            if v is not None:
                                                link_entry[ok] = v
                                        topo = lnk.get("metric")
                                        if topo is not None:
                                            link_entry.setdefault(
                                                "topologies", {}
                                            ).setdefault("0", {})[
                                                "metric"
                                            ] = topo
                                        if link_entry:
                                            links_out[lidx] = link_entry
                                    if links_out:
                                        body_router["links"] = links_out

                                if body_router:
                                    lsa_entry.setdefault("ospfv2", {})[
                                        "body"
                                    ] = {"router": body_router}

                            # Summary LSA body
                            slsa = lsa_data.get("summary-lsa", {})
                            if slsa:
                                body_summary: Dict[str, Any] = {}
                                nm = slsa.get("network-mask")
                                if nm is not None:
                                    body_summary["network_mask"] = nm
                                mt = slsa.get("metric")
                                if mt is not None:
                                    body_summary.setdefault(
                                        "topologies", {}
                                    ).setdefault("0", {})["metric"] = mt
                                if body_summary:
                                    lsa_entry.setdefault("ospfv2", {})[
                                        "body"
                                    ] = {"summary": body_summary}

                            if lsa_entry:
                                lsas_dict[lsa_key] = lsa_entry

                        if lsas_dict:
                            lt_entry["lsas"] = lsas_dict

                    lsa_types_dict[lsa_type_name] = lt_entry

                if lsa_types_dict:
                    area_entry.setdefault("database", {})[
                        "lsa_types"
                    ] = lsa_types_dict

            areas_dict[area_id] = area_entry

        if areas_dict:
            inst_dict["areas"] = areas_dict

        # --- Merge running-config-only areas/interfaces ---
        if run_cfg:
            for rc_aid, rc_adata in run_cfg.get("areas", {}).items():
                area_entry = areas_dict.setdefault(rc_aid, {"area_id": rc_aid})

                # Area type from running-config if not already set
                if "area_type" not in area_entry:
                    rc_type = rc_adata.get("area-type")
                    if rc_type:
                        area_entry["area_type"] = _map_area_type(rc_type)

                rc_intfs = rc_adata.get("interfaces", {})
                if rc_intfs:
                    intfs_dict = area_entry.setdefault("interfaces", {})
                    for intf_name, rc_idata in rc_intfs.items():
                        intf_entry = intfs_dict.setdefault(
                            intf_name, {"name": intf_name}
                        )
                        # Add timers if not already present
                        hi = rc_idata.get("hello-interval")
                        if hi is not None and "hello_interval" not in intf_entry:
                            intf_entry["hello_interval"] = hi
                        di = rc_idata.get("dead-interval")
                        if di is not None and "dead_interval" not in intf_entry:
                            intf_entry["dead_interval"] = di
                        nt = rc_idata.get("network-type")
                        if nt and "interface_type" not in intf_entry:
                            intf_entry["interface_type"] = _map_network_type(nt)

        # --- OSPFv3 (address_family: ipv6) ---
        v3_inst_dict = self._build_ospfv3_instance(vrf)

        # Assemble the full XR/XE hierarchy
        af_dict: Dict[str, Any] = {}
        if inst_dict:
            af_dict["ipv4"] = {"instance": {instance: inst_dict}}
        if v3_inst_dict:
            af_dict["ipv6"] = {"instance": {instance: v3_inst_dict}}

        if af_dict:
            self.info = {
                "vrf": {
                    vrf: {
                        "address_family": af_dict,
                    }
                }
            }

    # ------------------------------------------------------------------
    # Parser helpers (instance methods — access self.device)
    # ------------------------------------------------------------------

    def _parse_global(self) -> Dict[str, Any]:
        try:
            parser = ShowOspfGlobal(device=self.device)
            return parser.parse()
        except Exception:
            return {}

    def _parse_spf_throttle(self) -> Dict[str, Any]:
        try:
            parser = ShowOspfSpfThrottle(device=self.device)
            return parser.parse()
        except Exception:
            return {}

    def _parse_areas(self) -> Dict[str, Any]:
        try:
            parser = ShowOspfArea(device=self.device)
            result = parser.parse()
            return result.get("areas", {})
        except Exception:
            return {}

    def _parse_interfaces(self) -> Dict[str, Any]:
        try:
            parser = ShowOspfInterface(device=self.device)
            result = parser.parse()
            return result.get("areas", {})
        except Exception:
            return {}

    def _parse_neighbors(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Parse neighbors and reorganize by area → interface → neighbor.

        Returns:
            {area_id: {interface: {neighbor_rid: {fields...}}}}
        """
        try:
            parser = ShowOspfNeighbor(device=self.device)
            result = parser.parse()
            raw = result.get("neighbors", {})
        except Exception:
            return {}

        organized: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for key, nbr in raw.items():
            area_id = str(nbr.get("area", 0))
            intf = nbr.get("interface", "")
            rid = nbr.get("neighbor-router-id", "")
            if not rid:
                continue
            organized.setdefault(area_id, {}).setdefault(
                intf, {}
            )[rid] = nbr

        return organized

    def _parse_lsdb(self) -> Dict[str, Any]:
        try:
            parser = ShowOspfLsdb(device=self.device)
            result = parser.parse()
            return result.get("areas", {})
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # OSPFv3 builder
    # ------------------------------------------------------------------

    def _build_ospfv3_instance(self, vrf: str) -> Dict[str, Any]:
        """Build the OSPFv3 instance dict (address_family: ipv6).

        Returns an instance dict matching the same XR/XE schema as
        OSPFv2 but populated from ShowOspfv3* parsers.
        """
        inst: Dict[str, Any] = {}

        # Global state
        v3_global = self._parse_v3_global()
        if v3_global:
            rid = v3_global.get("router-id")
            if rid:
                inst["router_id"] = rid

        # Neighbors (reorganized by area → interface → rid)
        v3_nbrs = self._parse_v3_neighbors()

        # Build areas from neighbor data
        if v3_nbrs:
            areas_dict: Dict[str, Any] = {}
            for area_id, intfs in v3_nbrs.items():
                area_entry: Dict[str, Any] = {"area_id": area_id}
                interfaces_dict: Dict[str, Any] = {}

                for intf_name, nbrs in intfs.items():
                    intf_entry: Dict[str, Any] = {"name": intf_name}
                    neighbors_dict: Dict[str, Any] = {}
                    for nbr_rid, nbr_data in nbrs.items():
                        nbr_entry: Dict[str, Any] = {
                            "neighbor_router_id": nbr_rid,
                        }
                        addr = nbr_data.get("neighbor-ip-address")
                        if addr:
                            nbr_entry["address"] = addr
                        neighbors_dict[nbr_rid] = nbr_entry

                    if neighbors_dict:
                        intf_entry["neighbors"] = neighbors_dict
                    interfaces_dict[intf_name] = intf_entry

                if interfaces_dict:
                    area_entry["interfaces"] = interfaces_dict
                areas_dict[area_id] = area_entry

            if areas_dict:
                inst["areas"] = areas_dict

        return inst

    # ------------------------------------------------------------------
    # OSPFv3 parser helpers
    # ------------------------------------------------------------------

    def _parse_v3_global(self) -> Dict[str, Any]:
        try:
            parser = ShowOspfv3Global(device=self.device)
            return parser.parse()
        except Exception:
            return {}

    def _parse_v3_neighbors(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Parse OSPFv3 neighbors, reorganized by area → interface → rid."""
        try:
            parser = ShowOspfv3Neighbor(device=self.device)
            result = parser.parse()
            raw = result.get("neighbors", {})
        except Exception:
            return {}

        organized: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for key, nbr in raw.items():
            area_id = str(nbr.get("area", 0))
            intf = nbr.get("interface", "")
            rid = nbr.get("neighbor-router-id", "")
            if not rid:
                continue
            organized.setdefault(area_id, {}).setdefault(
                intf, {}
            )[rid] = nbr

        return organized

    def _parse_running_config(self) -> Dict[str, Any]:
        try:
            parser = ShowOspfRunningConfig(device=self.device)
            return parser.parse()
        except Exception:
            return {}

    def _parse_redistribution(
        self, ni: str = "default",
    ) -> Dict[str, Any]:
        """Extract OSPF redistribution from network-instance table-connections.

        Filters table-connections where dst-protocol is OSPF.
        """
        try:
            parser = ShowNetworkInstance(device=self.device)
            result = parser.parse(network_instance=ni)
            ni_data = result.get("network-instances", {}).get(ni, {})
            tc_list = ni_data.get("table-connections", [])
        except Exception:
            return {}

        redistribution: Dict[str, Any] = {}
        for tc in tc_list:
            dst = tc.get("dst-protocol", "")
            if "OSPF" not in dst.upper():
                continue
            src = tc.get("src-protocol", "")
            if src:
                redistribution[src.lower()] = {"enabled": True}

        return redistribution


# ------------------------------------------------------------------
# Static mapping helpers
# ------------------------------------------------------------------

def _map_area_type(raw: str) -> str:
    """Map arcOS area type to XR/XE ops schema value."""
    mapping = {
        "AREA_TYPE_NORMAL": "normal",
        "AREA_TYPE_STUB": "stub",
        "AREA_TYPE_NSSA": "nssa",
    }
    return mapping.get(raw, raw.lower() if raw else "normal")


def _map_network_type(raw: str) -> str:
    """Map arcOS OSPF network type to XR/XE ops schema value."""
    mapping = {
        "POINT_TO_POINT_NETWORK": "point-to-point",
        "BROADCAST_NETWORK": "broadcast",
        "NBMA_NETWORK": "non-broadcast",
        "POINT_TO_MULTIPOINT_NETWORK": "point-to-multipoint",
    }
    return mapping.get(raw, raw.lower() if raw else "broadcast")
