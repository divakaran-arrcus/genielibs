"""ArcOS ISIS Genie Ops Object.

Provides a Genie ISIS Ops object for Arrcus devices based on
OpenConfig JSON "show isis ..." outputs.

This implementation mirrors the IOS-XR ISIS Ops data model
(:class:`genie.libs.ops.isis.iosxr.isis.Isis`) as closely as
practical for the following sections:

- Global / instance / VRF info
- Interfaces and their ISIS state
- Adjacencies (XR-style nesting)
- LSDB (LSP database)
- Routes (per-AF prefixes)
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from genie.libs.ops.isis.isis import Isis as SuperIsis


class Isis(SuperIsis):
    """ArcOS ISIS Genie Ops Object."""

    def learn(
        self,
        instance: str = "default",
        vrf: str = "default",
        address_families: Tuple[str, ...] = ("ipv4", "ipv6"),
        **kwargs: Any,
    ) -> None:  # type: ignore[override]
        """Learn ISIS operational state on ArcOS devices.

        Args:
            instance: ISIS instance name (default: "default").
            vrf: VRF / network-instance name (default: "default").
            address_families: Address-families for which to collect
                route information (currently "ipv4" and/or "ipv6").
        """

        # ------------------------------------------------------------------
        # Global / instance / VRF
        # ------------------------------------------------------------------
        global_state = self._get_isis_global(instance=instance)

        system_id = global_state.get("system_id")
        area_address = global_state.get("area_address") or global_state.get(
            "area-address"
        )

        # Initialize top-level info structure following IOS-XR Ops layout
        self.info = {"instance": {}}
        inst_dict: Dict[str, Any] = self.info["instance"].setdefault(instance, {})
        inst_dict["process_id"] = instance

        vrf_dict: Dict[str, Any] = inst_dict.setdefault("vrf", {}).setdefault(vrf, {})
        vrf_dict["vrf"] = vrf
        if system_id is not None:
            vrf_dict["system_id"] = system_id
        if area_address:
            vrf_dict["area_address"] = area_address

        # Consider ISIS enabled if we have a system-id
        vrf_dict["enable"] = bool(system_id)

        # ------------------------------------------------------------------
        # Interfaces (show isis interface)
        # ------------------------------------------------------------------
        try:
            parsed_intf = self.device.parse("show isis interface")
            ni_root = parsed_intf.get("network-instance", {}).get("default", {})
            isis_root = ni_root.get("isis", {})
            inst_root = isis_root.get(instance, {})
            interfaces = inst_root.get("interfaces", {}) or {}
        except Exception:
            interfaces = {}

        vrf_intf_dict: Dict[str, Any] = vrf_dict.setdefault("interfaces", {})

        for if_name, if_data in interfaces.items():
            intf_entry: Dict[str, Any] = {}
            intf_entry["name"] = if_name

            # Level type (LEVEL_1, LEVEL_2, LEVEL_1_2 -> level-1-only, etc.)
            circuit_type = if_data.get("circuit-type")
            if circuit_type:
                intf_entry["level_type"] = self._map_circuit_type(circuit_type)

            # Interface type (POINT_TO_POINT, LOOPBACK, etc.)
            if_type = if_data.get("network-type")
            if if_type:
                intf_entry["interface_type"] = self._map_interface_type(if_type)

            # Passive flag
            if "passive" in if_data:
                intf_entry["passive"] = bool(if_data["passive"])

            # Timers
            timers = if_data.get("timers", {}) or {}
            if timers:
                lsp_pacing = timers.get("lsp-pacing-interval")
                if lsp_pacing is not None:
                    intf_entry["lsp_pacing_interval"] = lsp_pacing

            # Per-level attributes
            levels = if_data.get("levels", {}) or {}
            for lvl, lvl_data in levels.items():
                level_name = self._level_name_from_number(lvl)
                if not level_name:
                    continue

                # Priority
                priority = lvl_data.get("priority")
                if priority is not None:
                    pri_root = intf_entry.setdefault("priority", {}).setdefault(
                        level_name, {}
                    )
                    pri_root["priority"] = priority

                # Metric
                metric = lvl_data.get("metric")
                if metric is not None:
                    topo_root = (
                        intf_entry.setdefault("topologies", {})
                        .setdefault("0", {})
                        .setdefault("metric", {})
                        .setdefault(level_name, {})
                    )
                    topo_root["metric"] = metric

                # Packet counters per level
                pkt_counters = lvl_data.get("packet-counters", {}) or {}
                if pkt_counters:
                    lvl_root = (
                        intf_entry.setdefault("packet_counters", {})
                        .setdefault("level", {})
                        .setdefault(level_name, {})
                    )
                    for pkt_type, pkt_data in pkt_counters.items():
                        state = pkt_data.get("state", {})
                        if not state:
                            continue
                        sub = lvl_root.setdefault(pkt_type, {})
                        recv = state.get("received")
                        sent = state.get("sent")
                        if recv is not None:
                            sub["in"] = recv
                        if sent is not None:
                            sub["out"] = sent

            vrf_intf_dict[if_name] = intf_entry

        # ------------------------------------------------------------------
        # Adjacencies (show isis adjacency -> IOS-XR-style nesting)
        # ------------------------------------------------------------------
        neighbors = self._get_isis_neighbors(instance=instance)

        for sys_id, neigh in neighbors.items():
            intf_name = neigh.get("interface")
            if not intf_name:
                continue

            intf_entry = vrf_intf_dict.setdefault(intf_name, {"name": intf_name})

            # Get SNPA from interface data, if present
            intf_data = interfaces.get(intf_name, {})
            snpa = intf_data.get("snpa")

            # Map level (e.g. LEVEL_2) to XR-style key (level-2)
            level_raw = neigh.get("level") or neigh.get("adjacency-type")
            level_name = self._map_level_string(level_raw)
            if not level_name:
                level_name = "level-1-2"

            neighbor_root = (
                intf_entry.setdefault("adjacencies", {})
                .setdefault(sys_id, {})
                .setdefault("neighbor_snpa", {})
                .setdefault(snpa or "unknown", {})
                .setdefault("level", {})
                .setdefault(level_name, {})
            )

            # Core adjacency fields
            state = neigh.get("state") or neigh.get("adjacency-state")
            if state is not None:
                neighbor_root["state"] = state

            hold = neigh.get("holdtime") or neigh.get("remaining-hold-time")
            if hold is not None:
                neighbor_root["hold_timer"] = int(hold)

            last_up = neigh.get("up-time")
            if last_up is not None:
                neighbor_root["lastuptime"] = last_up

        # ------------------------------------------------------------------
        # LSDB (show isis lsp)
        # ------------------------------------------------------------------
        self.lsdb = {"instance": {}}
        lsdb_inst: Dict[str, Any] = self.lsdb["instance"].setdefault(instance, {})
        lsdb_vrf: Dict[str, Any] = lsdb_inst.setdefault("vrf", {}).setdefault(vrf, {})
        level_db: Dict[str, Any] = lsdb_vrf.setdefault("level_db", {})

        try:
            parsed_lsp = self.device.parse("show isis lsp")
            ni_root = parsed_lsp.get("network-instance", {}).get("default", {})
            isis_root = ni_root.get("isis", {})
            lsp_root = isis_root.get(instance, {})
            database = lsp_root.get("database", {}) or {}
        except Exception:
            database = {}

        # For now, associate all LSPs with a single level corresponding to
        # the global level-capability (e.g. LEVEL_1_2 -> level-1-2)
        level_cap = global_state.get("level-capability")
        level_name = self._map_level_string(level_cap) or "level-1-2"
        level_bucket: Dict[str, Any] = level_db.setdefault(level_name, {})

        for lsp_id, entry in database.items():
            lsp_entry: Dict[str, Any] = {"lsp_id": lsp_id}

            if "sequence" in entry:
                lsp_entry["sequence"] = entry["sequence"]
            if "checksum" in entry:
                lsp_entry["checksum"] = entry["checksum"]
            if "remaining-lifetime" in entry:
                lsp_entry["remaining_lifetime"] = entry["remaining-lifetime"]
            if "maximum-area-addresses" in entry:
                lsp_entry["maximum_area_addresses"] = entry["maximum-area-addresses"]
            if "pdu-length" in entry:
                lsp_entry["pdu_length"] = entry["pdu-length"]

            # Additional LSP attributes parsed from ArcOS augments
            for key in (
                "system-id",
                "overload-bit",
                "attached-bit",
                "is-type",
                "received-remaining-lifetime",
                "last-update-ifindex",
                "last-update-time",
                "srm-count",
                "ssn-count",
            ):
                if key in entry:
                    lsp_entry[key] = entry[key]

            tlvs = entry.get("tlvs", {}) or {}
            ipv4_addrs = tlvs.get("ipv4-interface-addresses")
            if ipv4_addrs is not None:
                lsp_entry["ipv4_addresses"] = ipv4_addrs

            ipv6_addrs = tlvs.get("ipv6-interface-addresses")
            if ipv6_addrs is not None:
                lsp_entry["ipv6_addresses"] = ipv6_addrs

            hostname = tlvs.get("hostname")
            if hostname is not None:
                lsp_entry["dynamic_hostname"] = hostname

            # SRv6 locator TLVs
            srv6_locs = tlvs.get("srv6-locators")
            if srv6_locs is not None:
                lsp_entry["srv6_locators"] = srv6_locs

            # Router capabilities TLV
            router_caps = tlvs.get("router-capabilities")
            if router_caps is not None:
                lsp_entry["router_capabilities"] = router_caps

            if "extended_ipv4_reachability" in entry:
                lsp_entry["extended_ipv4_reachability"] = entry[
                    "extended_ipv4_reachability"
                ]

            if "mt_ipv6_reachability" in entry:
                lsp_entry["mt_ipv6_reachability"] = entry["mt_ipv6_reachability"]

            level_bucket[lsp_id] = lsp_entry

        # ------------------------------------------------------------------
        # Routes (show isis route) – stored per AF under VRF
        # ------------------------------------------------------------------
        routes_root: Dict[str, Any] = {}
        for af in address_families:
            try:
                routes_af = self._get_isis_routes(instance=instance, address_family=af)
            except Exception:
                routes_af = {}
            if routes_af:
                routes_root[af] = routes_af

        if routes_root:
            vrf_dict["routes"] = routes_root

    # ==================================================================
    # Helper methods
    # ==================================================================

    @staticmethod
    def _safe_get_isis(
        data: Dict[str, Any], ni: str = "default", instance: str = "default"
    ) -> Dict[str, Any]:
        """Helper to navigate to ISIS instance data from parser output."""

        ni_root = data.get("network-instance", {}).get(ni, {})
        isis_root = ni_root.get("isis", {})
        return isis_root.get(instance, {}) or {}

    @staticmethod
    def _safe_get_global(
        data: Dict[str, Any], ni: str = "default", instance: str = "default"
    ) -> Dict[str, Any]:
        """Helper to navigate to global ISIS state data from parser output."""

        ni_root = data.get("network-instance", {}).get(ni, {})
        isis_root = ni_root.get("isis", {}).get(instance, {})
        return isis_root.get("global", {}) or {}

    def _get_isis_global(self, instance: str = "default") -> Dict[str, Any]:
        """Get raw ISIS global state for an instance ("show isis global")."""

        try:
            parsed = self.device.parse("show isis global")
            return self._safe_get_global(parsed, ni="default", instance=instance)
        except Exception:
            return {}

    def _get_isis_neighbors(self, instance: str = "default") -> Dict[str, Any]:
        """Get ISIS neighbors for an instance ("show isis adjacency")."""

        try:
            parsed = self.device.parse("show isis adjacency")
            isis = self._safe_get_isis(parsed, ni="default", instance=instance)
            return isis.get("neighbors", {}) or {}
        except Exception:
            return {}

    def _get_isis_routes(
        self, instance: str = "default", address_family: str = "ipv4"
    ) -> Dict[str, Any]:
        """Get ISIS routes for a given address-family ("show isis route").

        Aligns with :class:`ShowIsisRoute`, which nests routes under
        ``isis[instance]['routes'][AF]['routes']``.
        """

        af_map = {
            "ipv4": "IPV4-UNICAST",
            "ipv6": "IPV6-UNICAST",
        }
        af_key = af_map.get(address_family.lower())
        if af_key is None:
            raise ValueError(f"Unsupported address_family: {address_family}")

        try:
            parsed = self.device.parse("show isis route")
            isis = self._safe_get_isis(parsed, ni="default", instance=instance)
            routes_root = isis.get("routes", {}) or {}
            af_entry = routes_root.get(af_key, {}) or {}
            return af_entry.get("routes", {}) or {}
        except Exception:
            return {}

    @staticmethod
    def _map_circuit_type(circuit_type: str) -> str:
        """Map Arrcus circuit-type to IOS-XR-style level_type string."""

        mapping = {
            "LEVEL_1": "level-1-only",
            "LEVEL_2": "level-2-only",
            "LEVEL_1_2": "level-1-2",
            "arcos-isis-types:LEVEL_1": "level-1-only",
            "arcos-isis-types:LEVEL_2": "level-2-only",
            "arcos-isis-types:LEVEL_1_2": "level-1-2",
        }
        # Extract suffix if fully-qualified type
        if ":" in circuit_type:
            _, suffix = circuit_type.split(":", 1)
            return mapping.get(circuit_type, mapping.get(suffix, suffix.lower()))
        return mapping.get(circuit_type, circuit_type.lower())

    @staticmethod
    def _map_interface_type(if_type: str) -> str:
        """Map Arrcus network-type to IOS-XR-style interface_type string."""

        mapping = {
            "POINT_TO_POINT": "point-to-point",
            "BROADCAST": "broadcast",
            "LOOPBACK": "loopback",
        }
        return mapping.get(if_type, if_type.lower())

    @staticmethod
    def _level_name_from_number(level: Any) -> str | None:
        """Convert a numeric/string level identifier to XR-style name."""

        try:
            lvl_int = int(level)
        except Exception:
            return None
        return f"level-{lvl_int}"

    @staticmethod
    def _map_level_string(level: Any) -> str | None:
        """Map a LEVEL_* style string to XR-style level key."""

        if not level:
            return None
        level_str = str(level).upper()
        mapping = {
            "LEVEL_1": "level-1",
            "LEVEL_2": "level-2",
            "LEVEL_1_2": "level-1-2",
        }
        # Strip namespace if present
        if ":" in level_str:
            _, suffix = level_str.split(":", 1)
            return mapping.get(level_str, mapping.get(suffix, suffix.lower()))
        return mapping.get(level_str, level_str.lower())
