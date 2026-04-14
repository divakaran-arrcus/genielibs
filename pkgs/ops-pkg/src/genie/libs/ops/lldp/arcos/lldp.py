"""ArcOS LLDP Genie Ops Object.

Provides a Genie LLDP Ops object for Arrcus devices based on
OpenConfig JSON parser output.  The ``self.info`` structure matches
the IOS-XE LLDP Ops schema for cross-platform ``learn()``/``diff()``.

Parsers used:
    - ShowLldpState     -- global LLDP state: hello-timer, system-name,
                           system-description, counters
    - ShowLldpInterface -- per-interface LLDP state: enabled, mode,
                           neighbors (chassis-id, port-id, system-name,
                           capabilities, etc.)
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.lldp.lldp import Lldp as SuperLldp

from genie.libs.parser.arcos.show_lldp import (
    ShowLldpState,
    ShowLldpInterface,
)


class Lldp(SuperLldp):
    """ArcOS LLDP Genie Ops Object.

    ``self.info`` follows the IOS-XE schema::

        info
        +-- enabled              (bool)
        +-- hello_timer          (int)
        +-- hold_timer           (int)
        +-- system_name          (str)
        +-- system_description   (str)
        +-- counters
        |   +-- frame_in         (int)
        |   +-- frame_out        (int)
        |   +-- frame_error_in   (int)
        |   +-- frame_discard    (int)
        |   +-- tlv_discard      (int)
        |   +-- tlv_unknown      (int)
        +-- interfaces
            +-- <intf>
                +-- if_name      (str)
                +-- enabled      (bool)
                +-- port_id
                    +-- <port_id>
                        +-- neighbors
                            +-- <neighbor_id>
                                +-- neighbor_id        (str)
                                +-- system_name        (str)
                                +-- system_description (str)
                                +-- chassis_id         (str)
                                +-- port_id            (str)
                                +-- port_description   (str)
                                +-- management_address (str)
                                +-- capabilities
                                    +-- <name>
                                        +-- name       (str)
                                        +-- enabled    (bool)
    """

    def learn(self) -> None:
        """Learn LLDP operational state on ArcOS devices."""
        self.info: Dict[str, Any] = {}

        # --- Section 1: Global LLDP state ---
        state_data = self._parse_state()
        if state_data:
            self.info["enabled"] = True

            hello_timer = state_data.get("hello-timer")
            if hello_timer is not None:
                try:
                    self.info["hello_timer"] = int(hello_timer)
                except (ValueError, TypeError):
                    self.info["hello_timer"] = hello_timer

            system_name = state_data.get("system-name")
            if system_name:
                self.info["system_name"] = system_name

            system_desc = state_data.get("system-description")
            if system_desc:
                self.info["system_description"] = system_desc

            # Global counters
            counters = state_data.get("counters", {})
            if counters:
                counters_dict: Dict[str, Any] = {}
                for arcos_key, xe_key in (
                    ("frame-in", "frame_in"),
                    ("frame-out", "frame_out"),
                    ("frame-error-in", "frame_error_in"),
                    ("frame-discard", "frame_discard"),
                    ("tlv-discard", "tlv_discard"),
                    ("tlv-unknown", "tlv_unknown"),
                ):
                    val = counters.get(arcos_key)
                    if val is not None:
                        try:
                            counters_dict[xe_key] = int(val)
                        except (ValueError, TypeError):
                            counters_dict[xe_key] = val
                if counters_dict:
                    self.info["counters"] = counters_dict

        # --- Section 2: Per-interface state & neighbors ---
        intf_data = self._parse_interfaces()
        if intf_data:
            interfaces_dict: Dict[str, Any] = {}

            for intf_name, i_data in intf_data.items():
                intf_entry: Dict[str, Any] = {
                    "if_name": intf_name,
                }

                enabled = i_data.get("enabled")
                if enabled is not None:
                    intf_entry["enabled"] = enabled

                # Map neighbors into port_id -> neighbors hierarchy
                neighbors_raw = i_data.get("neighbors", {})
                if neighbors_raw:
                    port_id_dict: Dict[str, Any] = {}

                    for nbr_id, nbr_data in neighbors_raw.items():
                        port_id = nbr_data.get("port-id", nbr_id)
                        nbr_entry: Dict[str, Any] = {
                            "neighbor_id": nbr_id,
                        }

                        for arcos_key, xe_key in (
                            ("system-name", "system_name"),
                            ("system-description", "system_description"),
                            ("chassis-id", "chassis_id"),
                            ("port-id", "port_id"),
                            ("port-description", "port_description"),
                            ("management-address", "management_address"),
                        ):
                            val = nbr_data.get(arcos_key)
                            if val is not None:
                                nbr_entry[xe_key] = val

                        # Capabilities
                        caps_raw = nbr_data.get("capabilities", {})
                        if caps_raw:
                            caps_dict: Dict[str, Any] = {}
                            for cap_name, cap_data in caps_raw.items():
                                caps_dict[cap_name] = {
                                    "name": cap_data.get("name", cap_name),
                                    "enabled": cap_data.get("enabled", False),
                                }
                            if caps_dict:
                                nbr_entry["capabilities"] = caps_dict

                        # Place neighbor under port_id key
                        nbrs_for_port = (
                            port_id_dict
                            .setdefault(port_id, {})
                            .setdefault("neighbors", {})
                        )
                        nbrs_for_port[nbr_id] = nbr_entry

                    if port_id_dict:
                        intf_entry["port_id"] = port_id_dict

                interfaces_dict[intf_name] = intf_entry

            if interfaces_dict:
                self.info["interfaces"] = interfaces_dict

    # ------------------------------------------------------------------
    # Parser helpers
    # ------------------------------------------------------------------

    def _parse_state(self) -> Dict[str, Any]:
        """Parse global LLDP state via ShowLldpState."""
        try:
            parser = ShowLldpState(device=self.device)
            return parser.parse()
        except Exception:
            return {}

    def _parse_interfaces(self) -> Dict[str, Any]:
        """Parse per-interface LLDP data via ShowLldpInterface.

        Returns:
            {intf_name: {name, enabled, neighbors: {...}}}
        """
        try:
            parser = ShowLldpInterface(device=self.device)
            result = parser.parse()
            return result.get("interfaces", {})
        except Exception:
            return {}
