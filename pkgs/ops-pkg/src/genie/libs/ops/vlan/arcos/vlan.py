"""ArcOS VLAN Genie Ops Object.

Provides a Genie VLAN Ops object for Arrcus devices based on
OpenConfig JSON parser output.  The ``self.info`` structure matches
the IOS-XE VLAN Ops schema for cross-platform ``learn()``/``diff()``.

Parsers used:
    - ShowVlan -- VLAN list with id, name, status, and member interfaces
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.vlan.vlan import Vlan as SuperVlan

from genie.libs.parser.arcos.show_vlan import ShowVlan as ShowVlanParser


class Vlan(SuperVlan):
    """ArcOS VLAN Genie Ops Object.

    ``self.info`` follows the IOS-XE schema::

        info
        +-- vlans
            +-- <vlan_id>
                +-- vlan_id      (str)
                +-- name         (str)
                +-- state        (str)  -- "active" / "suspend"
                +-- shutdown     (bool)
                +-- interfaces   (list)
    """

    def learn(self) -> None:
        """Learn VLAN operational state on ArcOS devices."""
        self.info: Dict[str, Any] = {}

        vlan_data = self._parse_vlans()
        if not vlan_data:
            return

        vlans_dict: Dict[str, Any] = {}

        for vlan_id_key, v_data in vlan_data.items():
            vlan_entry: Dict[str, Any] = {
                "vlan_id": str(vlan_id_key),
            }

            name = v_data.get("name")
            if name is not None:
                vlan_entry["name"] = name

            # Map arcOS "status" field to XE "state" field
            status = v_data.get("status")
            if status is not None:
                vlan_entry["state"] = _map_vlan_state(status)

            # Determine shutdown from status
            if status is not None:
                vlan_entry["shutdown"] = status.lower() in (
                    "suspend", "suspended", "shutdown",
                )

            # Map arcOS "members" to XE "interfaces"
            members = v_data.get("members")
            if members is not None:
                vlan_entry["interfaces"] = members

            vlans_dict[str(vlan_id_key)] = vlan_entry

        if vlans_dict:
            self.info["vlans"] = vlans_dict

    # ------------------------------------------------------------------
    # Parser helpers
    # ------------------------------------------------------------------

    def _parse_vlans(self) -> Dict[str, Any]:
        """Parse VLAN data via ShowVlan.

        Returns:
            {vlan_id: {vlan-id, name, status, members: [...]}}
        """
        try:
            parser = ShowVlanParser(device=self.device)
            result = parser.parse()
            return result.get("vlans", {})
        except Exception:
            return {}


# ------------------------------------------------------------------
# Static mapping helpers
# ------------------------------------------------------------------

def _map_vlan_state(raw: str) -> str:
    """Map arcOS VLAN status to XE-style state string."""
    mapping = {
        "ACTIVE": "active",
        "SUSPEND": "suspend",
        "SUSPENDED": "suspend",
        "SHUTDOWN": "suspend",
    }
    return mapping.get(raw.upper(), raw.lower() if raw else "active")
