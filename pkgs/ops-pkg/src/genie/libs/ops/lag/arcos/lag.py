"""ArcOS LAG Genie Ops Object.

Provides a Genie LAG Ops object for Arrcus devices based on
OpenConfig JSON ``show lacp interface`` output parsed by
``genie.libs.parser.arcos.show_lacp.ShowLacpInterface``.

The ``self.info`` structure follows the IOS-XE/XR LAG Ops schema
for cross-platform ``learn()``/``diff()`` compatibility.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from genie.libs.ops.lag.lag import Lag as SuperLag

from genie.libs.parser.arcos.show_lacp import ShowLacpInterface


# Synchronization state mapping: arcOS -> XE ops schema
_SYNC_MAP: Dict[str, str] = {
    "IN_SYNC": "synchronized",
    "OUT_SYNC": "unsynchronized",
}


def _extract_bundle_id(bond_name: str) -> int | None:
    """Extract numeric bundle ID from bond name (e.g. 'bond111' -> 111)."""
    match = re.search(r"(\d+)$", bond_name)
    if match:
        return int(match.group(1))
    return None


class Lag(SuperLag):
    """ArcOS LAG Genie Ops Object.

    ``self.info`` follows the IOS-XE/XR schema::

        info
        └── interfaces
            └── [bond_name]
                ├── name
                ├── bundle_id
                ├── protocol          ("lacp")
                ├── oper_status       ("up" / "down")
                └── members
                    └── [member_intf]
                        ├── interface
                        ├── bundled       (bool)
                        ├── activity      (str)
                        ├── synchronization (str)
                        ├── aggregatable  (bool)
                        ├── collecting    (bool)
                        └── distributing  (bool)
    """

    def learn(self) -> None:
        """Learn LAG operational state on ArcOS devices."""
        self.info: Dict[str, Any] = {}

        try:
            parser = ShowLacpInterface(device=self.device)
            parsed = parser.parse()
        except Exception:
            return

        interfaces = parsed.get("interfaces", {})
        if not interfaces:
            return

        intf_dict: Dict[str, Any] = {}

        for bond_name, bond_data in interfaces.items():
            bond_entry: Dict[str, Any] = {}

            bond_entry["name"] = bond_data.get("name", bond_name)

            bundle_id = _extract_bundle_id(bond_name)
            if bundle_id is not None:
                bond_entry["bundle_id"] = bundle_id

            # arcOS LAG always uses LACP
            bond_entry["protocol"] = "lacp"

            # Build members and derive oper_status
            members_data = bond_data.get("members", {})
            any_distributing = False
            if members_data:
                members_dict: Dict[str, Any] = {}
                for mem_name, mem_data in members_data.items():
                    mem_entry: Dict[str, Any] = {}

                    mem_entry["interface"] = mem_data.get("interface", mem_name)

                    distributing = mem_data.get("distributing", False)
                    mem_entry["bundled"] = bool(distributing)
                    if distributing:
                        any_distributing = True

                    # Map interval to activity: FAST -> active, SLOW -> passive
                    interval = bond_data.get("interval")
                    if interval:
                        mem_entry["activity"] = (
                            "active" if interval == "FAST" else "passive"
                        )

                    # Synchronization state mapping
                    sync_raw = mem_data.get("synchronization")
                    if sync_raw is not None:
                        mem_entry["synchronization"] = _SYNC_MAP.get(
                            sync_raw, sync_raw.lower()
                        )

                    aggregatable = mem_data.get("aggregatable")
                    if aggregatable is not None:
                        mem_entry["aggregatable"] = bool(aggregatable)

                    collecting = mem_data.get("collecting")
                    if collecting is not None:
                        mem_entry["collecting"] = bool(collecting)

                    if distributing is not None:
                        mem_entry["distributing"] = bool(distributing)

                    members_dict[mem_name] = mem_entry

                if members_dict:
                    bond_entry["members"] = members_dict

            bond_entry["oper_status"] = "up" if any_distributing else "down"

            intf_dict[bond_name] = bond_entry

        if intf_dict:
            self.info["interfaces"] = intf_dict
