"""ArcOS NTP Genie Ops Object.

Provides a Genie NTP Ops object for Arrcus devices based on
OpenConfig JSON parser output. The ``self.info`` structure matches
the IOS-XE/XR NTP Ops schema for cross-platform ``learn()``/``diff()``.

Parser used:
    - ShowNtp — NTP associations (stratum, offset, poll, reach, status)
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.ntp.ntp import Ntp as SuperNtp

from genie.libs.parser.arcos.show_ntp import ShowNtp


class Ntp(SuperNtp):
    """ArcOS NTP Genie Ops Object.

    ``self.info`` follows the IOS-XE/XR schema::

        info
        ├─ clock_state.system_status.{associations_address, clock_stratum}
        └─ vrf[default].associations.address[<addr>]
            └─ local_mode[client].isconfigured[True]
                .{address, stratum, refid, reach, poll, offset, delay, vrf}
    """

    def learn(self, **kwargs: Any) -> None:  # type: ignore[override]
        """Learn NTP operational state on ArcOS devices."""
        self.info = {}

        parsed = self._parse_ntp()
        if not parsed:
            return

        associations = parsed.get("associations", {})
        if not associations:
            return

        vrf = parsed.get("network-instance", "default")

        # Find the sync source for clock_state
        sync_addr = None
        sync_stratum = None
        for addr, data in associations.items():
            status = data.get("association-status", "")
            if "SYNC_SOURCE" in status.upper():
                sync_addr = addr
                sync_stratum = data.get("stratum")
                break

        # clock_state (matching XE: clock_state.system_status)
        if sync_addr:
            clock_state: Dict[str, Any] = {
                "system_status": {
                    "associations_address": sync_addr,
                }
            }
            if sync_stratum is not None:
                clock_state["system_status"]["clock_stratum"] = sync_stratum
            self.info["clock_state"] = clock_state

        # associations under vrf (matching XE schema)
        vrf_assoc: Dict[str, Any] = {}

        for addr, data in associations.items():
            peer_entry: Dict[str, Any] = {}

            # arcOS NTP is always client mode
            mode_entry: Dict[str, Any] = {}
            config_entry: Dict[str, Any] = {
                "address": addr,
                "vrf": vrf,
                "isconfigured": True,
            }

            stratum = data.get("stratum")
            if stratum is not None:
                config_entry["stratum"] = stratum

            poll = data.get("poll-interval")
            if poll is not None:
                config_entry["poll"] = poll

            reach = data.get("reach")
            if reach is not None:
                config_entry["reach"] = int(reach)

            offset = data.get("offset")
            if offset is not None:
                config_entry["offset"] = str(offset)

            delay = data.get("root-delay")
            if delay is not None:
                config_entry["delay"] = str(delay)

            mode_entry.setdefault("isconfigured", {})[True] = config_entry

            peer_entry.setdefault("local_mode", {})["client"] = mode_entry

            vrf_assoc[addr] = peer_entry

        if vrf_assoc:
            self.info.setdefault("vrf", {}).setdefault(vrf, {})[
                "associations"
            ] = {"address": vrf_assoc}

    # ------------------------------------------------------------------
    # Parser helper
    # ------------------------------------------------------------------

    def _parse_ntp(self) -> Dict[str, Any]:
        try:
            parser = ShowNtp(device=self.device)
            return parser.parse()
        except Exception:
            return {}
