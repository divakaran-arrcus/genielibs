"""ArcOS STP Genie Ops Object.

Provides a Genie STP Ops object for Arrcus devices based on
OpenConfig JSON ``show stp global`` output parsed by
``genie.libs.parser.arcos.show_stp.ShowStpGlobal``.

The ``self.info`` structure matches the IOS-XE STP Ops schema
for cross-platform ``learn()``/``diff()``.
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.stp.stp import Stp as SuperStp

from genie.libs.parser.arcos.show_stp import ShowStpGlobal


# Protocol name mapping: arcOS enabled-protocol -> XE schema mode key
_PROTOCOL_MAP: Dict[str, str] = {
    "RAPID_PVST": "rapid_pvst",
    "PVST": "pvst",
    "MSTP": "mstp",
    "rapid_pvst": "rapid_pvst",
    "pvst": "pvst",
    "mstp": "mstp",
}


class Stp(SuperStp):
    """ArcOS STP Genie Ops Object.

    ``self.info`` follows the IOS-XE schema::

        info
        +-- global
        |   +-- bpdu_guard (bool)
        |   +-- bridge_assurance (bool)
        +-- rapid_pvst|pvst|mstp
            +-- default
                +-- (empty -- arcOS only has global config from this parser)
    """

    exclude = []

    def learn(self) -> None:
        """Learn STP operational state on ArcOS devices."""

        self.info = {}

        parsed = self._parse_stp_global()
        if not parsed:
            return

        # --- Global section ---
        global_dict: Dict[str, Any] = {}

        bpdu_guard = parsed.get("bpdu-guard")
        if bpdu_guard is not None:
            global_dict["bpdu_guard"] = bool(bpdu_guard)

        bridge_assurance = parsed.get("bridge-assurance")
        if bridge_assurance is not None:
            global_dict["bridge_assurance"] = bool(bridge_assurance)

        if global_dict:
            self.info["global"] = global_dict

        # --- Protocol mode section ---
        enabled_protocol = parsed.get("enabled-protocol")
        if enabled_protocol:
            mode_key = _PROTOCOL_MAP.get(enabled_protocol, enabled_protocol.lower())
            self.info[mode_key] = {"default": {}}

    # ------------------------------------------------------------------
    # Parser helpers
    # ------------------------------------------------------------------

    def _parse_stp_global(self) -> Dict[str, Any]:
        """Parse STP global configuration."""
        try:
            parser = ShowStpGlobal(device=self.device)
            return parser.parse()
        except Exception:
            return {}
