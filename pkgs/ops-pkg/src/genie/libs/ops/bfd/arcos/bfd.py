"""ArcOS BFD Genie Ops Object.

Provides a Genie BFD Ops object for Arrcus devices based on
OpenConfig JSON ``show bfd`` output parsed by
``genie.libs.parser.arcos.show_bfd.ShowBfd``.

There is no XR/XE BFD ops model to mirror, so this defines a custom
``self.info`` schema tailored to arcOS BFD profile/peer structure.

``self.info`` structure::

    info = {
        "profiles": {
            "<profile_name>": {
                "id": str,
                "enabled": bool,
                "desired_minimum_tx_interval": int,
                "required_minimum_receive": int,
                "detection_multiplier": int,
                "sessions": {
                    "<local_disc>": {
                        "local_address": str,
                        "remote_address": str,
                        "session_state": str,
                        "interface": str,
                        "subscribed_protocols": list,
                    }
                }
            }
        }
    }
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.bfd.bfd import Bfd as SuperBfd

from genie.libs.parser.arcos.show_bfd import ShowBfd


class Bfd(SuperBfd):
    """ArcOS BFD Genie Ops Object."""

    def learn(self, **kwargs: Any) -> None:  # type: ignore[override]
        """Learn BFD operational state on ArcOS devices.

        Populates ``self.info`` with BFD profile and session data.
        """
        self.info = {}

        parsed = self._parse_bfd()
        if not parsed:
            return

        profiles_raw = parsed.get("profile", {})
        if not profiles_raw:
            return

        profiles: Dict[str, Any] = {}

        for profile_name, profile_data in profiles_raw.items():
            profile_entry: Dict[str, Any] = {}

            # Profile identification
            pid = profile_data.get("id")
            if pid is not None:
                profile_entry["id"] = str(pid)

            enabled = profile_data.get("enabled")
            if enabled is not None:
                profile_entry["enabled"] = bool(enabled)

            # Timing parameters (kebab -> snake)
            tx_interval = profile_data.get("desired-minimum-tx-interval")
            if tx_interval is not None:
                profile_entry["desired_minimum_tx_interval"] = int(tx_interval)

            rx_interval = profile_data.get("required-minimum-receive")
            if rx_interval is not None:
                profile_entry["required_minimum_receive"] = int(rx_interval)

            multiplier = profile_data.get("detection-multiplier")
            if multiplier is not None:
                profile_entry["detection_multiplier"] = int(multiplier)

            # Hardware offload flags
            v4_hw = profile_data.get("v4-hw-offload")
            if v4_hw is not None:
                profile_entry["v4_hw_offload"] = bool(v4_hw)

            v6_hw = profile_data.get("v6-hw-offload")
            if v6_hw is not None:
                profile_entry["v6_hw_offload"] = bool(v6_hw)

            dscp = profile_data.get("dscp-value")
            if dscp is not None:
                profile_entry["dscp_value"] = int(dscp)

            # Sessions (peers keyed by local-discriminator)
            peers_raw = profile_data.get("peers", {})
            if peers_raw:
                sessions: Dict[str, Any] = {}
                for disc, peer_data in peers_raw.items():
                    session_entry: Dict[str, Any] = {}

                    local_addr = peer_data.get("local-address")
                    if local_addr is not None:
                        session_entry["local_address"] = str(local_addr)

                    remote_addr = peer_data.get("remote-address")
                    if remote_addr is not None:
                        session_entry["remote_address"] = str(remote_addr)

                    state = peer_data.get("session-state")
                    if state is not None:
                        session_entry["session_state"] = str(state)

                    remote_state = peer_data.get("remote-session-state")
                    if remote_state is not None:
                        session_entry["remote_session_state"] = str(remote_state)

                    local_disc = peer_data.get("local-discriminator")
                    if local_disc is not None:
                        session_entry["local_discriminator"] = int(local_disc)

                    remote_disc = peer_data.get("remote-discriminator")
                    if remote_disc is not None:
                        session_entry["remote_discriminator"] = int(remote_disc)

                    intf = peer_data.get("interface")
                    if intf is not None:
                        session_entry["interface"] = str(intf)

                    ni = peer_data.get("network-instance")
                    if ni is not None:
                        session_entry["network_instance"] = str(ni)

                    protocols = peer_data.get("subscribed-protocols")
                    if protocols is not None:
                        session_entry["subscribed_protocols"] = list(protocols)

                    neg_tx = peer_data.get("negotiated-tx-interval")
                    if neg_tx is not None:
                        session_entry["negotiated_tx_interval"] = int(neg_tx)

                    neg_rx = peer_data.get("negotiated-rx-interval")
                    if neg_rx is not None:
                        session_entry["negotiated_rx_interval"] = int(neg_rx)

                    session_type = peer_data.get("session-type")
                    if session_type is not None:
                        session_entry["session_type"] = str(session_type)

                    hw_offload = peer_data.get("hw-offload-status")
                    if hw_offload is not None:
                        session_entry["hw_offload_status"] = bool(hw_offload)

                    if session_entry:
                        sessions[str(disc)] = session_entry

                if sessions:
                    profile_entry["sessions"] = sessions

            if profile_entry:
                profiles[profile_name] = profile_entry

        if profiles:
            self.info = {"profiles": profiles}

    # ------------------------------------------------------------------
    # Parser helpers
    # ------------------------------------------------------------------

    def _parse_bfd(self) -> Dict[str, Any]:
        """Parse BFD output using ShowBfd parser."""
        try:
            parser = ShowBfd(device=self.device)
            return parser.parse()
        except Exception:
            return {}
