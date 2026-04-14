"""ArcOS ACL Genie Ops Object.

Provides a Genie ACL Ops object for Arrcus devices based on
OpenConfig JSON ``show acl`` output parsed by
``genie.libs.parser.arcos.show_acl.ShowAclSet``.

The ``self.info`` structure matches the IOS-XE ACL Ops schema
for cross-platform ``learn()``/``diff()``.

Parser output shape::

    acl-sets:
      "<name> <type>":
        name: str
        type: str (e.g. "ACL_IPV4")
        acl-entries:
          "<seq>":
            sequence-id, ipv4-source-address, ipv4-destination-address,
            forwarding-action, log-action, transport-source-port, ...
"""

from __future__ import annotations

from typing import Any, Dict

from genie.libs.ops.acl.acl import Acl as SuperAcl

from genie.libs.parser.arcos.show_acl import ShowAclSet


# Forwarding action mapping: arcOS -> XE schema
_ACTION_MAP: Dict[str, str] = {
    "ACCEPT": "permit",
    "DROP": "deny",
    "REJECT": "deny",
    "REDIRECT": "redirect",
}


class Acl(SuperAcl):
    """ArcOS ACL Genie Ops Object.

    ``self.info`` follows the IOS-XE schema::

        info
        +-- acls
            +-- [name]
                +-- name
                +-- type
                +-- aces
                    +-- [seq]
                        +-- name (= sequence-id)
                        +-- actions
                        |   +-- forwarding (permit|deny|redirect)
                        +-- matches
                            +-- l3
                            |   +-- ipv4.{source_ipv4_network, destination_ipv4_network, protocol}
                            |   +-- ipv6.{source_ipv6_network, destination_ipv6_network, protocol}
                            +-- l2
                            |   +-- eth.{source_mac_address, destination_mac_address}
                            +-- l4
                                +-- tcp|udp.{source_port, destination_port}
    """

    exclude = []

    def learn(self) -> None:
        """Learn ACL operational state on ArcOS devices."""

        self.info = {}

        parsed = self._parse_acl_sets()
        if not parsed:
            return

        acl_sets = parsed.get("acl-sets", {})
        if not acl_sets:
            return

        acls_dict: Dict[str, Any] = {}

        for _key, acl_data in acl_sets.items():
            acl_name = acl_data.get("name")
            acl_type = acl_data.get("type")
            if not acl_name:
                continue

            acl_entry: Dict[str, Any] = {
                "name": acl_name,
            }
            if acl_type:
                acl_entry["type"] = acl_type

            # Process ACL entries (ACEs)
            acl_entries = acl_data.get("acl-entries", {})
            if acl_entries:
                aces_dict: Dict[str, Any] = {}

                for seq, ace_data in acl_entries.items():
                    ace_entry: Dict[str, Any] = {}

                    # ACE name (sequence-id)
                    seq_id = ace_data.get("sequence-id")
                    if seq_id is not None:
                        ace_entry["name"] = str(seq_id)

                    # Actions
                    fwd_action = ace_data.get("forwarding-action")
                    if fwd_action:
                        mapped = _ACTION_MAP.get(fwd_action, fwd_action.lower())
                        ace_entry["actions"] = {"forwarding": mapped}

                    # Matches
                    matches = _build_matches(ace_data, acl_type)
                    if matches:
                        ace_entry["matches"] = matches

                    if ace_entry:
                        aces_dict[str(seq)] = ace_entry

                if aces_dict:
                    acl_entry["aces"] = aces_dict

            acls_dict[acl_name] = acl_entry

        if acls_dict:
            self.info["acls"] = acls_dict

    # ------------------------------------------------------------------
    # Parser helpers
    # ------------------------------------------------------------------

    def _parse_acl_sets(self) -> Dict[str, Any]:
        """Parse ACL sets from device."""
        try:
            parser = ShowAclSet(device=self.device)
            return parser.parse()
        except Exception:
            return {}


# ------------------------------------------------------------------
# Static mapping helpers
# ------------------------------------------------------------------

def _build_matches(ace_data: Dict[str, Any],
                   acl_type: str | None) -> Dict[str, Any]:
    """Build the matches subtree from arcOS ACE data.

    Maps arcOS fields to XE-style l3/l4/l2 match hierarchy.
    """
    matches: Dict[str, Any] = {}

    # --- L3 IPv4 matches ---
    ipv4_matches: Dict[str, Any] = {}
    src_v4 = ace_data.get("ipv4-source-address")
    if src_v4:
        ipv4_matches["source_ipv4_network"] = src_v4
    dst_v4 = ace_data.get("ipv4-destination-address")
    if dst_v4:
        ipv4_matches["destination_ipv4_network"] = dst_v4
    proto_v4 = ace_data.get("protocol")
    if proto_v4 and _is_ipv4_type(acl_type):
        ipv4_matches["protocol"] = proto_v4

    if ipv4_matches:
        matches.setdefault("l3", {})["ipv4"] = ipv4_matches

    # --- L3 IPv6 matches ---
    ipv6_matches: Dict[str, Any] = {}
    src_v6 = ace_data.get("ipv6-source-address")
    if src_v6:
        ipv6_matches["source_ipv6_network"] = src_v6
    dst_v6 = ace_data.get("ipv6-destination-address")
    if dst_v6:
        ipv6_matches["destination_ipv6_network"] = dst_v6
    proto_v6 = ace_data.get("protocol")
    if proto_v6 and _is_ipv6_type(acl_type):
        ipv6_matches["protocol"] = proto_v6

    if ipv6_matches:
        matches.setdefault("l3", {})["ipv6"] = ipv6_matches

    # --- L2 Ethernet matches ---
    l2_matches: Dict[str, Any] = {}
    src_mac = ace_data.get("source-mac-address")
    if src_mac:
        l2_matches["source_mac_address"] = src_mac
    dst_mac = ace_data.get("destination-mac-address")
    if dst_mac:
        l2_matches["destination_mac_address"] = dst_mac

    if l2_matches:
        matches.setdefault("l2", {})["eth"] = l2_matches

    # --- L4 transport matches ---
    transport_proto = _get_transport_protocol(ace_data)
    l4_matches: Dict[str, Any] = {}

    src_port = ace_data.get("transport-source-port")
    if src_port is not None:
        l4_matches["source_port"] = src_port
    dst_port = ace_data.get("transport-destination-port")
    if dst_port is not None:
        l4_matches["destination_port"] = dst_port

    if l4_matches:
        proto_key = transport_proto or "tcp"
        matches.setdefault("l4", {})[proto_key] = l4_matches

    return matches


def _is_ipv4_type(acl_type: str | None) -> bool:
    """Check if ACL type is IPv4."""
    if not acl_type:
        return False
    return "IPV4" in acl_type.upper()


def _is_ipv6_type(acl_type: str | None) -> bool:
    """Check if ACL type is IPv6."""
    if not acl_type:
        return False
    return "IPV6" in acl_type.upper()


def _get_transport_protocol(ace_data: Dict[str, Any]) -> str | None:
    """Determine transport protocol from ACE data.

    Returns 'tcp', 'udp', or None.
    """
    proto = ace_data.get("protocol")
    if proto:
        proto_lower = str(proto).lower()
        if "tcp" in proto_lower or proto_lower == "6":
            return "tcp"
        if "udp" in proto_lower or proto_lower == "17":
            return "udp"
    return None
