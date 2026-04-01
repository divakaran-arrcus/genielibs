"""ArcOS LDP get APIs.

High-level helpers built on top of the upstream ArcOS LDP parsers:
- ``genie.libs.parser.arcos.show_ldp.ShowLdpInterface``
- ``genie.libs.parser.arcos.show_ldp.ShowLdpSession``
- ``genie.libs.parser.arcos.show_ldp.ShowLdpHelloAdjacency``
- ``genie.libs.parser.arcos.show_ldp.ShowLdpNeighbor``

These functions instantiate parsers directly.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_ldp import (
    ShowLdpInterface,
    ShowLdpSession,
    ShowLdpHelloAdjacency,
    ShowLdpNeighbor,
)

log = logging.getLogger(__name__)


# =====================================================================
# Parse helpers
# =====================================================================

def _parse_ldp_interfaces(device) -> Dict[str, Any]:
    """Parse LDP interface-attributes."""
    try:
        parser = ShowLdpInterface(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse LDP interfaces: %s", exc)
        return {}


def _parse_ldp_sessions(device) -> Dict[str, Any]:
    """Parse LDP sessions."""
    try:
        parser = ShowLdpSession(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse LDP sessions: %s", exc)
        return {}


def _parse_ldp_neighbors(device) -> Dict[str, Any]:
    """Parse LDP neighbors."""
    try:
        parser = ShowLdpNeighbor(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse LDP neighbors: %s", exc)
        return {}


# =====================================================================
# Public get functions
# =====================================================================

def get_ldp_interfaces(device) -> Dict[str, Any]:
    """Get all LDP interfaces with state.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by interface-id with hello timers, link-hello,
        and address-family state. Empty dict if no data.
    """

    parsed = _parse_ldp_interfaces(device)
    return parsed.get("interfaces", {})


def get_ldp_sessions(device) -> Dict[str, Any]:
    """Get all LDP sessions keyed by peer-address.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by peer-address with session state fields.
        Empty dict if no sessions.
    """

    parsed = _parse_ldp_sessions(device)
    return parsed.get("sessions", {})


def get_ldp_session(
    device, peer_address: str
) -> Optional[Dict[str, Any]]:
    """Get a single LDP session by peer-address.

    Args:
        device: pyATS device object.
        peer_address: Peer address to look up (e.g., '1.1.1.1').

    Returns:
        Dict with session state, or None if not found.
    """

    sessions = get_ldp_sessions(device)
    return sessions.get(peer_address)


def get_ldp_session_state(
    device, peer_address: str
) -> Optional[str]:
    """Get session state for a specific LDP peer.

    Args:
        device: pyATS device object.
        peer_address: Peer address (e.g., '1.1.1.1').

    Returns:
        Session state string (e.g., 'Operational'), or None if not found.
    """

    session = get_ldp_session(device, peer_address)
    if not session:
        return None
    return session.get("session-state")


def get_ldp_neighbors(device) -> Dict[str, Any]:
    """Get all LDP neighbors keyed by 'lsr-id/label-space-id'.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by 'lsr-id/label-space-id' with neighbor state.
        Empty dict if no neighbors.
    """

    parsed = _parse_ldp_neighbors(device)
    return parsed.get("neighbors", {})


def get_ldp_session_count(device) -> int:
    """Get total number of LDP sessions.

    Args:
        device: pyATS device object.

    Returns:
        Number of LDP sessions.
    """

    sessions = get_ldp_sessions(device)
    return len(sessions)
