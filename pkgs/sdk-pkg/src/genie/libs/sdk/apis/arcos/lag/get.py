"""ArcOS LAG (LACP/Bond) get APIs.

High-level helpers built on top of the upstream ArcOS LACP parser:
``genie.libs.parser.arcos.show_lacp.ShowLacpInterface``

These functions instantiate the parser directly.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_lacp import ShowLacpInterface

log = logging.getLogger(__name__)


# =====================================================================
# Parse helper
# =====================================================================

def _parse_lacp(device, bond: str = "*") -> Dict[str, Any]:
    """Internal helper to parse LACP interface data.

    Args:
        device: pyATS device object.
        bond: Bond name or '*' for all.

    Returns:
        Parsed dict, or empty dict on error.
    """
    try:
        parser = ShowLacpInterface(device=device)
        return parser.parse(bond=bond)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse LACP interfaces: %s", exc)
        return {}


# =====================================================================
# Public get functions
# =====================================================================

def get_lag_interfaces(device) -> Dict[str, Any]:
    """Get all LACP bond interfaces with member state.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by bond name with interval and member data.
        Empty dict if no bonds.
    """

    parsed = _parse_lacp(device, bond="*")
    return parsed.get("interfaces", {})


def get_lag_bond(
    device, bond: str
) -> Optional[Dict[str, Any]]:
    """Get LACP state for a specific bond interface.

    Args:
        device: pyATS device object.
        bond: Bond interface name (e.g., 'bond10').

    Returns:
        Dict with bond state and members, or None if not found.
    """

    parsed = _parse_lacp(device, bond=bond)
    interfaces = parsed.get("interfaces", {})

    if bond in interfaces:
        return interfaces[bond]

    # Fallback: single-entry
    if len(interfaces) == 1:
        return next(iter(interfaces.values()))

    log.debug("get_lag_bond: %s not found", bond)
    return None


def get_lag_members(
    device, bond: str
) -> Dict[str, Any]:
    """Get members of a specific bond interface.

    Args:
        device: pyATS device object.
        bond: Bond interface name (e.g., 'bond10').

    Returns:
        Dict keyed by member interface name with sync/collect/distribute
        state. Empty dict if bond not found or no members.
    """

    bond_data = get_lag_bond(device, bond)
    if not bond_data:
        return {}
    return bond_data.get("members", {})


def get_lag_member_sync_state(
    device, bond: str, member: str
) -> Optional[str]:
    """Get synchronization state for a specific bond member.

    Args:
        device: pyATS device object.
        bond: Bond interface name (e.g., 'bond10').
        member: Member interface name (e.g., 'swp10').

    Returns:
        Sync state string (e.g., 'IN_SYNC', 'OUT_SYNC'),
        or None if not found.
    """

    members = get_lag_members(device, bond)
    member_data = members.get(member)
    if not member_data:
        return None
    return member_data.get("synchronization")


def get_lag_bond_count(device) -> int:
    """Get total number of LACP bond interfaces.

    Args:
        device: pyATS device object.

    Returns:
        Number of LACP bonds.
    """

    interfaces = get_lag_interfaces(device)
    return len(interfaces)
