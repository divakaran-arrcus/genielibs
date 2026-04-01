"""ArcOS VRRP get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.parser.arcos.show_vrrp import ShowVrrp

log = logging.getLogger(__name__)


def _parse_vrrp(device, interface="*", sub_id=0, af="ipv4",
                address="*") -> Dict[str, Any]:
    try:
        parser = ShowVrrp(device=device)
        return parser.parse(
            interface=interface, sub_id=sub_id,
            af=af, address=address,
        )
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse VRRP: %s", exc)
        return {}


def get_vrrp_groups(device, interface="*", sub_id=0, af="ipv4",
                     address="*") -> Dict[str, Any]:
    """Get all VRRP groups.

    Args:
        device: pyATS device object.
        interface: Interface name or '*'.
        sub_id: Subinterface ID.
        af: Address family.
        address: IP address or '*'.

    Returns:
        Dict keyed by 'intf:sub:af:ip:vrid'. Empty if none.
    """
    parsed = _parse_vrrp(device, interface, sub_id, af, address)
    return parsed.get("vrrp-groups", {})


def get_vrrp_group(device, interface, sub_id, af, address,
                    vrid) -> Optional[Dict[str, Any]]:
    """Get a single VRRP group.

    Returns:
        Dict with VRRP group state, or None if not found.
    """
    groups = get_vrrp_groups(device, interface, sub_id, af, address)
    key = f"{interface}:{sub_id}:{af}:{address}:{vrid}"
    return groups.get(key)


def get_vrrp_group_mode(device, interface, sub_id, af, address,
                         vrid) -> Optional[str]:
    """Get VRRP group mode (MASTER/BACKUP).

    Returns:
        Mode string, or None if not found.
    """
    grp = get_vrrp_group(device, interface, sub_id, af, address, vrid)
    if not grp:
        return None
    return grp.get("virtual-router-mode")


def is_vrrp_group_present(device, interface, sub_id, af, address,
                           vrid) -> bool:
    """Check if a VRRP group exists."""
    return get_vrrp_group(device, interface, sub_id, af, address, vrid) is not None
