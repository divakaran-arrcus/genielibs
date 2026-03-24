"""ArcOS VLAN get APIs.

High-level helpers built on top of the upstream ArcOS VLAN parser
``genie.libs.parser.arcos.show_vlan.ShowVlan``.
"""

from __future__ import annotations

from typing import Dict, Any, Optional, List
import logging
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def _parse_vlans(device) -> Dict[str, Any]:
    """Parse VLAN data using ShowVlan parser.

    Args:
        device: pyATS device object.

    Returns:
        Dict of VLANs keyed by vlan-id string, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_vlan import ShowVlan
        parser = ShowVlan(device=device)
        parsed = parser.parse()
    except SchemaEmptyParserError:
        log.debug("_parse_vlans: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_vlans: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_vlans: Unexpected exception - %s", exc)
        return {}

    return parsed.get("vlans", {})


def get_vlans(device) -> Dict[str, Any]:
    """Get all VLANs on ArcOS.

    Args:
        device: pyATS device object.

    Returns:
        Dict of VLANs keyed by vlan-id string (e.g., '100'),
        each containing vlan-id, name, status, members. Empty dict if none.
    """
    return _parse_vlans(device)


def get_vlan(device, vlan_id) -> Optional[Dict[str, Any]]:
    """Get a specific VLAN by ID on ArcOS.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).

    Returns:
        Dict with VLAN data (vlan-id, name, status, members) if found,
        None otherwise.
    """
    vlans = _parse_vlans(device)
    return vlans.get(str(vlan_id))


def get_vlan_members(device, vlan_id) -> List[str]:
    """Get member interfaces for a VLAN on ArcOS.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).

    Returns:
        List of interface names in the VLAN, or empty list.
    """
    vlan = get_vlan(device, vlan_id)
    if vlan is None:
        return []
    return vlan.get("members", [])


def get_vlan_count(device) -> int:
    """Get count of VLANs on ArcOS.

    Args:
        device: pyATS device object.

    Returns:
        Number of VLANs.
    """
    vlans = _parse_vlans(device)
    return len(vlans)


def get_vlan_name(device, vlan_id) -> Optional[str]:
    """Get the name of a specific VLAN on ArcOS.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).

    Returns:
        VLAN name string if found, None otherwise.
    """
    vlan = get_vlan(device, vlan_id)
    if vlan is None:
        return None
    return vlan.get("name")


def get_vlan_status(device, vlan_id) -> Optional[str]:
    """Get the status of a specific VLAN on ArcOS.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).

    Returns:
        VLAN status string (e.g., 'ACTIVE') if found, None otherwise.
    """
    vlan = get_vlan(device, vlan_id)
    if vlan is None:
        return None
    return vlan.get("status")


def is_vlan_present(device, vlan_id) -> bool:
    """Check if a VLAN exists on ArcOS.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).

    Returns:
        True if VLAN exists, False otherwise.
    """
    vlan = get_vlan(device, vlan_id)
    return vlan is not None
