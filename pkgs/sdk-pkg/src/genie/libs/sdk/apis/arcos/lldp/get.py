"""ArcOS LLDP get APIs.

High-level helpers built on top of the upstream ArcOS LLDP parsers:
- ``genie.libs.parser.arcos.show_lldp.ShowLldpState``
- ``genie.libs.parser.arcos.show_lldp.ShowLldpInterface``

These functions instantiate parsers directly (Genie's device.parse()
lookup does not auto-discover our parsers).
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_lldp import ShowLldpState, ShowLldpInterface

log = logging.getLogger(__name__)


# =====================================================================
# Parse helpers
# =====================================================================

def _parse_lldp_state(device) -> Dict[str, Any]:
    """Internal helper to parse ``show lldp state``.

    Returns:
        Parsed dict, or empty dict on error.
    """

    try:
        parser = ShowLldpState(device=device)
        parsed = parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse show lldp state: %s", exc)
        return {}

    return parsed or {}


def _parse_lldp_interface(
    device, interface: str = "*"
) -> Dict[str, Any]:
    """Internal helper to parse ``show lldp interface``.

    Args:
        device: pyATS device object.
        interface: Interface name or ``*`` for all.

    Returns:
        Parsed dict, or empty dict on error.
    """

    try:
        parser = ShowLldpInterface(device=device)
        parsed = parser.parse(interface=interface)
    except SchemaEmptyParserError:
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_lldp_interface: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse show lldp interface: %s", exc)
        return {}

    return parsed or {}


# =====================================================================
# Public get functions
# =====================================================================

def get_lldp_state(device) -> Dict[str, Any]:
    """Get global LLDP state on ArcOS.

    Returns hello-timer, system-name, system-description, and counters.

    Args:
        device: pyATS device object.

    Returns:
        Dict with global LLDP state fields.
        Returns empty dict if no data found or on error.
    """

    return _parse_lldp_state(device)


def get_lldp_interface(
    device, interface: str
) -> Optional[Dict[str, Any]]:
    """Get LLDP state for a specific interface.

    Args:
        device: pyATS device object.
        interface: Interface name (e.g., 'swp1', 'ma1').

    Returns:
        Dict with interface LLDP state and neighbors, or None if not found.
    """

    parsed = _parse_lldp_interface(device, interface=interface)
    interfaces = parsed.get("interfaces", {})

    if interface in interfaces:
        return interfaces[interface]

    # Fallback: if parser returned a single entry
    if len(interfaces) == 1:
        return next(iter(interfaces.values()))

    log.debug("get_lldp_interface: interface %s not found", interface)
    return None


def get_lldp_neighbors(device) -> Dict[str, Any]:
    """Get all LLDP interfaces that have neighbors.

    Filters out interfaces with no neighbor data.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by interface name, containing only interfaces with
        at least one neighbor. Returns empty dict if no neighbors found.
    """

    parsed = _parse_lldp_interface(device, interface="*")
    interfaces = parsed.get("interfaces", {})

    result = {}
    for intf_name, intf_data in interfaces.items():
        if intf_data.get("neighbors"):
            result[intf_name] = intf_data

    return result


def get_lldp_neighbor_count(device) -> int:
    """Get total count of LLDP neighbors across all interfaces.

    Args:
        device: pyATS device object.

    Returns:
        Total number of LLDP neighbors discovered.
    """

    parsed = _parse_lldp_interface(device, interface="*")
    interfaces = parsed.get("interfaces", {})

    count = 0
    for intf_data in interfaces.values():
        neighbors = intf_data.get("neighbors", {})
        count += len(neighbors)

    return count
