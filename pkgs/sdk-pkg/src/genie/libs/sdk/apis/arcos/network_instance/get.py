"""ArcOS Network Instance get APIs.

High-level helpers built on top of the upstream ArcOS Network Instance parser
``genie.libs.parser.arcos.show_network_instance.ShowNetworkInstance``.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def _parse_network_instance(device, ni_name: str) -> Dict[str, Any]:
    """Parse network instance data using ShowNetworkInstance parser.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.

    Returns:
        Dict with the NI entry, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_network_instance import ShowNetworkInstance
        parser = ShowNetworkInstance(device=device)
        parsed = parser.parse(network_instance=ni_name)
    except SchemaEmptyParserError:
        log.debug("_parse_network_instance: no data for NI=%s", ni_name)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_network_instance: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_network_instance: Unexpected exception - %s", exc)
        return {}

    return parsed.get("network-instance", {}).get(ni_name, {})


def get_network_instance(device, ni_name: str) -> Optional[Dict[str, Any]]:
    """Get full data for a specific network instance on ArcOS.

    Args:
        device: pyATS device object.
        ni_name: Network instance name (e.g., 'default', 'vlan100', 'vrf-3001').

    Returns:
        Dict with NI data (interfaces, fdb, l2rib, bgp, table-connections,
        rib-options, l3vrf), or None if not found.
    """
    result = _parse_network_instance(device, ni_name)
    return result if result else None


def get_network_instance_interfaces(device, ni_name: str) -> Dict[str, Any]:
    """Get interfaces bound to a network instance on ArcOS.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.

    Returns:
        Dict of interfaces keyed by interface ID, or empty dict.
    """
    ni_data = _parse_network_instance(device, ni_name)
    return ni_data.get("interfaces", {})


def get_network_instance_fdb_mac_entries(device, ni_name: str) -> Dict[str, Any]:
    """Get FDB MAC table entries for a network instance on ArcOS.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.

    Returns:
        Dict of MAC entries keyed by MAC address, or empty dict.
    """
    ni_data = _parse_network_instance(device, ni_name)
    fdb = ni_data.get("fdb", {})
    return fdb.get("mac-entries", {})


def get_network_instance_fdb_mac_count(device, ni_name: str) -> int:
    """Get count of FDB MAC entries for a network instance on ArcOS.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.

    Returns:
        Number of MAC entries in the FDB.
    """
    entries = get_network_instance_fdb_mac_entries(device, ni_name)
    return len(entries)


def get_network_instance_l2rib(device, ni_name: str) -> Dict[str, Any]:
    """Get L2RIB state for a network instance on ArcOS.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.

    Returns:
        Dict with L2RIB state fields (id, name, type, vni,
        advertise-mac-routes, mac-count, etc.), or empty dict.
    """
    ni_data = _parse_network_instance(device, ni_name)
    return ni_data.get("l2rib", {})


def is_network_instance_present(device, ni_name: str) -> bool:
    """Check if a network instance exists on ArcOS.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.

    Returns:
        True if the NI exists, False otherwise.
    """
    result = _parse_network_instance(device, ni_name)
    return bool(result)
