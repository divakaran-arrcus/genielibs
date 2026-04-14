"""ArcOS OSPF get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_ospf import (
    ShowOspfGlobal,
    ShowOspfNeighbor,
    ShowOspfArea,
    ShowOspfInterface,
    ShowOspfSpfThrottle,
    ShowOspfLsdb,
)

log = logging.getLogger(__name__)


def get_ospf_global(device) -> Dict[str, Any]:
    """Get OSPF global state."""
    try:
        parser = ShowOspfGlobal(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF global: %s", exc)
        return {}


def get_ospf_router_id(device) -> Optional[str]:
    """Get OSPF router-id."""
    data = get_ospf_global(device)
    return data.get("router-id")


def get_ospf_neighbor_count(device) -> int:
    """Get OSPF neighbor count."""
    data = get_ospf_global(device)
    return data.get("full-neighbor-count", 0)


def get_ospf_neighbors(device, area="*") -> Dict[str, Any]:
    """Get OSPF neighbors."""
    try:
        parser = ShowOspfNeighbor(device=device)
        result = parser.parse(area=area)
        return result.get("neighbors", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF neighbors: %s", exc)
        return {}


def is_ospf_neighbor_full(device, neighbor_rid, area="*") -> bool:
    """Check if an OSPF neighbor is in FULL state."""
    nbrs = get_ospf_neighbors(device, area=area)
    for key, nbr in nbrs.items():
        if nbr.get("neighbor-router-id") == neighbor_rid:
            return nbr.get("adjacency-state") == "NEIGHBOR_FULL"
    return False


# ---------------------------------------------------------------------------
# ShowOspfArea APIs
# ---------------------------------------------------------------------------

def get_ospf_areas(device) -> Dict[str, Any]:
    """Get all OSPF areas with operational state.

    Returns:
        Dict keyed by area ID (str), e.g. {"0": {...}, "1": {...}}.
    """
    try:
        parser = ShowOspfArea(device=device)
        result = parser.parse()
        return result.get("areas", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF areas: %s", exc)
        return {}


def get_ospf_area(device, area_id: str) -> Optional[Dict[str, Any]]:
    """Get a single OSPF area by ID.

    Args:
        device: pyATS device object.
        area_id: Area identifier (e.g. "0", "1").

    Returns:
        Dict with area state, or None if not found.
    """
    areas = get_ospf_areas(device)
    return areas.get(str(area_id))


def get_ospf_area_count(device) -> int:
    """Get the number of OSPF areas."""
    return len(get_ospf_areas(device))


def get_ospf_area_type(device, area_id: str) -> Optional[str]:
    """Get the area type for a specific OSPF area.

    Returns:
        Area type string (e.g. "AREA_TYPE_NORMAL", "AREA_TYPE_STUB"),
        or None if area not found.
    """
    area = get_ospf_area(device, area_id)
    if not area:
        return None
    return area.get("area-type")


# ---------------------------------------------------------------------------
# ShowOspfInterface APIs
# ---------------------------------------------------------------------------

def get_ospf_interfaces(device, area="*") -> Dict[str, Any]:
    """Get all OSPF interfaces grouped by area.

    Returns:
        Dict keyed by area ID, each containing an "interfaces" dict.
    """
    try:
        parser = ShowOspfInterface(device=device)
        result = parser.parse(area=area)
        return result.get("areas", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF interfaces: %s", exc)
        return {}


def get_ospf_interface(
    device, interface: str, area: str = "*",
) -> Optional[Dict[str, Any]]:
    """Get OSPF state for a specific interface.

    Args:
        device: pyATS device object.
        interface: Interface name (e.g. "swp1", "loopback0").
        area: Area filter (default "*" for all areas).

    Returns:
        Dict with interface state, or None if not found.
    """
    areas = get_ospf_interfaces(device, area=area)
    for area_data in areas.values():
        intfs = area_data.get("interfaces", {})
        if interface in intfs:
            return intfs[interface]
    return None


def get_ospf_interface_metric(
    device, interface: str, area: str = "*",
) -> Optional[int]:
    """Get the OSPF metric for a specific interface."""
    intf = get_ospf_interface(device, interface, area=area)
    if not intf:
        return None
    return intf.get("metric")


def is_ospf_interface_passive(
    device, interface: str, area: str = "*",
) -> Optional[bool]:
    """Check if an OSPF interface is passive."""
    intf = get_ospf_interface(device, interface, area=area)
    if not intf:
        return None
    return intf.get("passive")


# ---------------------------------------------------------------------------
# ShowOspfSpfThrottle APIs
# ---------------------------------------------------------------------------

def get_ospf_spf_throttle(device) -> Dict[str, Any]:
    """Get OSPF SPF throttle timer configuration.

    Returns:
        Dict with spf-initial-delay, spf-short-delay, spf-long-delay,
        time-to-learn-interval, holddown-interval.
    """
    try:
        parser = ShowOspfSpfThrottle(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF SPF throttle: %s", exc)
        return {}


def get_ospf_spf_initial_delay(device) -> Optional[int]:
    """Get the OSPF SPF initial delay in milliseconds."""
    data = get_ospf_spf_throttle(device)
    return data.get("spf-initial-delay")


# ---------------------------------------------------------------------------
# ShowOspfLsdb APIs
# ---------------------------------------------------------------------------

def get_ospf_lsdb(device, area="*") -> Dict[str, Any]:
    """Get OSPF LSDB grouped by area.

    Returns:
        Dict keyed by area ID, each containing "lsa-types" dict.
    """
    try:
        parser = ShowOspfLsdb(device=device)
        result = parser.parse(area=area)
        return result.get("areas", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF LSDB: %s", exc)
        return {}


def get_ospf_lsdb_lsa_count(device, area: str = "0",
                             lsa_type: str = "ROUTER_LSA") -> int:
    """Get count of LSAs of a specific type in an area."""
    lsdb = get_ospf_lsdb(device)
    area_data = lsdb.get(str(area), {})
    lsa_types = area_data.get("lsa-types", {})
    type_data = lsa_types.get(lsa_type, {})
    return len(type_data.get("lsas", {}))
