"""ArcOS OSPFv3 get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_ospfv3 import (
    ShowOspfv3Global,
    ShowOspfv3Neighbor,
    ShowOspfv3Area,
    ShowOspfv3Interface,
    ShowOspfv3SpfThrottle,
    ShowOspfv3Lsdb,
)

log = logging.getLogger(__name__)


def get_ospfv3_global(device) -> Dict[str, Any]:
    """Get OSPFv3 global state."""
    try:
        parser = ShowOspfv3Global(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 global: %s", exc)
        return {}


def get_ospfv3_router_id(device) -> Optional[str]:
    """Get OSPFv3 router-id."""
    data = get_ospfv3_global(device)
    return data.get("router-id")


def get_ospfv3_neighbor_count(device) -> int:
    """Get OSPFv3 neighbor count."""
    data = get_ospfv3_global(device)
    return data.get("full-neighbor-count", 0)


def get_ospfv3_neighbors(device, area="*") -> Dict[str, Any]:
    """Get OSPFv3 neighbors."""
    try:
        parser = ShowOspfv3Neighbor(device=device)
        result = parser.parse(area=area)
        return result.get("neighbors", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 neighbors: %s", exc)
        return {}


def is_ospfv3_neighbor_full(device, neighbor_rid, area="*") -> bool:
    """Check if an OSPFv3 neighbor is in FULL state."""
    nbrs = get_ospfv3_neighbors(device, area=area)
    for key, nbr in nbrs.items():
        if nbr.get("neighbor-router-id") == neighbor_rid:
            return nbr.get("adjacency-state") == "NEIGHBOR_FULL"
    return False


# ---------------------------------------------------------------------------
# Areas
# ---------------------------------------------------------------------------

def get_ospfv3_areas(device, area="*") -> Dict[str, Any]:
    """Get all OSPFv3 areas with operational state."""
    try:
        parser = ShowOspfv3Area(device=device)
        result = parser.parse(area=area)
        return result.get("areas", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 areas: %s", exc)
        return {}


def get_ospfv3_area(device, area_id: str) -> Optional[Dict[str, Any]]:
    """Get a single OSPFv3 area by ID."""
    areas = get_ospfv3_areas(device)
    return areas.get(str(area_id))


def get_ospfv3_area_count(device) -> int:
    """Get the number of OSPFv3 areas."""
    return len(get_ospfv3_areas(device))


def get_ospfv3_area_type(device, area_id: str) -> Optional[str]:
    """Get the area type for a specific OSPFv3 area."""
    area = get_ospfv3_area(device, area_id)
    if not area:
        return None
    return area.get("area-type")


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

def get_ospfv3_interfaces(device, area="*") -> Dict[str, Any]:
    """Get all OSPFv3 interfaces grouped by area."""
    try:
        parser = ShowOspfv3Interface(device=device)
        result = parser.parse(area=area)
        return result.get("areas", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 interfaces: %s", exc)
        return {}


def get_ospfv3_interface(
    device, interface: str, area: str = "*",
) -> Optional[Dict[str, Any]]:
    """Get OSPFv3 state for a specific interface."""
    areas = get_ospfv3_interfaces(device, area=area)
    for area_data in areas.values():
        intfs = area_data.get("interfaces", {})
        if interface in intfs:
            return intfs[interface]
    return None


def get_ospfv3_interface_metric(
    device, interface: str, area: str = "*",
) -> Optional[int]:
    """Get the OSPFv3 metric for a specific interface."""
    intf = get_ospfv3_interface(device, interface, area=area)
    if not intf:
        return None
    return intf.get("metric")


def is_ospfv3_interface_passive(
    device, interface: str, area: str = "*",
) -> Optional[bool]:
    """Check if an OSPFv3 interface is passive."""
    intf = get_ospfv3_interface(device, interface, area=area)
    if not intf:
        return None
    return intf.get("passive")


# ---------------------------------------------------------------------------
# SPF throttle
# ---------------------------------------------------------------------------

def get_ospfv3_spf_throttle(device) -> Dict[str, Any]:
    """Get OSPFv3 SPF throttle timer configuration."""
    try:
        parser = ShowOspfv3SpfThrottle(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 SPF throttle: %s", exc)
        return {}


def get_ospfv3_spf_initial_delay(device) -> Optional[int]:
    """Get the OSPFv3 SPF initial delay (ms)."""
    data = get_ospfv3_spf_throttle(device)
    return data.get("spf-initial-delay")


# ---------------------------------------------------------------------------
# LSDB
# ---------------------------------------------------------------------------

def get_ospfv3_lsdb(device, area="*") -> Dict[str, Any]:
    """Get OSPFv3 LSDB grouped by area."""
    try:
        parser = ShowOspfv3Lsdb(device=device)
        result = parser.parse(area=area)
        return result.get("areas", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 LSDB: %s", exc)
        return {}


def get_ospfv3_lsdb_lsa_count(device, area: str = "0",
                                lsa_type: Optional[str] = None) -> int:
    """Get count of LSAs in an area, optionally filtered by LSA type.

    OSPFv3 LSA types include ROUTER_LSA, NETWORK_LSA, INTER_AREA_PREFIX_LSA,
    INTER_AREA_ROUTER_LSA, AS_EXTERNAL_LSA, LINK_LSA, INTRA_AREA_PREFIX_LSA.
    Pass ``lsa_type=None`` for total across all types.
    """
    lsdb = get_ospfv3_lsdb(device)
    area_data = lsdb.get(str(area), {})
    lsa_types = area_data.get("lsa-types", {})

    if lsa_type is None:
        return sum(len(td.get("lsas", {})) for td in lsa_types.values())

    type_data = lsa_types.get(lsa_type, {})
    return len(type_data.get("lsas", {}))


# ---------------------------------------------------------------------------
# Routes (OSPFv3 Global RIB)
# ---------------------------------------------------------------------------

def get_ospfv3_route(device, prefix: str,
                      network_instance: str = "default",
                      protocol_instance: str = "default") -> Optional[Dict[str, Any]]:
    """Get OSPFv3 route entry for a specific IPv6 prefix from the global RIB.

    Returns None if the prefix isn't found or the parser is unavailable.
    """
    try:
        from genie.libs.parser.arcos.show_ospfv3 import (  # type: ignore
            ShowOspfv3GlobalRib,
        )
    except ImportError:
        log.warning(
            "get_ospfv3_route: ShowOspfv3GlobalRib parser not available"
        )
        return None

    try:
        parser = ShowOspfv3GlobalRib(device=device)
        result = parser.parse(ni=network_instance, instance=protocol_instance)
    except SchemaEmptyParserError:
        return None
    except Exception as exc:
        log.error("get_ospfv3_route(%s) failed: %s", prefix, exc)
        return None

    routes = result.get("routes", {}) if isinstance(result, dict) else {}
    return routes.get(prefix)


def get_ospfv3_routes(device,
                       network_instance: str = "default",
                       protocol_instance: str = "default") -> Dict[str, Any]:
    """Get the full OSPFv3 RIB keyed by IPv6 prefix."""
    try:
        from genie.libs.parser.arcos.show_ospfv3 import (  # type: ignore
            ShowOspfv3GlobalRib,
        )
    except ImportError:
        log.warning("get_ospfv3_routes: parser not available")
        return {}

    try:
        parser = ShowOspfv3GlobalRib(device=device)
        result = parser.parse(ni=network_instance, instance=protocol_instance)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("get_ospfv3_routes failed: %s", exc)
        return {}

    return result.get("routes", {}) if isinstance(result, dict) else {}
