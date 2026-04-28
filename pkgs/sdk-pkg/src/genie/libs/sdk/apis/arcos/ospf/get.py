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
                             lsa_type: Optional[str] = None) -> int:
    """Get count of LSAs in an area, optionally filtered by LSA type.

    Args:
        device: pyATS device object.
        area: Area identifier (default "0").
        lsa_type: Specific LSA type to count (e.g. "ROUTER_LSA",
            "NETWORK_LSA", "SUMMARY_IP_NETWORK_LSA",
            "SUMMARY_ROUTER_LSA", "AS_EXTERNAL_LSA"). If None,
            returns the total count across all LSA types in the area.
    """
    lsdb = get_ospf_lsdb(device)
    area_data = lsdb.get(str(area), {})
    lsa_types = area_data.get("lsa-types", {})

    if lsa_type is None:
        # Total across all types in the area
        return sum(
            len(td.get("lsas", {})) for td in lsa_types.values()
        )

    type_data = lsa_types.get(lsa_type, {})
    return len(type_data.get("lsas", {}))


# ---------------------------------------------------------------------------
# Batch A — OSPF RIB / route APIs
# ---------------------------------------------------------------------------

def get_ospf_route(device, prefix: str,
                   network_instance: str = "default",
                   protocol_instance: str = "default") -> Optional[Dict[str, Any]]:
    """Get OSPF route entry for a specific prefix from the OSPF Global RIB.

    Args:
        device: pyATS device object.
        prefix: IPv4 prefix (e.g. "4.4.4.4/32", "10.0.0.0/24").
        network_instance: Network instance name (default "default").
        protocol_instance: OSPF protocol instance name (default "default").

    Returns:
        Dict with route info::

            {
                "prefix": "4.4.4.4/32",
                "path-type": "intra-area" | "inter-area"
                             | "external-type-1" | "external-type-2"
                             | "intra-area-connected",
                "metric": int,
                "area": "1",
                "next-hops": [
                    {"interface": "swp2", "address": "10.14.2.4"},
                    ...
                ],
            }

        or None if the prefix is not found.
    """
    try:
        from genie.libs.parser.arcos.show_ospf import (  # type: ignore
            ShowOspfGlobalRib,
        )
    except ImportError:
        log.warning(
            "get_ospf_route: ShowOspfGlobalRib parser not available — "
            "returning None. Generate the parser via arcos-parser-gen."
        )
        return None

    try:
        parser = ShowOspfGlobalRib(device=device)
        result = parser.parse(ni=network_instance, instance=protocol_instance)
    except SchemaEmptyParserError:
        return None
    except Exception as exc:
        log.error("get_ospf_route(%s) failed: %s", prefix, exc)
        return None

    routes = result.get("routes", {}) if isinstance(result, dict) else {}
    return routes.get(prefix)


def get_ospf_routes(device,
                    network_instance: str = "default",
                    protocol_instance: str = "default") -> Dict[str, Any]:
    """Get the full OSPF RIB keyed by prefix.

    Returns an empty dict if the parser fails or no routes are present.
    """
    try:
        from genie.libs.parser.arcos.show_ospf import (  # type: ignore
            ShowOspfGlobalRib,
        )
    except ImportError:
        log.warning(
            "get_ospf_routes: ShowOspfGlobalRib parser not available"
        )
        return {}

    try:
        parser = ShowOspfGlobalRib(device=device)
        result = parser.parse(ni=network_instance, instance=protocol_instance)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("get_ospf_routes failed: %s", exc)
        return {}

    return result.get("routes", {}) if isinstance(result, dict) else {}
