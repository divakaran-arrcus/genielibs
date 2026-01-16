"""ArcOS ISIS get APIs.

High-level helpers built on top of the upstream ArcOS ISIS parsers in
``genie.libs.parser.arcos.show_isis``.

These functions wrap ``device.parse("show isis ...")`` and return
simplified dictionaries for common use cases.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from genie.metaparser.util.exceptions import SchemaEmptyParserError

log = logging.getLogger(__name__)


def _safe_get_isis(
    data: Dict[str, Any], ni: str = "default", instance: str = "default"
) -> Dict[str, Any]:
    """Helper to navigate to ISIS instance data."""

    ni_root = data.get("network-instance", {}).get(ni, {})
    isis_root = ni_root.get("isis", {})
    return isis_root.get(instance, {}) or {}


def _safe_get_global(
    data: Dict[str, Any], ni: str = "default", instance: str = "default"
) -> Dict[str, Any]:
    """Helper to navigate to global ISIS state data."""

    ni_root = data.get("network-instance", {}).get(ni, {})
    isis_root = ni_root.get("isis", {}).get(instance, {})
    return isis_root.get("global", {}) or {}


def get_isis_neighbors(
    device,
    instance: str = "default",
    interface: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """Get ISIS neighbors on ArcOS.

    Uses the upstream ArcOS ISIS adjacency parser via
    ``device.parse("show isis adjacency")``.

    Args:
        device: pyATS device object.
        instance: ISIS instance name (default: "default").
        interface: Optional interface filter; if provided, only neighbors
                   on this interface are returned.

    Returns:
        Dict mapping neighbor system-id -> neighbor info dict.
    """

    try:
        parsed = device.parse("show isis adjacency")
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS neighbors: %s", exc)
        return {}

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    neighbors = isis.get("neighbors", {}) or {}

    if interface:
        neighbors = {
            sys_id: info
            for sys_id, info in neighbors.items()
            if info.get("interface") == interface
        }

    return neighbors


def is_isis_neighbor_present(
    device,
    neighbor: str,
    instance: str = "default",
    interface: Optional[str] = None,
) -> bool:
    """Check if a given ISIS neighbor is present."""

    neighs = get_isis_neighbors(device, instance=instance, interface=interface)
    return neighbor in neighs


def get_isis_adjacency_state(
    device,
    neighbor: str,
    instance: str = "default",
    interface: Optional[str] = None,
) -> Optional[str]:
    """Get ISIS adjacency state for a given neighbor.

    Returns the raw state string (e.g. 'UP', 'DOWN', etc.) if present.
    """

    neighs = get_isis_neighbors(device, instance=instance, interface=interface)
    entry = neighs.get(neighbor)
    if not entry:
        return None

    # The parser stores adjacency state under 'state' or 'adjacency-state'
    state = entry.get("state") or entry.get("adjacency-state")
    return state


def get_isis_neighbor_count(device, instance: str = "default") -> int:
    """Get total ISIS neighbor count for an instance."""

    neighbors = get_isis_neighbors(device, instance=instance)
    return len(neighbors)


def get_isis_interface_information(
    device,
    interface: str,
    instance: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get ISIS interface information for a given interface on ArcOS."""

    try:
        parsed = device.parse("show isis interface")
    except SchemaEmptyParserError:
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.error(
            "Failed to get ISIS interface information for %s: %s",
            interface,
            exc,
        )
        return None

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    interfaces = isis.get("interfaces", {}) or {}
    return interfaces.get(interface)


def get_isis_system_id(device, instance: str = "default") -> Optional[str]:
    """Get ISIS system-id for an ArcOS instance."""

    try:
        parsed = device.parse("show isis global")
    except SchemaEmptyParserError:
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS system-id: %s", exc)
        return None

    global_entry = _safe_get_global(parsed, ni="default", instance=instance)
    return global_entry.get("system_id")


def get_isis_net(device, instance: str = "default") -> Optional[str]:
    """Get ISIS NET (first NET in list) for an ArcOS instance.

    Returns the first NET string if available.
    """

    try:
        parsed = device.parse("show isis global")
    except SchemaEmptyParserError:
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS NET: %s", exc)
        return None

    global_entry = _safe_get_global(parsed, ni="default", instance=instance)
    nets = global_entry.get("net") or []
    if isinstance(nets, list) and nets:
        return nets[0]
    return None


def get_isis_routes(
    device,
    address_family: str = "ipv4",
    instance: str = "default",
) -> Dict[str, Dict[str, Any]]:
    """Get ISIS routes for a given address-family on ArcOS.

    Args:
        device: pyATS device object.
        address_family: 'ipv4' or 'ipv6'.
        instance: ISIS instance name (currently always 'default' on ArcOS).

    Returns:
        Dict of prefix -> route info dict for the selected AF.
    """

    af_map = {
        "ipv4": "IPV4-UNICAST",
        "ipv6": "IPV6-UNICAST",
    }
    af_key = af_map.get(address_family.lower())
    if af_key is None:
        raise ValueError(f"Unsupported address_family: {address_family}")

    try:
        parsed = device.parse("show isis route")
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS routes for %s: %s", address_family, exc)
        return {}

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    routes_root = isis.get("routes", {}) or {}
    af_entry = routes_root.get(af_key, {}) or {}
    return af_entry.get("routes", {}) or {}


def get_isis_global(device, instance: str = "default") -> Dict[str, Any]:
    """Get raw ISIS global state for an ArcOS instance.

    Wrapper around the parsed output of 'show isis global'.
    """

    try:
        parsed = device.parse("show isis global")
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS global state: %s", exc)
        return {}

    return _safe_get_global(parsed, ni="default", instance=instance)


def get_isis_route(
    device,
    prefix: str,
    address_family: str = "ipv4",
    instance: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a single ISIS route by prefix.

    Uses 'show isis route <prefix>' to directly query a specific route
    instead of fetching all routes.

    Args:
        device: pyATS device object.
        prefix: Route prefix to search for (e.g., '5.5.5.5/32' or '5.5.5.5').
        address_family: 'ipv4' or 'ipv6'.
        instance: ISIS instance name (default: "default").

    Returns:
        Dict with route information including next-hops, or None if not found.
        Example:
            {
                'prefix': '5.5.5.5/32',
                'metric': 20,
                'next_hops': {
                    '1': {
                        'address': '10.1.5.5',
                        'interface': 'swp1',
                        'metric': 10
                    },
                    '2': {
                        'address': '10.2.5.5',
                        'interface': 'swp2',
                        'metric': 10
                    }
                }
            }

    Example:
        >>> route = get_isis_route(device, '5.5.5.5/32')
        >>> if route:
        ...     next_hops = route.get('next_hops', {})
        ...     nh_count = len(next_hops)
        ...     print(f"Route has {nh_count} next-hops")
    """

    af_map = {
        "ipv4": "IPV4-UNICAST",
        "ipv6": "IPV6-UNICAST",
    }
    af_key = af_map.get(address_family.lower())
    if af_key is None:
        raise ValueError(f"Unsupported address_family: {address_family}")

    try:
        # Use specific route query for efficiency
        parsed = device.parse(f"show isis route {prefix}")
    except SchemaEmptyParserError:
        log.debug("Route %s not found in ISIS routing table", prefix)
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS route for %s: %s", prefix, exc)
        return None

    # Navigate to the specific route
    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    routes_root = isis.get("routes", {}) or {}
    af_entry = routes_root.get(af_key, {}) or {}
    routes = af_entry.get("routes", {}) or {}

    # The parser should return the specific route
    # Try exact match first
    if prefix in routes:
        return routes[prefix]

    # Fallback: try any route in the result (parser may normalize prefix)
    if len(routes) == 1:
        return list(routes.values())[0]

    # Fuzzy match as last resort
    prefix_base = prefix.split('/')[0]
    for route_key, route_data in routes.items():
        route_prefix_base = route_data.get("prefix", route_key).split('/')[0]
        if prefix_base == route_prefix_base:
            return route_data

    log.debug("Route %s not found in ISIS routing table", prefix)
    return None


def get_isis_lsp_count(
    device,
    level: str,
    instance: str = "default",
) -> int:
    """Get count of LSPs in ISIS database for a specific level.

    Args:
        device: pyATS device object.
        level: ISIS level ('level_1' or 'level_2').
        instance: ISIS instance name (default: "default").

    Returns:
        int: Number of LSPs for the specified level, or 0 if none found.

    Example:
        >>> l1_count = get_isis_lsp_count(device, 'level_1')
        >>> l2_count = get_isis_lsp_count(device, 'level_2')
        >>> print(f"L1 LSPs: {l1_count}, L2 LSPs: {l2_count}")
    """

    # Map API level format to parser output format
    level_map = {
        'level_1': 'Level 1',
        'level_2': 'Level 2',
        'Level 1': 'Level 1',
        'Level 2': 'Level 2',
    }

    target_level = level_map.get(level)
    if target_level is None:
        log.warning("Invalid ISIS level: %s (expected 'level_1' or 'level_2')", level)
        return 0

    try:
        parsed = device.parse("show isis database")
    except SchemaEmptyParserError:
        return 0
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS database: %s", exc)
        return 0

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    lsps = isis.get("lsps", {}) or {}

    # Count LSPs for the target level
    count = 0
    for lsp_id, lsp_data in lsps.items():
        if lsp_data.get("level") == target_level:
            count += 1

    return count
