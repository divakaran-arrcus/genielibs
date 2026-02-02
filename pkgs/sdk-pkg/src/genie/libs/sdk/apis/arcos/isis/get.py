"""ArcOS ISIS get APIs.

High-level helpers built on top of the upstream ArcOS ISIS parsers in
``genie.libs.parser.arcos.show_isis``.

These functions wrap ``device.parse("show isis ...")`` and return
simplified dictionaries for common use cases.
"""

from typing import Dict, Any, Optional
import logging
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

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


def get_isis_adjacency(
    device,
    adjacency: Optional[str] = None,
    interface: Optional[str] = None,
    instance: str = "default",
    level: Optional[int] = None,
) -> Dict[str, Any]:
    """Get ISIS adjacencies on ArcOS.

    Uses the upstream ArcOS ISIS adjacency parser via
    ``device.parse("show isis adjacency")``.
    
    Returns hierarchical structure: interface → level → adjacency.
    For L1/L2 routers, LEVEL_1_2 adjacencies appear in both levels.

    Args:
        device: pyATS device object.
        adjacency: Optional adjacency system-id filter (e.g., "rtr2" or "2222.2222.2222").
        interface: Optional interface filter (e.g., "swp1").
        instance: ISIS instance name (default: "default").
        level: Optional level filter (1 or 2).

    Returns:
        Dict with hierarchical structure (same as parser):
        {
            "interface": {
                "swp1": {
                    "level": {
                        2: {
                            "adjacency": {
                                "rtr1": {"state": "UP", ...}
                            }
                        }
                    }
                }
            }
        }
        
        If filters are provided, returns only matching data.
    """

    # Use full wildcard command - parser handles L1/L2 splitting internally
    try:
        cmd = f"show network-instance * protocol ISIS {instance} interface * level * adjacency"
        log.debug(f"get_isis_adjacency: executing command: {cmd}")
        parsed = device.parse(cmd)
        
        isis = _safe_get_isis(parsed, ni="default", instance=instance)
        interfaces = isis.get("interface", {}) or {}
        log.debug(f"get_isis_adjacency: found {len(interfaces)} interfaces")
                    
    except SchemaEmptyParserError:
        log.debug("get_isis_adjacency: SchemaEmptyParserError - no adjacencies found")
        interfaces = {}
    except SubCommandFailure as exc:
        log.debug(f"get_isis_adjacency: SubCommandFailure - {exc}")
        interfaces = {}
    except Exception as exc:
        log.warning(f"get_isis_adjacency: Unexpected exception - {exc}")
        import traceback
        log.warning(f"Traceback: {traceback.format_exc()}")
        interfaces = {}

    # Apply filters if provided
    if adjacency or interface or level is not None:
        filtered = {}
        
        for intf_name, intf_data in interfaces.items():
            # Skip if interface filter doesn't match
            if interface and intf_name != interface:
                continue
            
            levels = intf_data.get("level", {})
            
            # Apply level filter if provided
            if level is not None:
                if level not in levels:
                    continue
                levels_to_check = {level: levels[level]}
            else:
                levels_to_check = levels
            
            # Apply adjacency filter if provided
            if adjacency:
                filtered_levels = {}
                for lvl_num, lvl_data in levels_to_check.items():
                    adjacencies = lvl_data.get("adjacency", {})
                    # Match by system-id (key in adjacency dict)
                    if adjacency in adjacencies:
                        filtered_levels[lvl_num] = {
                            "adjacency": {adjacency: adjacencies[adjacency]}
                        }
                if filtered_levels:
                    filtered[intf_name] = {"level": filtered_levels}
            else:
                # No adjacency filter, include all
                if level is not None:
                    filtered[intf_name] = {"level": levels_to_check}
                else:
                    filtered[intf_name] = intf_data
        
        result = {"interface": filtered} if filtered else {}
    else:
        result = {"interface": interfaces} if interfaces else {}
    
    return result


def is_isis_adjacency_present(
    device,
    adjacency: str,
    instance: str = "default",
    interface: Optional[str] = None,
    level: Optional[int] = None,
) -> bool:
    """Check if a given ISIS adjacency is present.
    
    Args:
        device: pyATS device object.
        adjacency: Adjacency system-id to check.
        instance: ISIS instance name (default: "default").
        interface: Optional interface filter.
        level: Optional level filter (1 or 2).
    
    Returns:
        True if adjacency is found, False otherwise.
    """

    data = get_isis_adjacency(device, instance=instance, interface=interface, level=level)
    interfaces = data.get("interface", {})
    
    # Search through all interfaces and levels
    for intf_data in interfaces.values():
        for level_data in intf_data.get("level", {}).values():
            adjacencies = level_data.get("adjacency", {})
            if adjacency in adjacencies:
                return True
    return False


def get_isis_adjacency_state(
    device,
    adjacency: str,
    instance: str = "default",
    interface: Optional[str] = None,
    level: Optional[int] = None,
) -> Optional[str]:
    """Get ISIS adjacency state for a given adjacency.

    Args:
        device: pyATS device object.
        adjacency: Adjacency system-id.
        instance: ISIS instance name (default: "default").
        interface: Optional interface filter.
        level: Optional level filter (1 or 2).

    Returns:
        The raw state string (e.g. 'UP', 'DOWN', etc.) if present, None otherwise.
    """

    data = get_isis_adjacency(device, instance=instance, interface=interface, level=level)
    interfaces = data.get("interface", {})
    
    # Search through all interfaces and levels for the adjacency
    for intf_data in interfaces.values():
        for level_data in intf_data.get("level", {}).values():
            adjacencies = level_data.get("adjacency", {})
            if adjacency in adjacencies:
                entry = adjacencies[adjacency]
                return entry.get("state") or entry.get("adjacency-state")
    
    return None


def get_isis_adjacency_count(
    device, 
    instance: str = "default",
    interface: Optional[str] = None,
    level: Optional[int] = None,
) -> int:
    """Get ISIS adjacency count for an instance.
    
    Args:
        device: pyATS device object.
        instance: ISIS instance name (default: "default").
        interface: Optional interface filter.
        level: Optional level filter (1 or 2).
    
    Returns:
        Total count of adjacencies (including duplicates for LEVEL_1_2).
        For example, a LEVEL_1_2 adjacency appears in both L1 and L2 counts.
    """

    data = get_isis_adjacency(device, instance=instance, interface=interface, level=level)
    interfaces = data.get("interface", {})
    
    count = 0
    for intf_data in interfaces.values():
        for level_data in intf_data.get("level", {}).values():
            adjacencies = level_data.get("adjacency", {})
            count += len(adjacencies)
    
    return count


def get_isis_interface(
    device,
    interface: str,
    instance: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get ISIS interface information for a given interface on ArcOS."""

    try:
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} interface"
        )
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
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} global state"
        )
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
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} global state"
        )
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

    # Map address_family to AFI for command (IPV4/IPV6 for parser)
    afi_cmd_map = {
        "ipv4": "IPV4",
        "ipv6": "IPV6",
    }
    afi = afi_cmd_map.get(address_family.lower())
    if afi is None:
        raise ValueError(f"Unsupported address_family: {address_family}")
    
    # Map address_family to result key (IPV4-UNICAST/IPV6-UNICAST)
    af_map = {
        "ipv4": "IPV4-UNICAST",
        "ipv6": "IPV6-UNICAST",
    }
    af_key = af_map.get(address_family.lower())

    try:
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} global af {afi} UNICAST route"
        )
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
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} global state"
        )
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

    # Map address_family to AFI for command (IPV4/IPV6 for parser)
    afi_cmd_map = {
        "ipv4": "IPV4",
        "ipv6": "IPV6",
    }
    afi = afi_cmd_map.get(address_family.lower())
    if afi is None:
        raise ValueError(f"Unsupported address_family: {address_family}")
    
    # Map address_family to result key (IPV4-UNICAST/IPV6-UNICAST)
    af_map = {
        "ipv4": "IPV4-UNICAST",
        "ipv6": "IPV6-UNICAST",
    }
    af_key = af_map.get(address_family.lower())

    try:
        # Use specific route query for efficiency
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} global af {afi} UNICAST route {prefix}"
        )
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
        level: ISIS level ('level-1', 'level-2', 'level_1', 'level_2', '1', or '2').
        instance: ISIS instance name (default: "default").

    Returns:
        int: Number of LSPs for the specified level, or 0 if none found.

    Example:
        >>> l1_count = get_isis_lsp_count(device, 'level-1')
        >>> l2_count = get_isis_lsp_count(device, 'level-2')
        >>> print(f"L1 LSPs: {l1_count}, L2 LSPs: {l2_count}")
    """

    # Normalize level format to number (1 or 2) for command
    level_map = {
        'level_1': '1',
        'level_2': '2',
        'level-1': '1',
        'level-2': '2',
        '1': '1',
        '2': '2',
    }

    level_num = level_map.get(level)
    if level_num is None:
        log.warning(
            "Invalid ISIS level: %s (expected 'level-1', 'level-2', 'level_1', 'level_2', '1', or '2')", 
            level
        )
        return 0

    try:
        # Use full OpenConfig command with explicit level
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} level {level_num} link-state-database lsp"
        )
    except SchemaEmptyParserError:
        log.debug("No LSPs found for level %s", level)
        return 0
    except Exception as exc:
        log.error("Failed to get ISIS LSP database for level %s: %s", level, exc)
        return 0

    # Navigate to LSP database (matches ShowIsisLsp parser structure)
    ni_data = parsed.get("network-instance", {}).get("default", {})
    isis_data = ni_data.get("isis", {}).get(instance, {})
    lsp_db = isis_data.get("database", {})

    return len(lsp_db)
