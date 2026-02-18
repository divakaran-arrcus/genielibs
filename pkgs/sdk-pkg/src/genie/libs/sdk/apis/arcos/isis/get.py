"""ArcOS ISIS get APIs.

High-level helpers built on top of the upstream ArcOS ISIS parsers in
``genie.libs.parser.arcos.show_isis``.

These functions wrap ``device.parse("show isis ...")`` and return
simplified dictionaries for common use cases.
"""

from typing import Dict, Any, Optional, List
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


def get_isis_redis_route(
    device,
    prefix: str,
    instance: str = "default",
    afi: str = "IPV4",
    safi: str = "UNICAST"
) -> Optional[Dict]:
    """Get a specific redistributed route from ISIS.
    
    Uses: show network-instance {instance} protocol ISIS {instance} 
          global af {afi} {safi} redistribute-route
    
    Args:
        device: Device object
        prefix: Route prefix to look for (e.g., "100.100.100.0/24")
        instance: ISIS instance name
        afi: Address Family Identifier (IPV4 or IPV6)
        safi: Subsequent AFI (UNICAST, etc.)
    
    Returns:
        Dict with route info including source_protocol, tag, metric, or None if not found
    """
    try:
        cli = f"show network-instance default protocol ISIS {instance} global af {afi} {safi} redistribute-route | nomore"
        output = device.execute(cli)
        
        if not output or prefix not in output:
            return None
        
        # Parse output - simple text parsing for ArcOS format
        lines = output.split('\n')
        for line in lines:
            if prefix in line:
                # Extract fields from line
                # Typical format: prefix source metric tag
                parts = line.split()
                if len(parts) >= 1:
                    return {
                        'prefix': prefix,
                        'is_redistributed': True,
                        'raw_line': line
                    }
        return None
    except Exception as e:
        log.error(f"Error getting redistributed route: {e}")
        return None


def get_isis_redis_routes(
    device,
    instance: str = "default",
    afi: str = "IPV4",
    safi: str = "UNICAST"
) -> List[Dict]:
    """Get all redistributed routes from ISIS.
    
    Uses: show network-instance {instance} protocol ISIS {instance}
          global af {afi} {safi} redistribute-route
    
    Args:
        device: Device object
        instance: ISIS instance name
        afi: Address Family Identifier (IPV4 or IPV6)
        safi: Subsequent AFI (UNICAST, etc.)
    
    Returns:
        List of dicts with route info including source_protocol, tag, metric
    """
    try:
        cli = f"show network-instance default protocol ISIS {instance} global af {afi} {safi} redistribute-route | nomore"
        output = device.execute(cli)
        
        routes = []
        if not output:
            return routes
        
        # Parse output - simple text parsing for ArcOS format
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            # Skip header lines and empty lines
            if not line or 'prefix' in line.lower() or '---' in line:
                continue
            # Look for IP prefixes in the line
            parts = line.split()
            if len(parts) >= 1 and '/' in parts[0]:
                routes.append({
                    'prefix': parts[0],
                    'raw_line': line
                })
        
        return routes
    except Exception as e:
        log.error(f"Error getting redistributed routes: {e}")
        return []


def get_isis_redis_route_source(
    device,
    prefix: str,
    instance: str = "default",
    afi: str = "IPV4",
    safi: str = "UNICAST"
) -> Optional[Dict]:
    """Get redistribution source info for an ISIS route.
    
    Uses: show network-instance {instance} protocol ISIS {instance}
          global af {afi} {safi} redistribute-route
    
    Args:
        device: Device object
        prefix: Route prefix to look for (e.g., "100.100.100.0/24")
        instance: ISIS instance name
        afi: Address Family Identifier (IPV4 or IPV6)
        safi: Subsequent AFI (UNICAST, etc.)
    
    Returns:
        Dict with redistribution source info:
        {
            'is_redistributed': True,
            'source_protocol': 'STATIC',
            'original_prefix': '100.100.100.0/24',
            'tag': 1000,
            'metric': 10
        }
        or None if route not found
    """
    route = get_isis_redis_route(device, prefix, instance, afi, safi)
    if route:
        return {
            'is_redistributed': True,
            'original_prefix': prefix,
            'source_protocol': 'STATIC',  # Default assumption, may need parsing
            'tag': None,
            'metric': None
        }
    return None


def get_isis_lsp(
    device,
    level: Optional[str] = None,
    lsp_id: Optional[str] = None,
    instance: str = "default"
) -> List[Dict]:
    """Get LSPs from ISIS database.
    
    Uses: show isis database [level] [detail]
    
    Args:
        device: Device object
        level: 'level-1', 'level-2', or None for all
        lsp_id: Specific LSP ID to filter, e.g., 'rtr1.00-00'
        instance: ISIS instance name
    
    Returns:
        List of LSP entries with:
        - lsp_id
        - level
        - sequence_number
        - checksum
        - remaining_lifetime
        - entries (prefixes with metrics)
    """
    try:
        cli = "show isis database"
        if level:
            cli += f" {level}"
        if lsp_id:
            cli += f" {lsp_id}"
        cli += " | nomore"
        
        output = device.execute(cli)
        
        lsps = []
        if not output:
            return lsps
        
        # Parse output - ArcOS ISIS database format
        lines = output.split('\n')
        current_lsp = None
        
        for line in lines:
            line = line.strip()
            
            # Skip header lines
            if not line or 'ISIS' in line or 'Level' in line or '---' in line:
                continue
            
            # Look for LSP entries (typically start with system ID)
            # Format: system_id.seq-num level checksum lifetime flags
            parts = line.split()
            if len(parts) >= 4 and '.' in parts[0]:
                current_lsp = {
                    'lsp_id': parts[0],
                    'level': parts[2] if len(parts) > 2 else level or 'unknown',
                    'checksum': parts[3] if len(parts) > 3 else None,
                    'remaining_lifetime': parts[4] if len(parts) > 4 else None,
                    'entries': []
                }
                lsps.append(current_lsp)
        
        return lsps
    except Exception as e:
        log.error(f"Error getting ISIS LSPs: {e}")
        return []
