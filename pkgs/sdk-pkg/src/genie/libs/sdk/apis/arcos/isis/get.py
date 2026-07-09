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
        log.debug("get_isis_adjacency: executing command: %s", cmd)
        parsed = device.parse(cmd)

        isis = _safe_get_isis(parsed, ni="default", instance=instance)
        interfaces = isis.get("interface", {}) or {}
        log.debug("get_isis_adjacency: found %d interfaces", len(interfaces))
                    
    except SchemaEmptyParserError:
        log.debug("get_isis_adjacency: SchemaEmptyParserError - no adjacencies found")
        interfaces = {}
    except SubCommandFailure as exc:
        log.debug("get_isis_adjacency: SubCommandFailure - %s", exc)
        interfaces = {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("get_isis_adjacency: Unexpected exception - %s", exc)
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
                return entry.get("state") or entry.get("adjacency_state")
    
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
    return global_entry.get("system-id")


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
        # Use the parser directly with the prefix parameter
        # (device.parse() can't match commands with extra trailing args)
        from genie.libs.parser.arcos.show_isis import ShowIsisRoute
        parser = ShowIsisRoute(device=device)
        parsed = parser.parse(
            network_instance="default",
            protocol_instance=instance,
            afi=afi,
            prefix=prefix,
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
    except Exception as exc:  # pragma: no cover - defensive
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
    safi: str = "UNICAST",
) -> Optional[Dict[str, Any]]:
    """Get a specific redistributed route from ISIS.

    Uses the upstream ``ShowIsisRedistributeRoute`` parser via
    ``device.parse("show ... redistribute-route")``.

    Args:
        device: pyATS device object.
        prefix: Route prefix to look for (e.g., "100.100.100.0/24").
        instance: ISIS instance name (default: "default").
        afi: Address Family Identifier ("IPV4" or "IPV6").
        safi: Subsequent AFI (default: "UNICAST").

    Returns:
        Dict with route info (prefix, levels with metric/tag/source) or
        None if not found.
    """

    af_key = f"{afi}-{safi}"

    try:
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} "
            f"global af {afi} UNICAST redistribute-route"
        )
    except SchemaEmptyParserError:
        log.debug("No redistributed routes found for %s", af_key)
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS redistributed route for %s: %s", prefix, exc)
        return None

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    redist = isis.get("redistribute-routes", {})
    af_entry = redist.get(af_key, {})
    routes = af_entry.get("routes", {})

    return routes.get(prefix)


def get_isis_redis_routes(
    device,
    instance: str = "default",
    afi: str = "IPV4",
    safi: str = "UNICAST",
) -> List[Dict[str, Any]]:
    """Get all redistributed routes from ISIS.

    Uses the upstream ``ShowIsisRedistributeRoute`` parser via
    ``device.parse("show ... redistribute-route")``.

    Args:
        device: pyATS device object.
        instance: ISIS instance name (default: "default").
        afi: Address Family Identifier ("IPV4" or "IPV6").
        safi: Subsequent AFI (default: "UNICAST").

    Returns:
        List of dicts, each containing 'prefix' and 'levels' info.
    """

    af_key = f"{afi}-{safi}"

    try:
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} "
            f"global af {afi} UNICAST redistribute-route"
        )
    except SchemaEmptyParserError:
        log.debug("No redistributed routes found for %s", af_key)
        return []
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS redistributed routes for %s: %s", af_key, exc)
        return []

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    redist = isis.get("redistribute-routes", {})
    af_entry = redist.get(af_key, {})
    routes = af_entry.get("routes", {})

    return list(routes.values())


def get_isis_redis_route_source(
    device,
    prefix: str,
    instance: str = "default",
    afi: str = "IPV4",
    safi: str = "UNICAST",
) -> Optional[Dict[str, Any]]:
    """Get redistribution source info for an ISIS route.

    Retrieves source-identifier, metric, and route-tag from the parsed
    redistribute-route data for the first level entry found.

    Args:
        device: pyATS device object.
        prefix: Route prefix to look for (e.g., "100.100.100.0/24").
        instance: ISIS instance name (default: "default").
        afi: Address Family Identifier ("IPV4" or "IPV6").
        safi: Subsequent AFI (default: "UNICAST").

    Returns:
        Dict with redistribution source info, or None if route not found.
        Example::

            {
                'is_redistributed': True,
                'original_prefix': '100.100.100.0/24',
                'source_protocol': 'STATIC',
                'tag': 1000,
                'metric': 10,
            }
    """

    route = get_isis_redis_route(device, prefix, instance, afi, safi)
    if not route:
        return None

    # Extract source info from first level entry
    levels = route.get("levels", {})
    source_protocol = None
    tag = None
    metric = None

    for level_data in levels.values():
        source_protocol = level_data.get("source-identifier", source_protocol)
        tag = level_data.get("route-tag", tag)
        metric = level_data.get("metric", metric)
        break  # use first level entry

    return {
        "is_redistributed": True,
        "original_prefix": prefix,
        "source_protocol": source_protocol,
        "tag": tag,
        "metric": metric,
    }


def get_isis_lsp(
    device,
    level: Optional[str] = None,
    lsp_id: Optional[str] = None,
    instance: str = "default",
) -> List[Dict[str, Any]]:
    """Get LSPs from ISIS link-state database.

    Uses the upstream ``ShowIsisLsp`` parser via
    ``device.parse("show ... link-state-database lsp")``.

    Args:
        device: pyATS device object.
        level: ISIS level ('level-1', 'level-2', 'level_1', 'level_2',
               '1', '2') or None for all levels (wildcard).
        lsp_id: Optional specific LSP ID to filter (e.g., 'rtr1.00-00').
        instance: ISIS instance name (default: "default").

    Returns:
        List of LSP entry dicts from the parser database, each containing
        at minimum 'lsp-id' and optional fields like 'sequence',
        'checksum', 'remaining-lifetime', 'system-id', 'tlvs', etc.
    """

    # Normalize level format to number for command, or use wildcard
    level_num = "*"
    if level is not None:
        level_map = {
            "level_1": "1",
            "level_2": "2",
            "level-1": "1",
            "level-2": "2",
            "1": "1",
            "2": "2",
        }
        level_num = level_map.get(level)
        if level_num is None:
            log.warning(
                "Invalid ISIS level: %s (expected 'level-1', 'level-2', "
                "'level_1', 'level_2', '1', or '2')",
                level,
            )
            return []

    try:
        parsed = device.parse(
            f"show network-instance default protocol ISIS {instance} "
            f"level {level_num} link-state-database lsp"
        )
    except SchemaEmptyParserError:
        log.debug("No LSPs found for level %s", level)
        return []
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to get ISIS LSP database for level %s: %s", level, exc)
        return []

    ni_data = parsed.get("network-instance", {}).get("default", {})
    isis_data = ni_data.get("isis", {}).get(instance, {})
    lsp_db = isis_data.get("database", {})

    lsps = list(lsp_db.values())

    # Apply optional lsp_id filter
    if lsp_id:
        lsps = [lsp for lsp in lsps if lsp.get("lsp-id", "").startswith(lsp_id)]

    return lsps


def get_isis_global_timers(
    device,
    instance: str = "default",
    network_instance: str = "default",
) -> Dict[str, Any]:
    """Get ISIS global timer configuration on ArcOS.

    Uses the upstream ArcOS ISIS global timers parser via
    ``device.parse("show network-instance ... protocol ISIS ... global timers")``.

    Args:
        device: pyATS device object.
        instance: ISIS protocol instance name (default: "default").
        network_instance: Network instance name (default: "default").

    Returns:
        Dict with ISIS timer values, or empty dict if not found:

        .. code-block:: python

            {
                "lsp-lifetime-interval": 1200,
                "lsp-refresh-interval": 600,
                "lsp-flood-delay-adj-up": 0,
                "spf": {
                    "spf-hold-interval": "5000",
                    "spf-first-interval": "50",
                    "spf-second-interval": "200",
                    "spf-mla-interval": "25",
                },
            }

        Returns empty dict on error or if no timers configured.
    """

    cmd = (
        f"show network-instance {network_instance} protocol ISIS {instance} global timers"
    )
    log.debug("get_isis_global_timers: executing command: %s", cmd)

    try:
        parsed = device.parse(cmd)
    except SchemaEmptyParserError:
        log.debug("get_isis_global_timers: SchemaEmptyParserError - no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("get_isis_global_timers: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("get_isis_global_timers: Unexpected exception - %s", exc)
        return {}

    instance_data = _safe_get_isis(parsed, ni=network_instance, instance=instance)
    timers = instance_data.get("timers", {})

    log.debug("get_isis_global_timers: returning timers: %s", timers)
    return timers


# ---------------------------------------------------------------------------
# Flex-Algo Get APIs
# ---------------------------------------------------------------------------

def get_isis_flex_algo_routes(
    device,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
) -> Dict[str, Any]:
    """Get ISIS flex-algo routes for a given AF and algorithm.

    Args:
        device: pyATS device object.
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID (e.g., '128') or '*' for all.
        instance: ISIS instance name (default: "default").

    Returns:
        Dict: algorithms → {algo_id → {routes → {prefix → route_data}}},
        or empty dict if none found.
    """
    try:
        from genie.libs.parser.arcos.show_isis import ShowIsisFlexAlgoRoute
        parser = ShowIsisFlexAlgoRoute(device=device)
        parsed = parser.parse(
            network_instance="default",
            protocol_instance=instance,
            afi=afi,
            algo=algo,
        )
    except SchemaEmptyParserError:
        log.debug("get_isis_flex_algo_routes: no data found")
        return {}
    except Exception as exc:
        log.warning("get_isis_flex_algo_routes: %s", exc)
        return {}

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    return isis.get("flex-algo-routes", {})


def get_isis_flex_algo_route(
    device,
    prefix: str,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a specific ISIS flex-algo route by prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '10.0.0.0/24').
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*' for all.
        instance: ISIS instance name.

    Returns:
        Dict with route data if found, None otherwise.
    """
    try:
        from genie.libs.parser.arcos.show_isis import ShowIsisFlexAlgoRoute
        parser = ShowIsisFlexAlgoRoute(device=device)
        parsed = parser.parse(
            network_instance="default",
            protocol_instance=instance,
            afi=afi,
            algo=algo,
            prefix=prefix,
        )
    except SchemaEmptyParserError:
        log.debug("get_isis_flex_algo_route: prefix %s not found", prefix)
        return None
    except Exception as exc:
        log.warning("get_isis_flex_algo_route: %s", exc)
        return None

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    flex_routes = isis.get("flex-algo-routes", {})

    # Search through AF entries and algorithms for the prefix
    for af_data in flex_routes.values():
        algorithms = af_data.get("algorithms", {})
        for algo_data in algorithms.values():
            routes = algo_data.get("routes", {})
            if prefix in routes:
                return routes[prefix]

    return None


def get_isis_flex_algo_route_count(
    device,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
) -> int:
    """Get count of ISIS flex-algo routes.

    Args:
        device: pyATS device object.
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*' for all.
        instance: ISIS instance name.

    Returns:
        Total number of flex-algo routes across all algorithms.
    """
    flex_routes = get_isis_flex_algo_routes(device, afi=afi, algo=algo, instance=instance)

    count = 0
    for af_data in flex_routes.values():
        algorithms = af_data.get("algorithms", {})
        for algo_data in algorithms.values():
            routes = algo_data.get("routes", {})
            count += len(routes)

    return count


def is_isis_flex_algo_route_present(
    device,
    prefix: str,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
) -> bool:
    """Check if an ISIS flex-algo route exists.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check.
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*'.
        instance: ISIS instance name.

    Returns:
        True if route found, False otherwise.
    """
    route = get_isis_flex_algo_route(
        device, prefix=prefix, afi=afi, algo=algo, instance=instance
    )
    return route is not None


def get_isis_flex_algo_fast_reroute(
    device,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
) -> Dict[str, Any]:
    """Get ISIS flex-algo fast-reroute entries for a given AF and algorithm.

    Args:
        device: pyATS device object.
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*' for all.
        instance: ISIS instance name.

    Returns:
        Dict of flex-algo FRR data, or empty dict if none found.
    """
    try:
        from genie.libs.parser.arcos.show_isis import ShowIsisFlexAlgoFastReroute
        parser = ShowIsisFlexAlgoFastReroute(device=device)
        parsed = parser.parse(
            network_instance="default",
            protocol_instance=instance,
            afi=afi,
            algo=algo,
        )
    except SchemaEmptyParserError:
        log.debug("get_isis_flex_algo_fast_reroute: no data found")
        return {}
    except Exception as exc:
        log.warning("get_isis_flex_algo_fast_reroute: %s", exc)
        return {}

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    return isis.get("flex-algo-fast-reroute", {})


def get_isis_flex_algo_definitions(
    device,
    instance: str = "default",
    network_instance: str = "default",
) -> Dict[str, Any]:
    """Get ISIS flex-algo definitions from running config.

    Uses the ShowIsisConfig parser to extract flexible-algorithm definitions.

    Args:
        device: pyATS device object.
        instance: ISIS protocol instance name.
        network_instance: Network instance name.

    Returns:
        Dict of flex-algo definitions keyed by algorithm ID string,
        or empty dict if none found.
    """
    try:
        from genie.libs.parser.arcos.show_isis import ShowIsisConfig
        parser = ShowIsisConfig(device=device)
        parsed = parser.parse(
            network_instance=network_instance,
            protocol_instance=instance,
        )
    except SchemaEmptyParserError:
        log.debug("get_isis_flex_algo_definitions: no data found")
        return {}
    except Exception as exc:
        log.warning("get_isis_flex_algo_definitions: %s", exc)
        return {}

    isis = _safe_get_isis(parsed, ni=network_instance, instance=instance)
    # ShowIsisConfig puts data under config.global.flexible-algorithms
    config_data = isis.get("config", isis)
    global_data = config_data.get("global", {})
    return global_data.get("flexible-algorithms", {})


def get_isis_flex_algo_definition(
    device,
    algo_id: int,
    instance: str = "default",
    network_instance: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a specific ISIS flex-algo definition by algorithm ID.

    Args:
        device: pyATS device object.
        algo_id: Flexible-algorithm ID (128-255).
        instance: ISIS protocol instance name.
        network_instance: Network instance name.

    Returns:
        Dict with definition data (id, metric-type, advertise-definition-enabled),
        or None if not found.
    """
    definitions = get_isis_flex_algo_definitions(
        device, instance=instance, network_instance=network_instance
    )
    return definitions.get(str(algo_id))


def get_isis_flex_algo_fast_reroutes(
    device,
    algo: int,
    afi: str = "IPV4",
    instance: str = "default",
) -> Dict[str, Any]:
    """Get all flex-algo fast-reroute prefix entries for an algorithm.

    Args:
        device: pyATS device object.
        algo: Flexible-algorithm ID (e.g., 128).
        afi: Address family ('IPV4' or 'IPV6').
        instance: ISIS instance name.

    Returns:
        Dict of prefix entries keyed by prefix string, each with
        levels containing reroute-type, metric, nexthop info.
        Empty dict if none found.
    """

    frr_data = get_isis_flex_algo_fast_reroute(
        device, afi=afi, algo=str(algo), instance=instance
    )

    # Navigate: af_key → algorithms → algo_id → prefixes
    af_key = f"{afi}-UNICAST"
    af_entry = frr_data.get(af_key, {})
    algorithms = af_entry.get("algorithms", {})
    algo_entry = algorithms.get(str(algo), {})

    return algo_entry.get("prefixes", {})


def is_isis_flex_algo_fast_reroute_present(
    device,
    prefix: str,
    algo: int,
    afi: str = "IPV4",
    instance: str = "default",
) -> bool:
    """Check if a flex-algo fast-reroute entry exists for a prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '3.3.3.3/32').
        algo: Flexible-algorithm ID.
        afi: Address family.
        instance: ISIS instance name.

    Returns:
        True if FRR entry exists for the prefix, False otherwise.
    """

    prefixes = get_isis_flex_algo_fast_reroutes(
        device, algo=algo, afi=afi, instance=instance
    )
    return prefix in prefixes


# ---------------------------------------------------------------------------
# TI-LFA / MLA Get APIs (2026-05-13)
# Wrappers over ShowIsisFastReroute and ShowIsisProtectionTracker parsers.
# Note: global tunnel container is intentionally not wrapped here — the
# ShowIsisGlobalTunnel parser is parked until Jericho-2 hardware data is
# available (see orchestrator/proposals/parked/show_isis_global_tunnel.md).
# ---------------------------------------------------------------------------

def get_isis_fast_reroute(
    device,
    prefix: Optional[str] = None,
    address_family: str = "ipv4",
    instance: str = "default",
) -> Dict[str, Any]:
    """Get ISIS fast-reroute (TI-LFA / MLA) computation entries.

    Wraps the ``ShowIsisFastReroute`` parser via ``device.parse``. Returns
    parsed fast-reroute data either for a single prefix or all prefixes in
    the requested address family. The deep parser hierarchy
    (``network-instance.<ni>.isis.<pi>.fast-reroute.<AF>-UNICAST.prefixes``)
    is flattened so the caller gets a prefix-keyed dict directly.

    Args:
        device: pyATS device object.
        prefix: Specific prefix to query (e.g., '6.6.6.6/32'). If None,
            returns all fast-reroute entries for the address family.
        address_family: 'ipv4' or 'ipv6'. Default 'ipv4'.
        instance: ISIS instance name. Default 'default'.

    Returns:
        Dict keyed by prefix. Each value contains the per-level fast-reroute
        state (reroute-type, protection-types, flags, pq-node, nexthop info).
        Empty dict {} if no entries or on parser error.

    Example:
        >>> entries = get_isis_fast_reroute(device, prefix='6.6.6.6/32')
        >>> if '6.6.6.6/32' in entries:
        ...     for level, lvl_data in entries['6.6.6.6/32']['levels'].items():
        ...         print(lvl_data['reroute-type'], lvl_data.get('pq-node-system-id'))
    """
    afi_cmd_map = {"ipv4": "IPV4", "ipv6": "IPV6"}
    afi = afi_cmd_map.get(address_family.lower())
    if afi is None:
        raise ValueError(f"Unsupported address_family: {address_family}")

    af_map = {"ipv4": "IPV4-UNICAST", "ipv6": "IPV6-UNICAST"}
    af_key = af_map.get(address_family.lower())

    try:
        from genie.libs.parser.arcos.show_isis import ShowIsisFastReroute
        parser = ShowIsisFastReroute(device=device)
        parse_kwargs = dict(
            network_instance="default",
            protocol_instance=instance,
            afi=afi,
        )
        if prefix:
            parse_kwargs["prefix"] = prefix
        parsed = parser.parse(**parse_kwargs)
    except SchemaEmptyParserError:
        log.debug("get_isis_fast_reroute: no data for prefix=%s af=%s", prefix, afi)
        return {}
    except SubCommandFailure as exc:
        log.debug("get_isis_fast_reroute: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("get_isis_fast_reroute: unexpected error — %s", exc)
        return {}

    isis = _safe_get_isis(parsed, ni="default", instance=instance)
    af_data = isis.get("fast-reroute", {}).get(af_key, {})
    prefixes = af_data.get("prefixes", {}) or {}
    return prefixes


def get_isis_protection_trackers(
    device,
    instance: str = "default",
) -> Dict[str, Any]:
    """Get all ISIS protection-tracker entries.

    Wraps the ``ShowIsisProtectionTracker`` parser via ``device.parse`` and
    returns the inner tracker-id-keyed dict directly, hiding the deep
    parser hierarchy
    (``network-instance.<ni>.isis.<pi>.global.protection-trackers.protection-tracker``).

    Args:
        device: pyATS device object.
        instance: ISIS instance name. Default 'default'.

    Returns:
        Dict keyed by tracker-id (str). Each value contains the
        tracker's state fields (id, reference-count, interface, system-id,
        last-updated-time, plus optional BFD fields when BFD is enabled
        on the protected interface). Empty dict {} when no trackers are
        programmed or on parser error.

    Example:
        >>> trackers = get_isis_protection_trackers(device)
        >>> for tid, t in trackers.items():
        ...     print(tid, t['interface'], t['system-id'])
    """
    try:
        from genie.libs.parser.arcos.show_isis import ShowIsisProtectionTracker
        parser = ShowIsisProtectionTracker(device=device)
        parsed = parser.parse(
            network_instance="default",
            protocol_instance=instance,
        )
    except SchemaEmptyParserError:
        log.debug("get_isis_protection_trackers: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("get_isis_protection_trackers: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("get_isis_protection_trackers: unexpected error — %s", exc)
        return {}

    global_data = _safe_get_global(parsed, ni="default", instance=instance)
    container = global_data.get("protection-trackers", {}) or {}
    return container.get("protection-tracker", {}) or {}


def get_isis_micro_loop_avoidance(
    device,
    network_instance: str = "default",
    protocol_instance: str = "default",
) -> Dict[str, Any]:
    """Get ISIS global micro-loop-avoidance operational state.

    Wraps the ``ShowIsisMicroLoopAvoidance`` parser. Returns the flattened
    micro-loop-avoidance dict::

        {
          "srv6-enabled": bool,
          "rib-update-delay": int,
          "status": {"<idx>": {"algo": int, "level": int, "topology-id": str,
                               "mla-state": "ACTIVE"|"EXPIRED", "last-event": str,
                               "near-node": str, "far-node": str,
                               "spf-start-timestamp": str}},
        }

    The MLA *status* rows durably record the last MLA event per topology —
    this is the control-plane observable for micro-loop avoidance (the ISIS
    fast-reroute table does NOT surface MLA on VIR, and a 0-segment MLA where
    the pre-convergence path equals the new primary installs no FR route).

    Returns ``{}`` if MLA is not present/configured or on any parse error.
    """
    try:
        from genie.libs.parser.arcos.show_isis import ShowIsisMicroLoopAvoidance

        parser = ShowIsisMicroLoopAvoidance(device=device)
        parsed = parser.parse(
            network_instance=network_instance,
            protocol_instance=protocol_instance,
        )
    except SchemaEmptyParserError:
        return {}
    except SubCommandFailure as exc:
        log.error("get_isis_micro_loop_avoidance failed: %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("get_isis_micro_loop_avoidance: unexpected error — %s", exc)
        return {}

    # Parser nests under the (hardcoded) default NI/instance; navigate
    # defensively so a non-default NI name still resolves.
    for ni in (parsed.get("network-instance", {}) or {}).values():
        for pi in (ni.get("isis", {}) or {}).values():
            mla = (pi.get("global", {}) or {}).get("micro-loop-avoidance")
            if mla is not None:
                return mla
    return {}
