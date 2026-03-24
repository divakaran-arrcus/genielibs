"""ArcOS BGP get APIs.

High-level helpers built on top of the upstream ArcOS BGP parsers in
``genie.libs.parser.arcos.show_bgp``.

These functions wrap the BGP parsers and return simplified dictionaries
for common use cases.
"""

from typing import Dict, Any, Optional, List
import logging
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_bgp_neighbors(device, network_instance='default',
                          protocol_instance='default', neighbor=None):
    """Parse BGP neighbor data using ShowBgpNeighbor parser.

    Args:
        device: pyATS device object.
        network_instance: Network instance name.
        protocol_instance: BGP protocol instance name.
        neighbor: Optional specific neighbor address.

    Returns:
        Dict of neighbors keyed by address, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_bgp import ShowBgpNeighbor
        parser = ShowBgpNeighbor(device=device)
        parsed = parser.parse(
            network_instance=network_instance,
            protocol_instance=protocol_instance,
            neighbor=neighbor,
        )
    except SchemaEmptyParserError:
        log.debug("_parse_bgp_neighbors: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_bgp_neighbors: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_bgp_neighbors: Unexpected exception - %s", exc)
        return {}

    return parsed.get("neighbors", {})


def _parse_bgp_global_state(device, network_instance='default',
                              protocol_instance='default'):
    """Parse BGP global state using ShowBgpGlobalState parser.

    Args:
        device: pyATS device object.
        network_instance: Network instance name.
        protocol_instance: BGP protocol instance name.

    Returns:
        Dict of global state fields, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_bgp import ShowBgpGlobalState
        parser = ShowBgpGlobalState(device=device)
        parsed = parser.parse(
            network_instance=network_instance,
            protocol_instance=protocol_instance,
        )
    except SchemaEmptyParserError:
        log.debug("_parse_bgp_global_state: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_bgp_global_state: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_bgp_global_state: Unexpected exception - %s", exc)
        return {}

    return parsed


def _parse_bgp_afi_safis(device, network_instance='default',
                           protocol_instance='default'):
    """Parse BGP global AFI-SAFI data using ShowBgpGlobalAfiSafi parser.

    Args:
        device: pyATS device object.
        network_instance: Network instance name.
        protocol_instance: BGP protocol instance name.

    Returns:
        Dict of AFI-SAFIs keyed by name, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_bgp import ShowBgpGlobalAfiSafi
        parser = ShowBgpGlobalAfiSafi(device=device)
        parsed = parser.parse(
            network_instance=network_instance,
            protocol_instance=protocol_instance,
        )
    except SchemaEmptyParserError:
        log.debug("_parse_bgp_afi_safis: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_bgp_afi_safis: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_bgp_afi_safis: Unexpected exception - %s", exc)
        return {}

    return parsed.get("afi-safis", {})


def _parse_bgp_rib_routes(device, afi_safi='IPV4_UNICAST', prefix=None,
                            network_instance='default',
                            protocol_instance='default'):
    """Parse BGP RIB routes using ShowBgpRibRoute parser.

    Args:
        device: pyATS device object.
        afi_safi: AFI-SAFI name (e.g., 'IPV4_UNICAST').
        prefix: Optional specific prefix to query.
        network_instance: Network instance name.
        protocol_instance: BGP protocol instance name.

    Returns:
        Dict of routes keyed by prefix, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_bgp import ShowBgpRibRoute
        parser = ShowBgpRibRoute(device=device)
        parsed = parser.parse(
            network_instance=network_instance,
            protocol_instance=protocol_instance,
            afi_safi=afi_safi,
            prefix=prefix,
        )
    except SchemaEmptyParserError:
        log.debug("_parse_bgp_rib_routes: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_bgp_rib_routes: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_bgp_rib_routes: Unexpected exception - %s", exc)
        return {}

    return parsed.get("routes", {})


# ---------------------------------------------------------------------------
# Public get APIs — Global state
# ---------------------------------------------------------------------------

def get_bgp_global_state(device, network_instance='default',
                          protocol_instance='default') -> Dict[str, Any]:
    """Get BGP global state on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Dict with BGP global state fields (as, router-id, total-paths, etc.),
        or empty dict if not found.
    """
    return _parse_bgp_global_state(device, network_instance, protocol_instance)


def get_bgp_as_number(device, network_instance='default',
                       protocol_instance='default') -> Optional[int]:
    """Get BGP autonomous system number on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        AS number as int if available, None otherwise.
    """
    state = _parse_bgp_global_state(device, network_instance, protocol_instance)
    as_val = state.get("as")
    if as_val is not None:
        try:
            return int(as_val)
        except (ValueError, TypeError):
            return as_val
    return None


def get_bgp_router_id(device, network_instance='default',
                       protocol_instance='default') -> Optional[str]:
    """Get BGP router-id on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Router-id string if available, None otherwise.
    """
    state = _parse_bgp_global_state(device, network_instance, protocol_instance)
    return state.get("router-id")


# ---------------------------------------------------------------------------
# Public get APIs — Neighbors
# ---------------------------------------------------------------------------

def get_bgp_neighbors(device, network_instance='default',
                       protocol_instance='default') -> Dict[str, Any]:
    """Get all BGP neighbors on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Dict of neighbors keyed by neighbor address, or empty dict.
    """
    return _parse_bgp_neighbors(device, network_instance, protocol_instance)


def get_bgp_neighbor(device, neighbor, network_instance='default',
                      protocol_instance='default') -> Optional[Dict[str, Any]]:
    """Get a specific BGP neighbor on ArcOS.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address (e.g., '10.0.0.1').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Dict with neighbor data if found, None otherwise.
    """
    neighbors = _parse_bgp_neighbors(
        device, network_instance, protocol_instance, neighbor=neighbor
    )
    return neighbors.get(neighbor)


def get_bgp_neighbor_state(device, neighbor, network_instance='default',
                             protocol_instance='default') -> Optional[str]:
    """Get BGP neighbor session state on ArcOS.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address (e.g., '10.0.0.1').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Session state string (e.g., 'ESTABLISHED', 'ACTIVE') if found,
        None otherwise.
    """
    nbr = get_bgp_neighbor(device, neighbor, network_instance, protocol_instance)
    if nbr is None:
        return None
    return nbr.get("session-state")


def get_bgp_neighbor_count(device, network_instance='default',
                             protocol_instance='default') -> int:
    """Get count of BGP neighbors on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Number of BGP neighbors.
    """
    neighbors = _parse_bgp_neighbors(device, network_instance, protocol_instance)
    return len(neighbors)


def is_bgp_neighbor_present(device, neighbor, network_instance='default',
                              protocol_instance='default') -> bool:
    """Check if a BGP neighbor is present on ArcOS.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address to check.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        True if neighbor is found, False otherwise.
    """
    nbr = get_bgp_neighbor(device, neighbor, network_instance, protocol_instance)
    return nbr is not None


# ---------------------------------------------------------------------------
# Public get APIs — AFI-SAFIs
# ---------------------------------------------------------------------------

def get_bgp_afi_safis(device, network_instance='default',
                       protocol_instance='default') -> Dict[str, Any]:
    """Get all BGP global AFI-SAFIs on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Dict of AFI-SAFIs keyed by name (e.g., 'IPV4_UNICAST'), or empty dict.
    """
    return _parse_bgp_afi_safis(device, network_instance, protocol_instance)


def get_bgp_afi_safi(device, afi_safi, network_instance='default',
                      protocol_instance='default') -> Optional[Dict[str, Any]]:
    """Get a specific BGP global AFI-SAFI on ArcOS.

    Args:
        device: pyATS device object.
        afi_safi: AFI-SAFI name (e.g., 'IPV4_UNICAST').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Dict with AFI-SAFI data if found, None otherwise.
    """
    afi_safis = _parse_bgp_afi_safis(device, network_instance, protocol_instance)
    return afi_safis.get(afi_safi)


# ---------------------------------------------------------------------------
# Public get APIs — Routes (RIB)
# ---------------------------------------------------------------------------

def get_bgp_routes(device, afi_safi='IPV4_UNICAST',
                    network_instance='default',
                    protocol_instance='default') -> Dict[str, Any]:
    """Get all BGP RIB routes for an AFI-SAFI on ArcOS.

    Args:
        device: pyATS device object.
        afi_safi: AFI-SAFI name (default: 'IPV4_UNICAST').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Dict of routes keyed by prefix, or empty dict.
    """
    return _parse_bgp_rib_routes(
        device, afi_safi=afi_safi,
        network_instance=network_instance,
        protocol_instance=protocol_instance,
    )


def get_bgp_route(device, prefix, afi_safi='IPV4_UNICAST',
                    network_instance='default',
                    protocol_instance='default') -> Optional[Dict[str, Any]]:
    """Get a specific BGP RIB route on ArcOS.

    Uses the prefix parameter for efficient single-route fetch.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '10.0.0.0/24').
        afi_safi: AFI-SAFI name (default: 'IPV4_UNICAST').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Dict with route data (including 'paths' list) if found, None otherwise.
    """
    routes = _parse_bgp_rib_routes(
        device, afi_safi=afi_safi, prefix=prefix,
        network_instance=network_instance,
        protocol_instance=protocol_instance,
    )
    if prefix in routes:
        return routes[prefix]

    # Fallback: if parser normalized the prefix, return first match
    if len(routes) == 1:
        return list(routes.values())[0]

    return None


def is_bgp_route_present(device, prefix, afi_safi='IPV4_UNICAST',
                           network_instance='default',
                           protocol_instance='default') -> bool:
    """Check if a BGP route is present in the RIB on ArcOS.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check (e.g., '10.0.0.0/24').
        afi_safi: AFI-SAFI name (default: 'IPV4_UNICAST').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        True if route is found, False otherwise.
    """
    route = get_bgp_route(
        device, prefix, afi_safi=afi_safi,
        network_instance=network_instance,
        protocol_instance=protocol_instance,
    )
    return route is not None


def get_bgp_route_count(device, afi_safi='IPV4_UNICAST',
                          network_instance='default',
                          protocol_instance='default') -> int:
    """Get count of BGP RIB routes for an AFI-SAFI on ArcOS.

    Args:
        device: pyATS device object.
        afi_safi: AFI-SAFI name (default: 'IPV4_UNICAST').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").

    Returns:
        Number of routes in the RIB.
    """
    routes = _parse_bgp_rib_routes(
        device, afi_safi=afi_safi,
        network_instance=network_instance,
        protocol_instance=protocol_instance,
    )
    return len(routes)


# ---------------------------------------------------------------------------
# Internal helper — Running config
# ---------------------------------------------------------------------------

def _parse_bgp_running_config(device, network_instance='default'):
    """Parse BGP running configuration using ShowBgpConfig parser.

    Args:
        device: pyATS device object.
        network_instance: Network instance name.

    Returns:
        Dict with the BGP instance data for the given NI,
        or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_bgp import ShowBgpConfig
        parser = ShowBgpConfig(device=device)
        parsed = parser.parse(network_instance=network_instance)
    except SchemaEmptyParserError:
        log.debug("_parse_bgp_running_config: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_bgp_running_config: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_bgp_running_config: Unexpected exception - %s", exc)
        return {}

    # Navigate to first BGP instance within the NI
    ni_data = parsed.get("network-instance", {}).get(network_instance, {})
    bgp_instances = ni_data.get("bgp", {})
    if not bgp_instances:
        return {}

    # Return the first (typically "default") BGP instance
    first_key = next(iter(bgp_instances))
    return bgp_instances[first_key]


# ---------------------------------------------------------------------------
# Public get APIs — Running config
# ---------------------------------------------------------------------------

def get_bgp_running_config(device,
                            network_instance='default') -> Dict[str, Any]:
    """Get full BGP running configuration on ArcOS.

    Uses the ShowBgpConfig parser to retrieve the parsed running-config
    with namespace prefixes stripped and structure flattened.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").

    Returns:
        Dict with keys 'config', 'neighbors', 'peer-groups' (all optional),
        or empty dict if BGP is not configured.
    """
    return _parse_bgp_running_config(device, network_instance)


def get_bgp_running_config_global(device,
                                    network_instance='default') -> Dict[str, Any]:
    """Get BGP global running configuration on ArcOS.

    Returns the 'config' section which contains global scalars
    (as, router-id, adj-rib-out-post, etc.) and afi-safis.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").

    Returns:
        Dict with global config fields, or empty dict.
    """
    inst = _parse_bgp_running_config(device, network_instance)
    return inst.get("config", {})


def get_bgp_running_config_neighbors(device,
                                       network_instance='default') -> Dict[str, Any]:
    """Get all BGP neighbor configurations from running-config on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").

    Returns:
        Dict of neighbors keyed by address, or empty dict.
    """
    inst = _parse_bgp_running_config(device, network_instance)
    return inst.get("neighbors", {})


def get_bgp_running_config_neighbor(device, neighbor,
                                      network_instance='default') -> Optional[Dict[str, Any]]:
    """Get a specific BGP neighbor configuration from running-config on ArcOS.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address (IPv4 or IPv6).
        network_instance: Network instance name (default: "default").

    Returns:
        Dict with neighbor config data if found, None otherwise.
    """
    neighbors = get_bgp_running_config_neighbors(device, network_instance)
    return neighbors.get(neighbor)


def get_bgp_running_config_peer_groups(device,
                                         network_instance='default') -> Dict[str, Any]:
    """Get all BGP peer-group configurations from running-config on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").

    Returns:
        Dict of peer-groups keyed by name, or empty dict.
    """
    inst = _parse_bgp_running_config(device, network_instance)
    return inst.get("peer-groups", {})


def get_bgp_running_config_peer_group(device, peer_group,
                                        network_instance='default') -> Optional[Dict[str, Any]]:
    """Get a specific BGP peer-group configuration from running-config on ArcOS.

    Args:
        device: pyATS device object.
        peer_group: Peer-group name.
        network_instance: Network instance name (default: "default").

    Returns:
        Dict with peer-group config data if found, None otherwise.
    """
    peer_groups = get_bgp_running_config_peer_groups(device, network_instance)
    return peer_groups.get(peer_group)
