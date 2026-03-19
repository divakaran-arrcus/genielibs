"""ArcOS static routing get APIs."""

from __future__ import annotations

from typing import Any, Dict, Optional

import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_static_routing import ShowStaticRoutingConfig

log = logging.getLogger(__name__)


def _parse_static_routing(
    device,
    ni: str = "default",
    pi: str = "default",
) -> Dict[str, Any]:
    """Parse static routing configuration from the device.

    Args:
        device: Device object.
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        Parsed dictionary from ShowStaticRoutingConfig, or empty dict
        on any error.
    """
    try:
        parser = ShowStaticRoutingConfig(device=device)
        return parser.parse(network_instance=ni, protocol_instance=pi)
    except SchemaEmptyParserError:
        log.debug(
            "No static routing data found on %s (ni=%s, pi=%s)",
            device.name, ni, pi,
        )
        return {}
    except SubCommandFailure as exc:
        log.error(
            "Command failure retrieving static routing on %s: %s",
            device.name, exc,
        )
        return {}
    except Exception as exc:
        log.error(
            "Unexpected error retrieving static routing on %s: %s",
            device.name, exc,
        )
        return {}


def _get_static_routes_data(
    parsed: Dict[str, Any],
    ni: str = "default",
    pi: str = "default",
) -> Dict[str, Any]:
    """Navigate parsed output to the static-routes dictionary.

    Args:
        parsed: Parsed output from ShowStaticRoutingConfig.
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        The ``static-routes`` dictionary, or empty dict if not found.
    """
    return (
        parsed
        .get("network-instances", {})
        .get(ni, {})
        .get("protocols", {})
        .get(pi, {})
        .get("static-routes", {})
    )


def get_static_routes(
    device,
    ni: str = "default",
    pi: str = "default",
) -> Dict[str, Any]:
    """Get all static routes configured on the device.

    Args:
        device: Device object.
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        Dictionary of static routes keyed by prefix, or empty dict
        if none are found.
    """
    parsed = _parse_static_routing(device, ni=ni, pi=pi)
    return _get_static_routes_data(parsed, ni=ni, pi=pi)


def get_static_route(
    device,
    prefix: str,
    ni: str = "default",
    pi: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a single static route by prefix.

    Args:
        device: Device object.
        prefix: Route prefix (e.g. ``'100.100.100.0/24'``).
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        Route dictionary for the given prefix, or ``None`` if not found.
    """
    routes = get_static_routes(device, ni=ni, pi=pi)
    return routes.get(prefix)


def get_static_route_count(
    device,
    ni: str = "default",
    pi: str = "default",
) -> int:
    """Get the number of static routes configured.

    Args:
        device: Device object.
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        Count of static routes.
    """
    routes = get_static_routes(device, ni=ni, pi=pi)
    return len(routes)


def get_static_route_next_hops(
    device,
    prefix: str,
    ni: str = "default",
    pi: str = "default",
) -> Dict[str, Any]:
    """Get the next-hops dictionary for a static route prefix.

    Args:
        device: Device object.
        prefix: Route prefix (e.g. ``'100.100.100.0/24'``).
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        Dictionary of next-hops keyed by index, or empty dict if the
        prefix is not found or has no next-hops.
    """
    route = get_static_route(device, prefix, ni=ni, pi=pi)
    if route is None:
        return {}
    return route.get("next-hops", {})


def is_static_route_present(
    device,
    prefix: str,
    ni: str = "default",
    pi: str = "default",
) -> bool:
    """Check whether a static route with the given prefix exists.

    Args:
        device: Device object.
        prefix: Route prefix (e.g. ``'100.100.100.0/24'``).
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        ``True`` if the route is present, ``False`` otherwise.
    """
    routes = get_static_routes(device, ni=ni, pi=pi)
    return prefix in routes


def get_static_route_tag(
    device,
    prefix: str,
    ni: str = "default",
    pi: str = "default",
) -> Optional[int]:
    """Get the set-tag value for a static route.

    Args:
        device: Device object.
        prefix: Route prefix (e.g. ``'100.100.100.0/24'``).
        ni: Network instance name.
        pi: Protocol instance name.

    Returns:
        The tag value as an integer, or ``None`` if the route is not
        found or has no tag configured.
    """
    route = get_static_route(device, prefix, ni=ni, pi=pi)
    if route is None:
        return None
    tag = route.get("set-tag")
    if tag is not None:
        return int(tag)
    return None
