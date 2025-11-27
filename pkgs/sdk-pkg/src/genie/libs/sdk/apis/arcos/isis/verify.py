"""ArcOS ISIS verify APIs.

Verification helpers built on top of the ArcOS ISIS get APIs in
``genie.libs.sdk.apis.arcos.isis.get``.

These functions typically poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.isis.get import (
    get_isis_adjacency_state,
    get_isis_routes,
    is_isis_neighbor_present,
)

log = logging.getLogger(__name__)


def verify_isis_neighbor_present(
    device,
    neighbor: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS neighbor is present.

    Args:
        device: pyATS device object.
        neighbor: Neighbor system-id to look for.
        instance: ISIS instance name (default: "default").
        interface: Optional interface filter.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the neighbor is present within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_neighbor_present(
                device,
                neighbor=neighbor,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_neighbor_present failed for %s: %s", neighbor, exc)
            present = False

        log.debug(
            "verify_isis_neighbor_present(%s): present=%s",
            neighbor,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_neighbor_not_present(
    device,
    neighbor: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS neighbor is NOT present.

    This is the logical negation of :func:`verify_isis_neighbor_present`.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_neighbor_present(
                device,
                neighbor=neighbor,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_neighbor_present failed for %s: %s", neighbor, exc)
            present = True

        log.debug(
            "verify_isis_neighbor_not_present(%s): present=%s",
            neighbor,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_isis_neighbor_state(
    device,
    neighbor: str,
    expected_state: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ISIS adjacency state for a given neighbor.

    Args:
        device: pyATS device object.
        neighbor: Neighbor system-id.
        expected_state: Expected adjacency state string (e.g. 'UP').
        instance: ISIS instance name.
        interface: Optional interface filter.

    Returns:
        True if the adjacency state matches within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)
    expected_state = expected_state.upper()

    while timeout.iterate():
        try:
            state = get_isis_adjacency_state(
                device,
                neighbor=neighbor,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_adjacency_state failed for %s: %s", neighbor, exc)
            state = None

        log.debug(
            "verify_isis_neighbor_state(%s): current=%s, expected=%s",
            neighbor,
            state,
            expected_state,
        )

        if state is not None and str(state).upper() == expected_state:
            return True

        timeout.sleep()

    return False


def verify_isis_route_present(
    device,
    prefix: str,
    address_family: str = "ipv4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS route is present for the given prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. '10.0.0.0/24', '2001:db8::/64').
        address_family: 'ipv4' or 'ipv6'.
        instance: ISIS instance name (currently always 'default' on ArcOS).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the route is present within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            routes = get_isis_routes(
                device,
                address_family=address_family,
                instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_routes failed for AF %s: %s", address_family, exc)
            routes = {}

        present = prefix in routes

        log.debug(
            "verify_isis_route_present(%s, af=%s): present=%s",
            prefix,
            address_family,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False
