"""ArcOS static routing verify APIs."""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.static_routing.get import (
    is_static_route_present,
    get_static_route_tag,
)

log = logging.getLogger(__name__)


def verify_static_route_present(
    device,
    prefix: str,
    ni: str = "default",
    pi: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a static route is present on the device.

    Polls the device until the route appears or the timeout expires.

    Args:
        device: Device object.
        prefix: Route prefix to check (e.g. ``'100.100.100.0/24'``).
        ni: Network instance name.
        pi: Protocol instance name.
        max_time: Maximum time to wait in seconds.
        check_interval: Polling interval in seconds.

    Returns:
        ``True`` if the route is found within the timeout, ``False``
        otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        if is_static_route_present(device, prefix, ni=ni, pi=pi):
            log.info(
                "Static route %s found on %s (ni=%s, pi=%s)",
                prefix, device.name, ni, pi,
            )
            return True

        log.debug(
            "Static route %s not yet present on %s, retrying...",
            prefix, device.name,
        )
        timeout.sleep()

    log.warning(
        "Static route %s not found on %s within %s seconds",
        prefix, device.name, max_time,
    )
    return False


def verify_static_route_not_present(
    device,
    prefix: str,
    ni: str = "default",
    pi: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a static route is not present on the device.

    Polls the device until the route disappears or the timeout expires.

    Args:
        device: Device object.
        prefix: Route prefix to check (e.g. ``'100.100.100.0/24'``).
        ni: Network instance name.
        pi: Protocol instance name.
        max_time: Maximum time to wait in seconds.
        check_interval: Polling interval in seconds.

    Returns:
        ``True`` if the route is absent within the timeout, ``False``
        otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        if not is_static_route_present(device, prefix, ni=ni, pi=pi):
            log.info(
                "Static route %s confirmed absent on %s (ni=%s, pi=%s)",
                prefix, device.name, ni, pi,
            )
            return True

        log.debug(
            "Static route %s still present on %s, retrying...",
            prefix, device.name,
        )
        timeout.sleep()

    log.warning(
        "Static route %s still present on %s after %s seconds",
        prefix, device.name, max_time,
    )
    return False


def verify_static_route_tag(
    device,
    prefix: str,
    expected_tag: int,
    ni: str = "default",
    pi: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a static route has the expected tag value.

    Polls the device until the tag matches or the timeout expires.

    Args:
        device: Device object.
        prefix: Route prefix to check (e.g. ``'100.100.100.0/24'``).
        expected_tag: Expected set-tag value.
        ni: Network instance name.
        pi: Protocol instance name.
        max_time: Maximum time to wait in seconds.
        check_interval: Polling interval in seconds.

    Returns:
        ``True`` if the tag matches within the timeout, ``False``
        otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        actual_tag = get_static_route_tag(device, prefix, ni=ni, pi=pi)

        if actual_tag is not None and actual_tag == expected_tag:
            log.info(
                "Static route %s on %s has expected tag %s",
                prefix, device.name, expected_tag,
            )
            return True

        log.debug(
            "Static route %s on %s tag=%s (expected %s), retrying...",
            prefix, device.name, actual_tag, expected_tag,
        )
        timeout.sleep()

    log.warning(
        "Static route %s on %s tag mismatch after %s seconds "
        "(got %s, expected %s)",
        prefix, device.name, max_time,
        get_static_route_tag(device, prefix, ni=ni, pi=pi),
        expected_tag,
    )
    return False
