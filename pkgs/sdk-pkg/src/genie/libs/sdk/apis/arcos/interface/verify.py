"""ArcOS interface verify APIs.

Verification helpers built on top of the ArcOS interface get APIs in
``genie.libs.sdk.apis.arcos.interface.get``.

These functions typically poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.interface.get import (
    get_interface_mtu,
    get_interface_status,
)

log = logging.getLogger(__name__)


def verify_interface_state(
    device,
    interface: str,
    expected_status: str = "up",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ArcOS interface operational/admin status.

    This uses :func:`get_interface_status` which normalizes state into
    one of ``"up"``, ``"down"``, or ``"admin-down"``.

    Args:
        device: pyATS device object.
        interface: Interface name to verify.
        expected_status: Expected status string (case-insensitive).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the interface reaches the expected status within the
        timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)
    expected_status = expected_status.lower()

    while timeout.iterate():
        try:
            status: Optional[str] = get_interface_status(device, interface)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_interface_status failed for %s: %s", interface, exc)
            status = None

        log.debug("verify_interface_state(%s): current=%s, expected=%s", interface, status, expected_status)

        if status is not None and status.lower() == expected_status:
            return True

        timeout.sleep()

    return False


def verify_interface_state_up(
    device,
    interface: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ArcOS interface is operationally up."""

    return verify_interface_state(
        device=device,
        interface=interface,
        expected_status="up",
        max_time=max_time,
        check_interval=check_interval,
    )


def verify_interface_state_down(
    device,
    interface: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ArcOS interface is operationally down (but not admin-down)."""

    return verify_interface_state(
        device=device,
        interface=interface,
        expected_status="down",
        max_time=max_time,
        check_interval=check_interval,
    )


def verify_interface_state_admin_down(
    device,
    interface: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ArcOS interface is administratively down."""

    return verify_interface_state(
        device=device,
        interface=interface,
        expected_status="admin-down",
        max_time=max_time,
        check_interval=check_interval,
    )


def verify_interface_mtu(
    device,
    interface: str,
    expected_mtu: int,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ArcOS interface MTU matches the expected value.

    Args:
        device: pyATS device object.
        interface: Interface name to verify.
        expected_mtu: Expected MTU value.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the MTU equals ``expected_mtu`` within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            mtu = get_interface_mtu(device, interface)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_interface_mtu failed for %s: %s", interface, exc)
            mtu = None

        log.debug(
            "verify_interface_mtu(%s): current=%s, expected=%s",
            interface,
            mtu,
            expected_mtu,
        )

        if mtu == expected_mtu:
            return True

        timeout.sleep()

    return False
