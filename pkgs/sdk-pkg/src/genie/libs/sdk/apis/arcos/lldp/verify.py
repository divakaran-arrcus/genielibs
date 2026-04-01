"""ArcOS LLDP verify APIs.

Verification helpers built on top of the ArcOS LLDP get APIs in
``genie.libs.sdk.apis.arcos.lldp.get``.

These functions poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.lldp.get import (
    get_lldp_interface,
)

log = logging.getLogger(__name__)


def _has_neighbor_with_system_name(
    intf_data: Optional[dict],
    neighbor_system_name: str,
) -> bool:
    """Check if interface data contains a neighbor with given system-name."""

    if not intf_data:
        return False

    neighbors = intf_data.get("neighbors", {})
    for nbr_data in neighbors.values():
        if nbr_data.get("system-name") == neighbor_system_name:
            return True

    return False


def verify_lldp_neighbor_present(
    device,
    interface: str,
    neighbor_system_name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an LLDP neighbor with a given system-name appears on an interface.

    This uses :func:`get_lldp_interface` to poll the device.

    Args:
        device: pyATS device object.
        interface: Interface name to check (e.g., 'swp1').
        neighbor_system_name: Expected neighbor system-name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the neighbor appears within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            intf_data = get_lldp_interface(device, interface=interface)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_lldp_interface failed for %s: %s", interface, exc
            )
            intf_data = None

        present = _has_neighbor_with_system_name(
            intf_data, neighbor_system_name
        )

        log.debug(
            "verify_lldp_neighbor_present(%s, %s): present=%s",
            interface,
            neighbor_system_name,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_lldp_neighbor_not_present(
    device,
    interface: str,
    neighbor_system_name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an LLDP neighbor with a given system-name is NOT on an interface.

    This uses :func:`get_lldp_interface` to poll the device.

    Args:
        device: pyATS device object.
        interface: Interface name to check (e.g., 'swp1').
        neighbor_system_name: Neighbor system-name that should be absent.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the neighbor is absent within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            intf_data = get_lldp_interface(device, interface=interface)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_lldp_interface failed for %s: %s", interface, exc
            )
            intf_data = None

        # On error, assume neighbor is present (safe default for not_present)
        if intf_data is None:
            present = True
        else:
            present = _has_neighbor_with_system_name(
                intf_data, neighbor_system_name
            )

        log.debug(
            "verify_lldp_neighbor_not_present(%s, %s): present=%s",
            interface,
            neighbor_system_name,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False
