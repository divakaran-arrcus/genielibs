"""ArcOS VLAN verify APIs.

Verification helpers built on top of the ArcOS VLAN get APIs in
``genie.libs.sdk.apis.arcos.vlan.get``.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.vlan.get import (
    is_vlan_present,
    get_vlan_members,
)

log = logging.getLogger(__name__)


def verify_vlan_present(
    device,
    vlan_id,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a VLAN exists.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if VLAN exists within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_vlan_present(device, vlan_id)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_vlan_present failed for %s: %s", vlan_id, exc)
            present = False

        log.debug("verify_vlan_present(%s): present=%s", vlan_id, present)

        if present:
            return True

        timeout.sleep()

    return False


def verify_vlan_not_present(
    device,
    vlan_id,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a VLAN does NOT exist.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if VLAN is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_vlan_present(device, vlan_id)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_vlan_present failed for %s: %s", vlan_id, exc)
            present = True

        log.debug("verify_vlan_not_present(%s): present=%s", vlan_id, present)

        if not present:
            return True

        timeout.sleep()

    return False


def verify_vlan_member_present(
    device,
    vlan_id,
    interface: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an interface is a member of a VLAN.

    Args:
        device: pyATS device object.
        vlan_id: VLAN ID (int or str).
        interface: Interface name to check (e.g., 'swp1').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if interface is a VLAN member within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            members = get_vlan_members(device, vlan_id)
            present = interface in members
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_vlan_members failed for VLAN %s: %s", vlan_id, exc
            )
            present = False

        log.debug(
            "verify_vlan_member_present(%s, %s): present=%s",
            vlan_id,
            interface,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False
