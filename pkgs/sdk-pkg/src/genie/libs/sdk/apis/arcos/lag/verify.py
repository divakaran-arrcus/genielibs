"""ArcOS LAG (LACP/Bond) verify APIs.

Verification helpers built on top of the ArcOS LAG get APIs in
``genie.libs.sdk.apis.arcos.lag.get``.

These functions poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.lag.get import (
    get_lag_bond,
    get_lag_members,
    get_lag_member_sync_state,
)

log = logging.getLogger(__name__)


def verify_lag_member_in_sync(
    device,
    bond: str,
    member: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a bond member reaches IN_SYNC state.

    Args:
        device: pyATS device object.
        bond: Bond interface name (e.g., 'bond10').
        member: Member interface name (e.g., 'swp10').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if member reaches IN_SYNC within timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            state = get_lag_member_sync_state(device, bond, member)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_lag_member_sync_state failed for %s/%s: %s",
                bond, member, exc,
            )
            state = None

        log.debug(
            "verify_lag_member_in_sync(%s, %s): state=%s",
            bond, member, state,
        )

        if state == "IN_SYNC":
            return True

        timeout.sleep()

    return False


def verify_lag_member_collecting_distributing(
    device,
    bond: str,
    member: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a bond member is collecting and distributing.

    Args:
        device: pyATS device object.
        bond: Bond interface name (e.g., 'bond10').
        member: Member interface name (e.g., 'swp10').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if member is collecting+distributing within timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            members = get_lag_members(device, bond)
            member_data = members.get(member, {})
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_lag_members failed for %s/%s: %s",
                bond, member, exc,
            )
            member_data = {}

        collecting = member_data.get("collecting", False)
        distributing = member_data.get("distributing", False)

        log.debug(
            "verify_lag_member_collecting_distributing(%s, %s): "
            "collecting=%s, distributing=%s",
            bond, member, collecting, distributing,
        )

        if collecting and distributing:
            return True

        timeout.sleep()

    return False


def verify_lag_bond_present(
    device,
    bond: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a bond interface exists in LACP output.

    Args:
        device: pyATS device object.
        bond: Bond interface name (e.g., 'bond10').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if bond appears within timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            bond_data = get_lag_bond(device, bond)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_lag_bond failed for %s: %s", bond, exc,
            )
            bond_data = None

        log.debug(
            "verify_lag_bond_present(%s): present=%s",
            bond, bond_data is not None,
        )

        if bond_data is not None:
            return True

        timeout.sleep()

    return False
