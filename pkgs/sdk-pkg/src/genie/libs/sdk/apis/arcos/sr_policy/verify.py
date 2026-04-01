"""ArcOS SR-Policy verify APIs.

Verification helpers built on top of the ArcOS SR-Policy get APIs in
``genie.libs.sdk.apis.arcos.sr_policy.get``.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.sr_policy.get import (
    get_sr_policy_db_oper_state,
    get_sr_policy_segment_list,
)

log = logging.getLogger(__name__)


def verify_sr_policy_oper_up(
    device,
    endpoint: str,
    color: int,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an SR-Policy reaches UP operational state.

    Args:
        device: pyATS device object.
        endpoint: Policy endpoint (e.g., '2.2.2.2').
        color: Policy color (e.g., 100).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if policy reaches UP within timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            state = get_sr_policy_db_oper_state(device, endpoint, color)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_sr_policy_db_oper_state failed for %s/%s: %s",
                endpoint, color, exc,
            )
            state = None

        log.debug(
            "verify_sr_policy_oper_up(%s, %s): state=%s",
            endpoint, color, state,
        )

        if state == "UP":
            return True

        timeout.sleep()

    return False


def verify_sr_policy_oper_down(
    device,
    endpoint: str,
    color: int,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an SR-Policy is in DOWN operational state.

    Args:
        device: pyATS device object.
        endpoint: Policy endpoint.
        color: Policy color.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if policy is DOWN within timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            state = get_sr_policy_db_oper_state(device, endpoint, color)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_sr_policy_db_oper_state failed for %s/%s: %s",
                endpoint, color, exc,
            )
            state = None

        log.debug(
            "verify_sr_policy_oper_down(%s, %s): state=%s",
            endpoint, color, state,
        )

        if state == "DOWN":
            return True

        timeout.sleep()

    return False


def verify_sr_policy_segment_list_present(
    device,
    name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an SR-Policy segment-list exists.

    Args:
        device: pyATS device object.
        name: Segment-list name (e.g., 'sl1').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if segment-list exists within timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            sl = get_sr_policy_segment_list(device, name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_sr_policy_segment_list failed for %s: %s",
                name, exc,
            )
            sl = None

        log.debug(
            "verify_sr_policy_segment_list_present(%s): present=%s",
            name, sl is not None,
        )

        if sl is not None:
            return True

        timeout.sleep()

    return False
