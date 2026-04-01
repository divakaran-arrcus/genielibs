"""ArcOS QoS verify APIs."""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.qos.get import is_qos_policy_present

log = logging.getLogger(__name__)


def verify_qos_policy_present(
    device, name: str,
    max_time: int = 60, check_interval: int = 10,
) -> bool:
    """Verify that a QoS policy exists.

    Args:
        device: pyATS device object.
        name: Policy name.
        max_time: Maximum wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if policy exists within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_qos_policy_present(device, name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_qos_policy_present failed: %s", exc)
            present = False

        if present:
            return True
        timeout.sleep()

    return False


def verify_qos_policy_not_present(
    device, name: str,
    max_time: int = 60, check_interval: int = 10,
) -> bool:
    """Verify that a QoS policy does NOT exist.

    Args:
        device: pyATS device object.
        name: Policy name.
        max_time: Maximum wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if policy is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_qos_policy_present(device, name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_qos_policy_present failed: %s", exc)
            present = True

        if not present:
            return True
        timeout.sleep()

    return False
