"""ArcOS ACL verify APIs."""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.acl.get import (
    is_acl_set_present,
)

log = logging.getLogger(__name__)


def verify_acl_set_present(
    device,
    name: str,
    acl_type: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ACL set exists.

    Args:
        device: pyATS device object.
        name: ACL name.
        acl_type: ACL type.
        max_time: Maximum wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if ACL exists within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_acl_set_present(device, name, acl_type)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_acl_set_present failed: %s", exc)
            present = False

        log.debug(
            "verify_acl_set_present(%s %s): present=%s",
            name, acl_type, present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_acl_set_not_present(
    device,
    name: str,
    acl_type: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ACL set does NOT exist.

    Args:
        device: pyATS device object.
        name: ACL name.
        acl_type: ACL type.
        max_time: Maximum wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if ACL is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_acl_set_present(device, name, acl_type)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_acl_set_present failed: %s", exc)
            present = True

        log.debug(
            "verify_acl_set_not_present(%s %s): present=%s",
            name, acl_type, present,
        )

        if not present:
            return True

        timeout.sleep()

    return False
