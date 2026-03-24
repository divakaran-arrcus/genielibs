"""ArcOS TE verify APIs.

Verification helpers built on top of the ArcOS TE get APIs in
``genie.libs.sdk.apis.arcos.te.get``.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.te.get import (
    is_te_admin_group_present,
)

log = logging.getLogger(__name__)


def verify_te_admin_group_present(
    device,
    name: str,
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a TE admin-group exists.

    Args:
        device: pyATS device object.
        name: Admin-group name to check.
        network_instance: Network instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if admin-group exists within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_te_admin_group_present(
                device, name, network_instance=network_instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_te_admin_group_present failed for %s: %s", name, exc)
            present = False

        log.debug("verify_te_admin_group_present(%s): present=%s", name, present)

        if present:
            return True

        timeout.sleep()

    return False


def verify_te_admin_group_not_present(
    device,
    name: str,
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a TE admin-group does NOT exist.

    Args:
        device: pyATS device object.
        name: Admin-group name to check.
        network_instance: Network instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if admin-group is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_te_admin_group_present(
                device, name, network_instance=network_instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_te_admin_group_present failed for %s: %s", name, exc)
            present = True

        log.debug("verify_te_admin_group_not_present(%s): present=%s", name, present)

        if not present:
            return True

        timeout.sleep()

    return False
