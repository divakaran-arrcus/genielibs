"""ArcOS VRRP verify APIs."""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.vrrp.get import (
    is_vrrp_group_present,
    get_vrrp_group_mode,
)

log = logging.getLogger(__name__)


def verify_vrrp_group_present(
    device, interface, sub_id, af, address, vrid,
    max_time=60, check_interval=10,
) -> bool:
    """Verify VRRP group exists."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            present = is_vrrp_group_present(
                device, interface, sub_id, af, address, vrid,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_vrrp_group_present failed: %s", exc)
            present = False

        if present:
            return True
        timeout.sleep()
    return False


def verify_vrrp_group_not_present(
    device, interface, sub_id, af, address, vrid,
    max_time=60, check_interval=10,
) -> bool:
    """Verify VRRP group does NOT exist."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            present = is_vrrp_group_present(
                device, interface, sub_id, af, address, vrid,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_vrrp_group_present failed: %s", exc)
            present = True

        if not present:
            return True
        timeout.sleep()
    return False


def verify_vrrp_group_master(
    device, interface, sub_id, af, address, vrid,
    max_time=60, check_interval=10,
) -> bool:
    """Verify VRRP group is MASTER."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            mode = get_vrrp_group_mode(
                device, interface, sub_id, af, address, vrid,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_vrrp_group_mode failed: %s", exc)
            mode = None

        if mode == "MASTER":
            return True
        timeout.sleep()
    return False
