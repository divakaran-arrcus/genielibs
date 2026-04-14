"""ArcOS OSPF verify APIs."""

from __future__ import annotations

import logging
from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.ospf.get import (
    is_ospf_neighbor_full,
    get_ospf_router_id,
    get_ospf_area_count,
    get_ospf_area_type,
    get_ospf_interface_metric,
    is_ospf_interface_passive,
    get_ospf_spf_initial_delay,
)

log = logging.getLogger(__name__)


def verify_ospf_neighbor_full(device, neighbor_rid, area="*",
                                max_time=60, check_interval=10) -> bool:
    """Verify OSPF neighbor is in FULL state."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            if is_ospf_neighbor_full(device, neighbor_rid, area=area):
                return True
        except Exception as exc:
            log.error("is_ospf_neighbor_full failed: %s", exc)
        timeout.sleep()
    return False


def verify_ospf_router_id(device, expected_rid,
                            max_time=60, check_interval=10) -> bool:
    """Verify OSPF router-id matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            rid = get_ospf_router_id(device)
        except Exception as exc:
            log.error("get_ospf_router_id failed: %s", exc)
            rid = None

        if rid == expected_rid:
            return True
        timeout.sleep()
    return False


def verify_ospf_area_count(device, expected_count: int,
                           max_time=60, check_interval=10) -> bool:
    """Verify the number of OSPF areas matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            count = get_ospf_area_count(device)
        except Exception as exc:
            log.error("get_ospf_area_count failed: %s", exc)
            count = -1

        if count == expected_count:
            return True
        timeout.sleep()
    return False


def verify_ospf_area_type(device, area_id: str, expected_type: str,
                          max_time=60, check_interval=10) -> bool:
    """Verify OSPF area type matches expected.

    Args:
        expected_type: e.g. "AREA_TYPE_NORMAL", "AREA_TYPE_STUB".
    """
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            area_type = get_ospf_area_type(device, area_id)
        except Exception as exc:
            log.error("get_ospf_area_type failed: %s", exc)
            area_type = None

        if area_type == expected_type:
            return True
        timeout.sleep()
    return False


def verify_ospf_interface_metric(device, interface: str, expected_metric: int,
                                 area: str = "*",
                                 max_time=60, check_interval=10) -> bool:
    """Verify OSPF interface metric matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            metric = get_ospf_interface_metric(device, interface, area=area)
        except Exception as exc:
            log.error("get_ospf_interface_metric failed: %s", exc)
            metric = None

        if metric == expected_metric:
            return True
        timeout.sleep()
    return False


def verify_ospf_interface_passive(device, interface: str, expected: bool,
                                  area: str = "*",
                                  max_time=60, check_interval=10) -> bool:
    """Verify OSPF interface passive state."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            passive = is_ospf_interface_passive(device, interface, area=area)
        except Exception as exc:
            log.error("is_ospf_interface_passive failed: %s", exc)
            passive = None

        if passive == expected:
            return True
        timeout.sleep()
    return False


def verify_ospf_spf_initial_delay(device, expected_delay: int,
                                  max_time=60, check_interval=10) -> bool:
    """Verify OSPF SPF initial delay matches expected (ms)."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            delay = get_ospf_spf_initial_delay(device)
        except Exception as exc:
            log.error("get_ospf_spf_initial_delay failed: %s", exc)
            delay = None

        if delay == expected_delay:
            return True
        timeout.sleep()
    return False
