"""ArcOS OSPFv3 verify APIs."""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.ospfv3.get import (
    is_ospfv3_neighbor_full,
    get_ospfv3_router_id,
    get_ospfv3_area_count,
    get_ospfv3_area_type,
    get_ospfv3_interface_metric,
    is_ospfv3_interface_passive,
    get_ospfv3_spf_initial_delay,
    get_ospfv3_route,
    get_ospfv3_global,
)

log = logging.getLogger(__name__)


def verify_ospfv3_neighbor_full(device, neighbor_rid, area="*",
                                 max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 neighbor is in FULL state."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            if is_ospfv3_neighbor_full(device, neighbor_rid, area=area):
                return True
        except Exception as exc:
            log.error("is_ospfv3_neighbor_full failed: %s", exc)
        timeout.sleep()
    return False


def verify_ospfv3_router_id(device, expected_rid,
                             max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 router-id matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            rid = get_ospfv3_router_id(device)
        except Exception as exc:
            log.error("get_ospfv3_router_id failed: %s", exc)
            rid = None
        if rid == expected_rid:
            return True
        timeout.sleep()
    return False


def verify_ospfv3_area_count(device, expected_count: int,
                              max_time=60, check_interval=10) -> bool:
    """Verify the number of OSPFv3 areas matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            count = get_ospfv3_area_count(device)
        except Exception as exc:
            log.error("get_ospfv3_area_count failed: %s", exc)
            count = -1
        if count == expected_count:
            return True
        timeout.sleep()
    return False


def verify_ospfv3_area_type(device, area_id: str, expected_type: str,
                             max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 area type matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            area_type = get_ospfv3_area_type(device, area_id)
        except Exception as exc:
            log.error("get_ospfv3_area_type failed: %s", exc)
            area_type = None
        if area_type == expected_type:
            return True
        timeout.sleep()
    return False


def verify_ospfv3_interface_metric(device, interface: str, expected_metric: int,
                                    area: str = "*",
                                    max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 interface metric matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            metric = get_ospfv3_interface_metric(device, interface, area=area)
        except Exception as exc:
            log.error("get_ospfv3_interface_metric failed: %s", exc)
            metric = None
        if metric == expected_metric:
            return True
        timeout.sleep()
    return False


def verify_ospfv3_interface_passive(device, interface: str, expected: bool,
                                     area: str = "*",
                                     max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 interface passive state."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            passive = is_ospfv3_interface_passive(device, interface, area=area)
        except Exception as exc:
            log.error("is_ospfv3_interface_passive failed: %s", exc)
            passive = None
        if passive == expected:
            return True
        timeout.sleep()
    return False


def verify_ospfv3_spf_initial_delay(device, expected_delay: int,
                                     max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 SPF initial-delay matches expected (ms)."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            delay = get_ospfv3_spf_initial_delay(device)
        except Exception as exc:
            log.error("get_ospfv3_spf_initial_delay failed: %s", exc)
            delay = None
        if delay == expected_delay:
            return True
        timeout.sleep()
    return False


def verify_ospfv3_route_present(device, prefix: str,
                                 path_type: Optional[str] = None,
                                 expected_metric: Optional[int] = None,
                                 network_instance: str = "default",
                                 protocol_instance: str = "default",
                                 max_time: int = 30,
                                 check_interval: int = 5) -> bool:
    """Verify an OSPFv3 IPv6 route is present in the OSPFv3 RIB."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            route = get_ospfv3_route(
                device, prefix,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:
            log.error("get_ospfv3_route(%s) failed: %s", prefix, exc)
            route = None

        if route is not None:
            type_ok = path_type is None or route.get("path-type") == path_type
            metric_ok = (
                expected_metric is None
                or route.get("metric") == expected_metric
            )
            if type_ok and metric_ok:
                return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# Batch B verifies (parser-dependent — soft when parser doesn't expose)
# ---------------------------------------------------------------------------

def verify_ospfv3_route_preference(device,
                                     intra_area: Optional[int] = None,
                                     inter_area: Optional[int] = None,
                                     external: Optional[int] = None,
                                     max_time: int = 30,
                                     check_interval: int = 5) -> bool:
    """Verify OSPFv3 global route-preference matches expected subset.

    Reads from get_ospfv3_global; returns False if parser doesn't yet
    expose the route-preference dict (graceful soft-fail).
    """
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            data = get_ospfv3_global(device)
        except Exception as exc:
            log.error("get_ospfv3_global failed: %s", exc)
            data = {}

        rp = (data or {}).get("route-preference", {})
        actual_intra = rp.get("intra-area")
        actual_inter = rp.get("inter-area")
        actual_external = rp.get("external")

        intra_ok = intra_area is None or actual_intra == intra_area
        inter_ok = inter_area is None or actual_inter == inter_area
        ext_ok = external is None or actual_external == external

        if intra_ok and inter_ok and ext_ok:
            return True

        timeout.sleep()

    return False


def verify_ospfv3_max_lsa(device,
                            lsa_limit: Optional[int] = None,
                            warning_threshold: Optional[int] = None,
                            state: Optional[str] = None,
                            max_time: int = 30,
                            check_interval: int = 5) -> bool:
    """Verify OSPFv3 max-lsa configuration + state match expected subset."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            data = get_ospfv3_global(device)
        except Exception as exc:
            log.error("get_ospfv3_global failed: %s", exc)
            data = {}

        max_lsa = (data or {}).get("max-lsa", {}) or {}
        actual_limit = max_lsa.get("lsa-limit")
        actual_warn = max_lsa.get("warning-threshold")
        actual_state = max_lsa.get("state") or max_lsa.get("max-lsa-state")

        limit_ok = lsa_limit is None or actual_limit == lsa_limit
        warn_ok = warning_threshold is None or actual_warn == warning_threshold
        state_ok = state is None or actual_state == state

        if limit_ok and warn_ok and state_ok:
            return True

        timeout.sleep()

    return False


def verify_ospfv3_maintenance_mode_state(device, expected_state: str,
                                           max_time: int = 30,
                                           check_interval: int = 5) -> bool:
    """Verify OSPFv3 maintenance-mode operational state."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            data = get_ospfv3_global(device)
        except Exception as exc:
            log.error("get_ospfv3_global failed: %s", exc)
            data = {}

        mm = (data or {}).get("maintenance-mode", {}) or {}
        actual = mm.get("state") or mm.get("maintenance-mode-state")

        if actual == expected_state:
            return True

        timeout.sleep()

    return False
