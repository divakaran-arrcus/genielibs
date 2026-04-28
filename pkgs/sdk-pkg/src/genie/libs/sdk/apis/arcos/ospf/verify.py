"""ArcOS OSPF verify APIs."""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.ospf.get import (
    is_ospf_neighbor_full,
    get_ospf_router_id,
    get_ospf_area_count,
    get_ospf_area_type,
    get_ospf_interface_metric,
    is_ospf_interface_passive,
    get_ospf_spf_initial_delay,
    get_ospf_route,
    get_ospf_global,
    get_ospf_interface,
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


def verify_ospf_route_present(device, prefix: str,
                               path_type: Optional[str] = None,
                               expected_metric: Optional[int] = None,
                               network_instance: str = "default",
                               protocol_instance: str = "default",
                               max_time: int = 30,
                               check_interval: int = 5) -> bool:
    """Verify an OSPF route is present in the OSPF RIB.

    Polls ``get_ospf_route`` until the prefix is present and (optionally)
    matches ``path_type`` and ``expected_metric``.

    Args:
        device: pyATS device object.
        prefix: IPv4 prefix to look up.
        path_type: Optional expected route-type (e.g. ``"intra-area"``,
            ``"inter-area"``, ``"intra-area-connected"``,
            ``"external-type-1"``, ``"external-type-2"``). If None, type
            is not checked.
        expected_metric: Optional expected metric value. If None,
            metric is not checked.
        network_instance: Network instance name.
        protocol_instance: OSPF protocol instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the route is present (and matches the optional
        type/metric filters) within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            route = get_ospf_route(
                device, prefix,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:
            log.error("get_ospf_route(%s) failed: %s", prefix, exc)
            route = None

        log.debug(
            "verify_ospf_route_present(%s): route=%s, expected_type=%s, expected_metric=%s",
            prefix, route, path_type, expected_metric,
        )

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
# Batch B — features-plan blockers
# ---------------------------------------------------------------------------

def verify_ospf_interface_auth_type(device, interface: str,
                                     expected_auth_type: str,
                                     area: str = "*",
                                     max_time: int = 30,
                                     check_interval: int = 5) -> bool:
    """Verify OSPF interface authentication-type matches expected.

    Args:
        expected_auth_type: e.g. "OSPF_AUTH_NULL" or "OSPF_AUTH_CRYPTO_KEY".
    """
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            intf = get_ospf_interface(device, interface, area=area)
        except Exception as exc:
            log.error("get_ospf_interface failed: %s", exc)
            intf = None

        auth_type = None
        if intf:
            auth = intf.get("authentication") or {}
            auth_type = auth.get("auth-type") or intf.get("auth-type")

        log.debug(
            "verify_ospf_interface_auth_type(%s): current=%s expected=%s",
            interface, auth_type, expected_auth_type,
        )

        if auth_type == expected_auth_type:
            return True

        timeout.sleep()

    return False


def verify_ospf_route_preference(device,
                                  intra_area: Optional[int] = None,
                                  inter_area: Optional[int] = None,
                                  external: Optional[int] = None,
                                  max_time: int = 30,
                                  check_interval: int = 5) -> bool:
    """Verify OSPF global route-preference matches the specified subset.

    Any param left as ``None`` is not checked. Returns True only when all
    specified preferences match.
    """
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            data = get_ospf_global(device)
        except Exception as exc:
            log.error("get_ospf_global failed: %s", exc)
            data = {}

        rp = (data or {}).get("route-preference", {})
        actual_intra = rp.get("intra-area")
        actual_inter = rp.get("inter-area")
        actual_external = rp.get("external")

        log.debug(
            "verify_ospf_route_preference: intra=%s/%s inter=%s/%s ext=%s/%s",
            actual_intra, intra_area,
            actual_inter, inter_area,
            actual_external, external,
        )

        intra_ok = intra_area is None or actual_intra == intra_area
        inter_ok = inter_area is None or actual_inter == inter_area
        ext_ok = external is None or actual_external == external

        if intra_ok and inter_ok and ext_ok:
            return True

        timeout.sleep()

    return False


def verify_ospf_max_lsa(device,
                         lsa_limit: Optional[int] = None,
                         warning_threshold: Optional[int] = None,
                         state: Optional[str] = None,
                         max_time: int = 30,
                         check_interval: int = 5) -> bool:
    """Verify OSPF max-lsa configuration and state match expected subset.

    Args:
        lsa_limit: Optional expected lsa-limit.
        warning_threshold: Optional expected warning-threshold (%).
        state: Optional expected state — one of "DISABLED", "NORMAL",
            "LIMIT", "DOWN".
    """
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            data = get_ospf_global(device)
        except Exception as exc:
            log.error("get_ospf_global failed: %s", exc)
            data = {}

        max_lsa = (data or {}).get("max-lsa", {}) or {}
        actual_limit = max_lsa.get("lsa-limit")
        actual_warn = max_lsa.get("warning-threshold")
        actual_state = max_lsa.get("state") or max_lsa.get("max-lsa-state")

        log.debug(
            "verify_ospf_max_lsa: limit=%s/%s warn=%s/%s state=%s/%s",
            actual_limit, lsa_limit,
            actual_warn, warning_threshold,
            actual_state, state,
        )

        limit_ok = lsa_limit is None or actual_limit == lsa_limit
        warn_ok = warning_threshold is None or actual_warn == warning_threshold
        state_ok = state is None or actual_state == state

        if limit_ok and warn_ok and state_ok:
            return True

        timeout.sleep()

    return False


def verify_ospf_maintenance_mode_state(device, expected_state: str,
                                        max_time: int = 30,
                                        check_interval: int = 5) -> bool:
    """Verify OSPF maintenance-mode operational state.

    Args:
        expected_state: e.g. "ACTIVE" or "INACTIVE".
    """
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            data = get_ospf_global(device)
        except Exception as exc:
            log.error("get_ospf_global failed: %s", exc)
            data = {}

        mm = (data or {}).get("maintenance-mode", {}) or {}
        actual = mm.get("state") or mm.get("maintenance-mode-state")

        log.debug(
            "verify_ospf_maintenance_mode_state: current=%s expected=%s",
            actual, expected_state,
        )

        if actual == expected_state:
            return True

        timeout.sleep()

    return False
