"""ArcOS ISIS verify APIs.

Verification helpers built on top of the ArcOS ISIS get APIs in
``genie.libs.sdk.apis.arcos.isis.get``.

These functions typically poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.isis.get import (
    get_isis_adjacency_state,
    get_isis_routes,
    get_isis_route,
    get_isis_system_id,
    is_isis_adjacency_present,
    is_isis_flex_algo_route_present,
    is_isis_flex_algo_fast_reroute_present,
    get_isis_flex_algo_definitions,
    get_isis_fast_reroute,
    get_isis_micro_loop_avoidance,
)

log = logging.getLogger(__name__)


def verify_isis_system_id(
    device,
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that ISIS system-id is available.

    This is useful to verify that ISIS subsystem has started and is responding
    to queries after configuration.

    Args:
        device: pyATS device object.
        instance: ISIS instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the system-id is available within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            system_id = get_isis_system_id(device, instance=instance)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_system_id failed for instance %s: %s", instance, exc)
            system_id = None

        log.debug(
            "verify_isis_system_id(instance=%s): system_id=%s",
            instance,
            system_id,
        )

        if system_id is not None:
            return True

        timeout.sleep()

    return False


def verify_isis_adjacency_present(
    device,
    adjacency: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS adjacency is present.

    Args:
        device: pyATS device object.
        adjacency: Adjacency system-id to look for.
        instance: ISIS instance name (default: "default").
        interface: Optional interface filter.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the adjacency is present within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_adjacency_present(
                device,
                adjacency=adjacency,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_adjacency_present failed for %s: %s", adjacency, exc)
            present = False

        log.debug(
            "verify_isis_adjacency_present(%s): present=%s",
            adjacency,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_adjacency_not_present(
    device,
    adjacency: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS adjacency is NOT present.

    This is the logical negation of :func:`verify_isis_adjacency_present`.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_adjacency_present(
                device,
                adjacency=adjacency,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_adjacency_present failed for %s: %s", adjacency, exc)
            present = True

        log.debug(
            "verify_isis_adjacency_not_present(%s): present=%s",
            adjacency,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_isis_adjacency_state(
    device,
    adjacency: str,
    expected_state: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ISIS adjacency state for a given adjacency.

    Args:
        device: pyATS device object.
        adjacency: Adjacency system-id.
        expected_state: Expected adjacency state string (e.g. 'UP').
        instance: ISIS instance name.
        interface: Optional interface filter.

    Returns:
        True if the adjacency state matches within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)
    expected_state = expected_state.upper()

    while timeout.iterate():
        try:
            state = get_isis_adjacency_state(
                device,
                adjacency=adjacency,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_adjacency_state failed for %s: %s", adjacency, exc)
            state = None

        log.debug(
            "verify_isis_adjacency_state(%s): current=%s, expected=%s",
            adjacency,
            state,
            expected_state,
        )

        if state is not None and str(state).upper() == expected_state:
            return True

        timeout.sleep()

    return False


def verify_isis_route_present(
    device,
    prefix: str,
    address_family: str = "ipv4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS route is present for the given prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. '10.0.0.0/24', '2001:db8::/64').
        address_family: 'ipv4' or 'ipv6'.
        instance: ISIS instance name (currently always 'default' on ArcOS).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the route is present within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            routes = get_isis_routes(
                device,
                address_family=address_family,
                instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_routes failed for AF %s: %s", address_family, exc)
            routes = {}

        present = prefix in routes

        log.debug(
            "verify_isis_route_present(%s, af=%s): present=%s",
            prefix,
            address_family,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# Flex-Algo Verify APIs
# ---------------------------------------------------------------------------

def verify_isis_flex_algo_route_present(
    device,
    prefix: str,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo route is present.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check (e.g., '10.0.0.0/24').
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*' for all.
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if route is present within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_route_present(
                device, prefix=prefix, afi=afi, algo=algo, instance=instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_flex_algo_route_present failed for %s: %s", prefix, exc)
            present = False

        log.debug(
            "verify_isis_flex_algo_route_present(%s, algo=%s): present=%s",
            prefix,
            algo,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_route_not_present(
    device,
    prefix: str,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo route is NOT present.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check.
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*'.
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if route is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_route_present(
                device, prefix=prefix, afi=afi, algo=algo, instance=instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_flex_algo_route_present failed for %s: %s", prefix, exc)
            present = True

        log.debug(
            "verify_isis_flex_algo_route_not_present(%s, algo=%s): present=%s",
            prefix,
            algo,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_definition_present(
    device,
    algo_id: int,
    instance: str = "default",
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo definition is configured.

    Args:
        device: pyATS device object.
        algo_id: Flexible-algorithm ID (128-255).
        instance: ISIS protocol instance name.
        network_instance: Network instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if definition exists within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            definitions = get_isis_flex_algo_definitions(
                device, instance=instance, network_instance=network_instance
            )
            present = str(algo_id) in definitions
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_isis_flex_algo_definitions failed for algo %s: %s", algo_id, exc
            )
            present = False

        log.debug(
            "verify_isis_flex_algo_definition_present(%s): present=%s",
            algo_id,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_definition_not_present(
    device,
    algo_id: int,
    instance: str = "default",
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo definition does NOT exist.

    Args:
        device: pyATS device object.
        algo_id: Flexible-algorithm ID (128-255).
        instance: ISIS protocol instance name.
        network_instance: Network instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if definition is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            definitions = get_isis_flex_algo_definitions(
                device, instance=instance, network_instance=network_instance
            )
            present = str(algo_id) in definitions
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_isis_flex_algo_definitions failed for algo %s: %s", algo_id, exc
            )
            present = True  # assume present on error

        log.debug(
            "verify_isis_flex_algo_definition_not_present(%s): present=%s",
            algo_id,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_fast_reroute_present(
    device,
    prefix: str,
    algo: int,
    afi: str = "IPV4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a flex-algo fast-reroute entry exists for a prefix.

    This uses :func:`is_isis_flex_algo_fast_reroute_present` to poll
    the device.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '3.3.3.3/32').
        algo: Flexible-algorithm ID (e.g., 128).
        afi: Address family ('IPV4' or 'IPV6').
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the FRR entry appears within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_fast_reroute_present(
                device, prefix=prefix, algo=algo,
                afi=afi, instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_isis_flex_algo_fast_reroute_present failed for "
                "%s algo %s: %s", prefix, algo, exc,
            )
            present = False

        log.debug(
            "verify_isis_flex_algo_fast_reroute_present(%s, algo=%s): "
            "present=%s",
            prefix, algo, present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_fast_reroute_not_present(
    device,
    prefix: str,
    algo: int,
    afi: str = "IPV4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a flex-algo fast-reroute entry does NOT exist for a prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '3.3.3.3/32').
        algo: Flexible-algorithm ID (e.g., 128).
        afi: Address family ('IPV4' or 'IPV6').
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the FRR entry is absent within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_fast_reroute_present(
                device, prefix=prefix, algo=algo,
                afi=afi, instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_isis_flex_algo_fast_reroute_present failed for "
                "%s algo %s: %s", prefix, algo, exc,
            )
            present = True  # assume present on error

        log.debug(
            "verify_isis_flex_algo_fast_reroute_not_present(%s, algo=%s): "
            "present=%s",
            prefix, algo, present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# TI-LFA / MLA Verify APIs (2026-05-13)
# Polling helpers for backup-row presence and fast-reroute reroute-type.
# ---------------------------------------------------------------------------


def _iter_route_nexthops(route_data: Optional[dict]):
    """Yield every next-hop dict from a ``get_isis_route`` result.

    Handles two structural shapes:

    1. Top-level ``next_hops`` / ``next-hops`` (dict or list) — legacy.
    2. Nested under ``levels.<lvl>.next-hops`` (list of dicts) — current
       :class:`ShowIsisRoute` parser output. ``next-hops`` may be a list,
       a dict keyed by id, or wrapped under a ``next-hop`` key.
    """
    if not route_data:
        return
    # Top-level (legacy)
    top = route_data.get("next_hops") or route_data.get("next-hops")
    if isinstance(top, dict):
        if "next-hop" in top and isinstance(top["next-hop"], list):
            yield from top["next-hop"]
        else:
            yield from top.values()
    elif isinstance(top, list):
        yield from top

    # Nested under levels (current parser shape)
    levels = route_data.get("levels", {})
    if isinstance(levels, dict):
        for lv_data in levels.values():
            if not isinstance(lv_data, dict):
                continue
            nhc = lv_data.get("next_hops") or lv_data.get("next-hops")
            if isinstance(nhc, dict):
                if "next-hop" in nhc and isinstance(nhc["next-hop"], list):
                    yield from nhc["next-hop"]
                else:
                    yield from nhc.values()
            elif isinstance(nhc, list):
                yield from nhc


def _has_backup_nexthop(
    route_data: Optional[dict],
) -> tuple[bool, Optional[str], Optional[int]]:
    """Inspect a ``get_isis_route`` result and report backup-nexthop status.

    Returns:
        Tuple ``(has_backup, backup_egress, label_stack_len)``. When no backup
        row is found, returns ``(False, None, None)``.

    ``label_stack_len`` will be None when the parser doesn't expose a label
    stack for this entry (e.g. PQ_IS_ADJACENT TI-LFA backups on docker arcOS
    do not include label-stack fields — they don't need extra labels).
    """
    if not route_data:
        return (False, None, None)

    for nh in _iter_route_nexthops(route_data):
        if not isinstance(nh, dict):
            continue
        is_backup = (
            nh.get("backup") is True
            or (nh.get("state") or {}).get("backup") is True
        )
        if is_backup:
            egress = (
                nh.get("interface")
                or nh.get("outgoing-interface")
                or (nh.get("state") or {}).get("outgoing-interface")
            )
            label_stack = (
                nh.get("label_stack")
                or nh.get("pushed-mpls-label-stack")
                or nh.get("out-labels")
                or (nh.get("state") or {}).get("pushed-mpls-label-stack")
            )
            label_len = (
                len(label_stack) if isinstance(label_stack, list) else None
            )
            return (True, egress, label_len)

    return (False, None, None)


def verify_isis_route_has_backup(
    device,
    prefix: str,
    expected_backup_egress: Optional[str] = None,
    expected_label_stack_len: Optional[int] = None,
    address_family: str = "ipv4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that the given prefix's ISIS route entry has a backup nexthop.

    Polls ``get_isis_route`` until a next-hop with ``backup=true`` is found.
    Optionally also asserts the backup row's outgoing-interface and/or
    label-stack length match the provided expectations.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check (e.g., '6.6.6.6/32').
        expected_backup_egress: If set, also require the backup row's
            outgoing-interface to equal this value.
        expected_label_stack_len: If set, also require the backup row's
            label-stack length to equal this value.
        address_family: 'ipv4' or 'ipv6'. Default 'ipv4'.
        instance: ISIS instance name. Default 'default'.
        max_time: Maximum time to wait (seconds). Default 60.
        check_interval: Poll interval (seconds). Default 10.

    Returns:
        bool: True when a backup nexthop matching all constraints is
        observed within the timeout; False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            route = get_isis_route(
                device, prefix=prefix,
                address_family=address_family, instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_route failed for %s: %s", prefix, exc)
            route = None

        has_backup, egress, label_len = _has_backup_nexthop(route)

        constraints_ok = True
        if has_backup:
            if expected_backup_egress is not None and egress != expected_backup_egress:
                constraints_ok = False
            if expected_label_stack_len is not None and label_len != expected_label_stack_len:
                constraints_ok = False

        log.debug(
            "verify_isis_route_has_backup(%s): has_backup=%s egress=%s "
            "label_len=%s constraints_ok=%s",
            prefix, has_backup, egress, label_len, constraints_ok,
        )

        if has_backup and constraints_ok:
            return True

        timeout.sleep()

    return False


def verify_isis_no_backup_for_prefix(
    device,
    prefix: str,
    address_family: str = "ipv4",
    instance: str = "default",
    max_time: int = 30,
    check_interval: int = 5,
) -> bool:
    """Verify the given prefix's ISIS route entry has NO backup nexthop.

    Used by ECMP-exclusion: per arcOS, TI-LFA must not install a backup
    for prefixes with multiple primary equal-cost paths. Polls for the
    entire ``max_time`` window — returns False if a backup row is observed
    at ANY point.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check.
        address_family: 'ipv4' or 'ipv6'. Default 'ipv4'.
        instance: ISIS instance name. Default 'default'.
        max_time: Polling window in seconds. Default 30.
        check_interval: Poll interval. Default 5.

    Returns:
        bool: True if NO backup row is observed across the entire window.
        False if a backup row IS observed at any point.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            route = get_isis_route(
                device, prefix=prefix,
                address_family=address_family, instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_route failed for %s: %s", prefix, exc)
            route = None

        has_backup, _, _ = _has_backup_nexthop(route)

        log.debug(
            "verify_isis_no_backup_for_prefix(%s): has_backup=%s",
            prefix, has_backup,
        )

        if has_backup:
            return False

        timeout.sleep()

    return True


def verify_isis_no_mla_for_prefix(
    device,
    prefix: str,
    address_family: str = "ipv4",
    instance: str = "default",
    max_time: int = 10,
    check_interval: int = 1,
) -> bool:
    """Verify the given prefix has NO ``MICRO_LOOP_AVOIDANCE`` fast-reroute entry.

    Per arcOS doc, MLA must NOT be programmed when multiple link events
    fire concurrently. This API confirms that condition by polling
    ``get_isis_fast_reroute`` for the prefix and asserting that either no
    entry exists, or no level has ``reroute-type=='MICRO_LOOP_AVOIDANCE'``.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check.
        address_family: 'ipv4' or 'ipv6'. Default 'ipv4'.
        instance: ISIS instance name. Default 'default'.
        max_time: Polling window in seconds. Default 10.
        check_interval: Poll interval. Default 1.

    Returns:
        bool: True if no MICRO_LOOP_AVOIDANCE entry is observed across
        the entire window. False if such an entry IS observed.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            entries = get_isis_fast_reroute(
                device, prefix=prefix,
                address_family=address_family, instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_fast_reroute failed for %s: %s", prefix, exc)
            entries = {}

        prefix_entry = entries.get(prefix, {}) if isinstance(entries, dict) else {}
        levels = prefix_entry.get("levels", {}) if isinstance(prefix_entry, dict) else {}
        has_mla = any(
            (lv_data.get("reroute-type") == "MICRO_LOOP_AVOIDANCE")
            for lv_data in levels.values() if isinstance(lv_data, dict)
        )

        log.debug(
            "verify_isis_no_mla_for_prefix(%s): has_mla=%s",
            prefix, has_mla,
        )

        if has_mla:
            return False

        timeout.sleep()

    return True


def verify_isis_mla_fired(
    device,
    expected_event: Optional[str] = None,
    algo: int = 0,
    near_node: Optional[str] = None,
    far_node: Optional[str] = None,
    expected_states=("ACTIVE", "EXPIRED"),
    since_timestamp: Optional[str] = None,
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 5,
) -> bool:
    """Verify Micro-Loop-Avoidance fired for a given algorithm/topology.

    MLA records each event durably in the ``micro-loop-avoidance status``
    table (one row per algo/topology): ``mla-state`` (ACTIVE during the
    rib-update-delay window, EXPIRED after) + ``last-event`` +
    ``near-node``/``far-node``. This is the control-plane observable for MLA
    on arcOS/VIR (the ISIS fast-reroute table does not surface it).

    Polls ``get_isis_micro_loop_avoidance`` until a status row for ``algo``
    (0 = SPF/base, 128+ = flex-algo) has ``mla-state`` in ``expected_states``
    and — when specified — ``last-event == expected_event`` and matching
    ``near_node``/``far_node``.

    Args:
        device: pyATS device object.
        expected_event: If set, require ``last-event`` to equal this
            (e.g. 'METRIC-INCREASE', 'ADJACENCY-DOWN', 'OVERLOAD-BIT').
        algo: Algorithm id of the status row to match (default 0 = SPF).
        near_node / far_node: If set, require the row's endpoints to match.
        expected_states: Acceptable ``mla-state`` values (default ACTIVE or
            EXPIRED — i.e. MLA fired at some point).
        network_instance / protocol_instance: ISIS instance selectors.
        max_time / check_interval: Polling bounds (seconds).

    Returns:
        True if a matching MLA status row is found within the timeout.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            mla = get_isis_micro_loop_avoidance(
                device,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_micro_loop_avoidance failed: %s", exc)
            mla = {}

        for row in (mla.get("status") or {}).values():
            if row.get("algo") != algo:
                continue
            # Fresh-fire filter: the MLA status is a single row per
            # (algo, topology) overwritten in place, so a stale event from a
            # prior trigger can linger. When ``since_timestamp`` is given,
            # only a row whose ``spf-start-timestamp`` is strictly newer counts
            # (ISO-8601 strings compare lexicographically). Capture the
            # baseline timestamp BEFORE the trigger and pass it here.
            if since_timestamp is not None and (
                str(row.get("spf-start-timestamp") or "") <= since_timestamp
            ):
                continue
            if row.get("mla-state") not in expected_states:
                continue
            if expected_event is not None and row.get("last-event") != expected_event:
                continue
            if near_node is not None and row.get("near-node") != near_node:
                continue
            if far_node is not None and row.get("far-node") != far_node:
                continue
            log.debug(
                "verify_isis_mla_fired: matched algo=%s state=%s last-event=%s "
                "near=%s far=%s",
                algo,
                row.get("mla-state"),
                row.get("last-event"),
                row.get("near-node"),
                row.get("far-node"),
            )
            return True

        timeout.sleep()

    return False
