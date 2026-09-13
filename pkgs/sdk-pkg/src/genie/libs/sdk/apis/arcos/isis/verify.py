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


#: Every ``mla-state`` arcOS publishes, in C-enum order
#: (``ISIS_MLA_DISP_*`` in ``isis_common.h`` @797f74e4c0). Used to warn when a
#: device reports a state this SDK has never heard of, which is the signal that
#: the enum grew and this module needs updating.
MLA_STATES = ("NONE", "ACTIVE", "CANCELED", "EXPIRED", "EMPTY")

#: The only ``mla-state`` that means no session ever started. Everything else
#: means MLA fired. Expressed as the exclusion it actually is, so a sixth state
#: is accepted by default rather than silently regressing every caller to
#: "did not fire" — which is what a hardcoded allowlist would do.
MLA_STATES_NOT_FIRED = ("NONE",)


def verify_isis_mla_fired(
    device,
    expected_event: Optional[str] = None,
    algo: int = 0,
    near_node: Optional[str] = None,
    far_node: Optional[str] = None,
    expected_states=None,
    since_timestamp: Optional[str] = None,
    level: Optional[int] = None,
    topology_id: Optional[str] = None,
    allow_missing_timestamp: bool = True,
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 5,
) -> bool:
    """Verify Micro-Loop-Avoidance fired for a given algorithm/topology.

    MLA records each event durably in the ``micro-loop-avoidance status``
    table (one row per algo/topology): ``mla-state`` + ``last-event`` +
    ``near-node``/``far-node``. This is the control-plane observable for MLA
    on arcOS/VIR (the ISIS fast-reroute table does not surface it).

    The ``mla-state`` enum is FIVE-way, and four of the five mean the session
    started -- i.e. MLA fired:

    Listed in C-enum order (``ISIS_MLA_DISP_*``):

    ==========  ====================================================
    NONE        no session ever started; no compatible trigger. The
                only value that means "did not fire".
    ACTIVE      session running, rib-update-delay pending.
    CANCELED    torn down before the window elapsed. A conflicting
                topology change is the intended case, but the same
                teardown is reached from a flex-algo FAD change, an
                invalid change batch, a ctx-create error, and level
                disable / IS-type drop / sys-id reconfigure.
    EXPIRED     ran its full delay window and completed normally.
    EMPTY       activated, then the route calculation programmed ZERO
                MLA SID stacks, so it was torn down early.
    ==========  ====================================================

    ``EMPTY`` is the newest of these (arrcus_sw ANPN-33133 / 797f74e4c0,
    "isis: cancel MLA when the computation produces no enforcement"). Before
    that fix the rib-update-delay was armed at ctx-create time on the
    PREDICTION that MLA would be needed, so a session that enforced nothing
    still deferred TI-LFA for the whole window; the fix decides from the
    OUTCOME and tears such a session down early. It is stamped EMPTY rather
    than CANCELED precisely because no conflict occurred.

    By default every state but ``NONE`` is accepted, and that default is
    encoded as the EXCLUSION it actually is (``MLA_STATES_NOT_FIRED``) rather
    than as a list of the four acceptable values. The difference matters when
    the enum next grows: an allowlist would silently regress every default
    caller to "did not fire" for the new state, whereas an exclusion accepts
    it and logs a warning naming the unknown value.

    This matters more than it sounds: for a single-link shut on a small
    topology, EMPTY is the COMMON outcome, not the exception -- one archived
    trigger produced EMPTY on three of four (algo, topology) tuples and
    EXPIRED on the fourth. Defaulting to ("ACTIVE", "EXPIRED") made those runs
    report "MLA did not fire" while the device's own status table showed
    last-event=LINK-DOWN with a fresh SPF timestamp.

    Pass ``expected_states`` explicitly to narrow it -- e.g. ``("EXPIRED",)``
    when a test genuinely requires a completed hold. A bare string is
    accepted and normalised, so ``expected_states="EXPIRED"`` does not
    degrade into a substring match.

    .. warning::
       Do NOT compare ``spf-start-timestamp`` across states as one clock. It
       is stamped from a different SPF in each state (arrcus_sw @797f74e4c0):

       ==========  ==================================================
       NONE        no timestamp published at all -- confd gates
                   last-event/near-node/far-node/spf-start-timestamp
                   on ``state != NONE``.
       ACTIVE      the ACTIVATING SPF's start (``isis_spf.c:1710``).
       EXPIRED     deferred to the POST-CONVERGENCE SPF the RIB-delay
                   handler scheduled (``:588`` arms it, ``:5294``
                   stamps it).
       CANCELED    the CANCELING SPF's start, or wall-clock when no
                   SPF is live -- e.g. an administrative teardown
                   (``:1441`` / ``:1443``).
       EMPTY       the SPF whose route calculation installed zero MLA
                   paths; it reaches the same cancel path from inside
                   that run (``:1481``).
       ==========  ==================================================

       So two rows from one trigger can differ by ~``rib-update-delay`` with
       nothing wrong.

       Freshness-vs-baseline (``since_timestamp``) is sound for a genuine new
       fire, but it is NOT a guarantee the row describes *your* trigger.
       ``last-event``/``near-node``/``far-node`` are written only at
       activation and are not cleared by a teardown
       (``isis_clear_mla_state_for_topo`` clears the working state, not the
       oper snapshot), so an administratively cancelled row can carry a fresh
       wall-clock stamp alongside the PREVIOUS activation's event. Pair
       ``since_timestamp`` with ``expected_event`` when that matters.

    Polls ``get_isis_micro_loop_avoidance`` until a status row for ``algo``
    (0 = SPF/base, 128+ = flex-algo) has ``mla-state`` in ``expected_states``
    and — when specified — ``last-event == expected_event`` and matching
    ``near_node``/``far_node``.

    Args:
        device: pyATS device object.
        expected_event: If set, require ``last-event`` to equal this. The
            arcOS ``last-event`` enum is: 'LINK-DOWN', 'LINK-UP',
            'METRIC-INCREASE', 'METRIC-DECREASE', 'OVERLOAD-SET',
            'OVERLOAD-CLEAR', 'MAX-METRIC-SET', 'MAX-METRIC-CLEAR'.
        algo: Algorithm id of the status row to match (default 0 = SPF).
        near_node / far_node: If set, require the row's endpoints to match.
        expected_states: Acceptable ``mla-state`` values. ``None`` (default)
            means every state except ``NONE`` -- i.e. MLA fired at some
            point. Narrow it explicitly when a test needs a specific outcome;
            a bare string is normalised to a one-tuple.
        level / topology_id: Pin the status row to a specific IS-IS level or
            topology. The oper list is keyed on (algo, level, topology-id),
            so ``algo`` alone can match a different level or topology than
            intended. Both default to ``None`` (match any).
        allow_missing_timestamp: When ``since_timestamp`` is given and a
            matching row carries no ``spf-start-timestamp``, accept it with a
            warning (default) or reject it. Accepting is the default because
            such a row is most likely the fire just triggered; set ``False``
            when a test must not pass on unconfirmable freshness.
        network_instance / protocol_instance: ISIS instance selectors.
        max_time / check_interval: Polling bounds (seconds).

    Returns:
        True if a matching MLA status row is found within the timeout.
    """
    # A bare string would degrade every state test to a SUBSTRING match
    # ("NONE" in "NONE" is True, but so is "ACT" in "ACTIVE"), so normalise.
    if isinstance(expected_states, str):
        expected_states = (expected_states,)
    if expected_states is not None:
        expected_states = tuple(expected_states)

    # get_isis_mla_status_timestamp returns "" (not None) when it cannot read a
    # baseline. Left alone, "" arms the freshness filter and then compares
    # every row as newer than "" — an armed filter that rejects nothing. Treat
    # any falsy baseline as "no baseline", and say so, since the caller asked
    # for freshness checking and is not getting it.
    if since_timestamp is not None and not str(since_timestamp).strip():
        log.warning(
            "verify_isis_mla_fired: since_timestamp is empty — the freshness "
            "filter is DISABLED for this call. get_isis_mla_status_timestamp "
            "returns \"\" only when there was genuinely nothing to baseline "
            "against (no row for the algo, or a NONE row, which publishes no "
            "spf-start-timestamp), so there is normally no stale row to be "
            "fooled by. It RAISES on a failed read, so this is not masking "
            "an unreadable device. Still worth noting: this call's verdict "
            "rests on state/event/node matching alone."
        )
        since_timestamp = None

    timeout = Timeout(max_time, check_interval)
    read_failed = False
    rows_seen = 0

    while timeout.iterate():
        try:
            mla = get_isis_micro_loop_avoidance(
                device,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
            read_failed = False
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_micro_loop_avoidance failed: %s", exc)
            mla = {}
            read_failed = True

        status = (mla or {}).get("status") or {}
        rows_seen = max(rows_seen, len(status))

        for key, row in status.items():
            if row.get("algo") != algo:
                continue
            # The oper list is keyed on (algo, level, topology-id), so `algo`
            # alone can match a DIFFERENT level or topology than the caller
            # meant. Both selectors default to None (match any) to preserve
            # existing behaviour; pass them to pin the row you intend.
            if level is not None and row.get("level") != level:
                continue
            if (topology_id is not None
                    and row.get("topology-id") != topology_id):
                continue

            state = row.get("mla-state")
            if state is not None and state not in MLA_STATES:
                log.warning(
                    "verify_isis_mla_fired: row %s reports mla-state=%r, which "
                    "this SDK does not know. The arcOS enum has grown — update "
                    "MLA_STATES in %s.",
                    key, state, __name__,
                )

            # Default rule is an EXCLUSION, not an allowlist: every state but
            # NONE means the session started. An explicit expected_states
            # narrows it.
            if expected_states is None:
                if state in MLA_STATES_NOT_FIRED:
                    continue
            elif state not in expected_states:
                continue

            if expected_event is not None and row.get("last-event") != expected_event:
                continue
            if near_node is not None and row.get("near-node") != near_node:
                continue
            if far_node is not None and row.get("far-node") != far_node:
                continue

            # Fresh-fire filter, applied LAST so its warning only fires for a
            # row that otherwise matched. The MLA status is a single row per
            # (algo, level, topology) overwritten in place, so a stale event
            # from a prior trigger can linger. Capture the baseline BEFORE the
            # trigger and pass it here.
            if since_timestamp is not None:
                row_ts = row.get("spf-start-timestamp")
                if row_ts is None:
                    # Freshness cannot be confirmed. Accepting is the default
                    # because a row matching state/event/nodes with no
                    # timestamp is most likely the fire just triggered, and
                    # skipping would misreport a genuine fire as a no-fire.
                    # Pass allow_missing_timestamp=False to reject instead.
                    if not allow_missing_timestamp:
                        log.warning(
                            "verify_isis_mla_fired: algo=%s row %s has no "
                            "spf-start-timestamp and allow_missing_timestamp "
                            "is False — rejecting the match",
                            algo, key,
                        )
                        continue
                    log.warning(
                        "verify_isis_mla_fired: algo=%s row %s has no "
                        "spf-start-timestamp; cannot confirm freshness vs "
                        "baseline %s — accepting the match",
                        algo, key, since_timestamp,
                    )
                elif str(row_ts) <= str(since_timestamp):
                    continue

            log.debug(
                "verify_isis_mla_fired: matched row=%s algo=%s state=%s "
                "last-event=%s near=%s far=%s",
                key,
                algo,
                state,
                row.get("last-event"),
                row.get("near-node"),
                row.get("far-node"),
            )
            return True

        timeout.sleep()

    # Distinguish the three ways this returns False. They have different
    # causes and only the last is "the device says MLA did not fire".
    if read_failed:
        log.error(
            "verify_isis_mla_fired: returning False after the status read "
            "FAILED — this is a read/transport problem, not evidence that "
            "MLA did not fire."
        )
    elif not rows_seen:
        log.error(
            "verify_isis_mla_fired: returning False and the status table was "
            "EMPTY — arcOS omits the list entirely when MLA is globally "
            "disabled, so check the MLA config before reading this as a "
            "no-fire."
        )
    else:
        log.info(
            "verify_isis_mla_fired: no row matched algo=%s (saw %d row(s)) — "
            "the device reports MLA did not fire for this trigger.",
            algo, rows_seen,
        )
    return False
