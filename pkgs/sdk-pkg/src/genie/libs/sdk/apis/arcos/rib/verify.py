"""ArcOS RIB verify APIs.

Verification helpers built on top of the ArcOS RIB get APIs in
``genie.libs.sdk.apis.arcos.rib.get``.

These functions typically poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.rib.get import (
    is_route_in_rib,
    get_route_best_protocol,
    get_rib_label_entry,
    get_rib_backup_nexthops,
)

log = logging.getLogger(__name__)


def _local(obj, key, default=None):
    """Fetch ``key`` from a dict, ignoring any YANG module prefix."""
    if not isinstance(obj, dict):
        return default
    for k, v in obj.items():
        if str(k).split(":")[-1] == key:
            return v
    return default


def verify_route_in_rib(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a route prefix is present in the RIB.

    Polls ``is_route_in_rib`` until the prefix is found or the timeout
    expires.

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. '10.0.0.0/24').
        af: Address family ('IPV4' or 'IPV6').
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the prefix is present within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_route_in_rib(device, prefix=prefix, af=af, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_route_in_rib failed for %s: %s", prefix, exc)
            present = False

        log.debug(
            "verify_route_in_rib(%s, af=%s, ni=%s): present=%s",
            prefix,
            af,
            ni,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_route_not_in_rib(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a route prefix is NOT present in the RIB.

    This is the logical negation of :func:`verify_route_in_rib`.  Polls
    ``is_route_in_rib`` until the prefix is no longer found or the timeout
    expires.

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. '10.0.0.0/24').
        af: Address family ('IPV4' or 'IPV6').
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the prefix is absent within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_route_in_rib(device, prefix=prefix, af=af, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_route_in_rib failed for %s: %s", prefix, exc)
            present = True

        log.debug(
            "verify_route_not_in_rib(%s, af=%s, ni=%s): present=%s",
            prefix,
            af,
            ni,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_route_protocol(
    device,
    prefix: str,
    expected: str,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a route's best protocol matches the expected value.

    Polls ``get_route_best_protocol`` until the protocol matches
    *expected* (compared case-insensitively) or the timeout expires.

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. '10.0.0.0/24').
        expected: Expected protocol string (e.g. 'ISIS', 'BGP').
        af: Address family ('IPV4' or 'IPV6').
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the protocol matches within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)
    expected_upper = expected.upper()

    while timeout.iterate():
        try:
            protocol = get_route_best_protocol(
                device, prefix=prefix, af=af, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_route_best_protocol failed for %s: %s", prefix, exc)
            protocol = None

        log.debug(
            "verify_route_protocol(%s, af=%s, ni=%s): current=%s, expected=%s",
            prefix,
            af,
            ni,
            protocol,
            expected_upper,
        )

        if protocol is not None and str(protocol).upper() == expected_upper:
            return True

        timeout.sleep()

    return False


def verify_label_in_rib(
    device,
    label: int,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a label entry is present in the RIB.

    Polls ``get_rib_label_entry`` until a non-None entry is returned or
    the timeout expires.

    Args:
        device: pyATS device object.
        label: MPLS label value to look up.
        af: Address family ('IPV4' or 'IPV6').
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the label entry is found within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            entry = get_rib_label_entry(device, label=label, af=af, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_rib_label_entry failed for label %s: %s", label, exc)
            entry = None

        log.debug(
            "verify_label_in_rib(label=%s, af=%s, ni=%s): entry=%s",
            label,
            af,
            ni,
            entry,
        )

        if entry is not None:
            return True

        timeout.sleep()

    return False


def verify_rib_has_backup(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
    expected_backup_egress: Optional[str] = None,
    backup_flag: str = "BACKUP",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify a prefix has a TI-LFA / FRR backup next-hop in the RIB.

    Polls ``get_rib_backup_nexthops`` until a next-hop whose ``flags`` field
    contains ``backup_flag`` (e.g. ``ATTACH,BACKUP`` / ``ATTACH,BACKUP,SR``)
    is present. If ``expected_backup_egress`` is set, also requires that
    backup next-hop's ``interface`` to match it. This is the control-plane
    observable for TI-LFA backup programming on arcOS (the ISIS route table
    and ISIS ``fast-reroute`` output do NOT surface it).

    NOTE: arcOS installs the backup next-hop on the first SPF/topology event
    *after* TI-LFA is enabled — enabling TI-LFA alone does not install it.
    Callers should trigger a metric-change (or other SPF) event after
    enabling TI-LFA and before polling this verifier.

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. ``'6.6.6.6/32'``).
        af: Address family ('IPV4' or 'IPV6').
        ni: Network instance name (default: 'default').
        expected_backup_egress: If set, require the backup next-hop's
            outgoing ``interface`` to equal this (e.g. ``'swp2'``).
        backup_flag: Flag token identifying a backup next-hop (default
            ``'BACKUP'``).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if a matching backup next-hop is present within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            backups = get_rib_backup_nexthops(
                device, prefix=prefix, af=af, ni=ni, backup_flag=backup_flag
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_rib_backup_nexthops failed for %s: %s", prefix, exc)
            backups = []

        for nh in backups:
            # A backup resolved through the SR-MPLS indirection comes from the
            # pathid table, whose leaves can arrive module-qualified, so match
            # on the local name rather than an exact key.
            egress = _local(nh, "interface")
            if (
                expected_backup_egress is None
                or egress == expected_backup_egress
            ):
                log.debug(
                    "verify_rib_has_backup(%s, af=%s): backup via %s flags=%s",
                    prefix,
                    af,
                    egress,
                    _local(nh, "flags"),
                )
                return True

        timeout.sleep()

    return False
