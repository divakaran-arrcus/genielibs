"""ArcOS FIB (Forwarding Information Base) verify APIs.

Verification helpers built on top of the ArcOS FIB get APIs in
``genie.libs.sdk.apis.arcos.fib.get``.

These functions poll the device for a bounded amount of time and return
a boolean result.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.fib.get import (
    get_fib_label_entry,
    get_fib_nexthop_entry,
    is_prefix_in_fib,
)

log = logging.getLogger(__name__)


def verify_prefix_in_fib(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a prefix is present in the FIB.

    Polls ``is_prefix_in_fib`` until the prefix appears or *max_time* is
    exceeded.

    Args:
        device: pyATS device object.
        prefix: Route prefix to look for (e.g. ``"10.0.0.0/24"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).
        max_time: Maximum polling time in seconds (default 60).
        check_interval: Seconds between polls (default 10).

    Returns:
        ``True`` if the prefix is found within the timeout, ``False``
        otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_prefix_in_fib(device, prefix=prefix, af=af, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_prefix_in_fib failed for %s: %s", prefix, exc)
            present = False

        log.debug("verify_prefix_in_fib(%s): present=%s", prefix, present)

        if present:
            return True

        timeout.sleep()

    return False


def verify_prefix_not_in_fib(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a prefix is NOT present in the FIB.

    Polls ``is_prefix_in_fib`` until the prefix disappears or *max_time*
    is exceeded.

    Args:
        device: pyATS device object.
        prefix: Route prefix that should be absent.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).
        max_time: Maximum polling time in seconds (default 60).
        check_interval: Seconds between polls (default 10).

    Returns:
        ``True`` if the prefix is absent within the timeout, ``False``
        otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_prefix_in_fib(device, prefix=prefix, af=af, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_prefix_in_fib failed for %s: %s", prefix, exc)
            present = True  # assume present on error (safe for not_present)

        log.debug("verify_prefix_not_in_fib(%s): present=%s", prefix, present)

        if not present:
            return True

        timeout.sleep()

    return False


def verify_nexthop_in_fib(
    device,
    index: str,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a next-hop entry exists in the FIB.

    Polls ``get_fib_nexthop_entry`` until the entry is found or
    *max_time* is exceeded.

    Args:
        device: pyATS device object.
        index: Next-hop index to look for (e.g. ``"643"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).
        max_time: Maximum polling time in seconds (default 60).
        check_interval: Seconds between polls (default 10).

    Returns:
        ``True`` if the next-hop entry is found within the timeout,
        ``False`` otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            entry = get_fib_nexthop_entry(device, index=index, af=af, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_fib_nexthop_entry failed for %s: %s", index, exc)
            entry = None

        log.debug("verify_nexthop_in_fib(%s): found=%s", index, entry is not None)

        if entry is not None:
            return True

        timeout.sleep()

    return False


def verify_label_in_fib(
    device,
    label: str,
    af: str = "IPV4",
    ni: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an MPLS label entry exists in the FIB.

    Polls ``get_fib_label_entry`` until the label is found or *max_time*
    is exceeded.

    Args:
        device: pyATS device object.
        label: MPLS label to look for (e.g. ``"10005"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).
        max_time: Maximum polling time in seconds (default 60).
        check_interval: Seconds between polls (default 10).

    Returns:
        ``True`` if the label entry is found within the timeout, ``False``
        otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            entry = get_fib_label_entry(device, label=label, af=af, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_fib_label_entry failed for %s: %s", label, exc)
            entry = None

        log.debug("verify_label_in_fib(%s): found=%s", label, entry is not None)

        if entry is not None:
            return True

        timeout.sleep()

    return False
