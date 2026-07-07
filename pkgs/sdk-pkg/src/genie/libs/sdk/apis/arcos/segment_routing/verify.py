"""ArcOS Segment Routing verify APIs.

Verification helpers built on top of the ArcOS Segment Routing get APIs
in ``genie.libs.sdk.apis.arcos.segment_routing.get``.

These functions poll the device for a bounded amount of time and return
a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.segment_routing.get import (
    is_srv6_locator_present,
    is_srms_mapping_present,
    get_srv6_encap_source_address,
    get_srv6_locator_count,
    get_srv6_locator_algorithm,
    get_srv6_locator_micro_segment_enabled,
    get_srv6_local_sids,
    get_srv6_local_sid_behavior,
)

log = logging.getLogger(__name__)


def verify_srv6_locator_present(device, locator_name: str,
                                ni: str = 'default',
                                max_time: int = 60,
                                check_interval: int = 10) -> bool:
    """Verify that an SRv6 locator is present in operational state.

    Args:
        device: pyATS device object.
        locator_name: Name of the SRv6 locator to check.
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the locator is present within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_srv6_locator_present(
                device, locator_name, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_srv6_locator_present failed for %s: %s",
                locator_name, exc
            )
            present = False

        log.debug(
            "verify_srv6_locator_present(%s): present=%s",
            locator_name, present
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_srv6_locator_not_present(device, locator_name: str,
                                    ni: str = 'default',
                                    max_time: int = 60,
                                    check_interval: int = 10) -> bool:
    """Verify that an SRv6 locator is NOT present in operational state.

    This is the logical negation of :func:`verify_srv6_locator_present`.

    Args:
        device: pyATS device object.
        locator_name: Name of the SRv6 locator to check.
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the locator is absent within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_srv6_locator_present(
                device, locator_name, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_srv6_locator_present failed for %s: %s",
                locator_name, exc
            )
            present = True

        log.debug(
            "verify_srv6_locator_not_present(%s): present=%s",
            locator_name, present
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_srms_mapping_present(device, mapping_id: str,
                                ni: str = 'default',
                                max_time: int = 60,
                                check_interval: int = 10) -> bool:
    """Verify that an SRMS mapping is present.

    Args:
        device: pyATS device object.
        mapping_id: Mapping identifier (local-id) to check.
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the mapping is present within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_srms_mapping_present(
                device, mapping_id, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_srms_mapping_present failed for %s: %s",
                mapping_id, exc
            )
            present = False

        log.debug(
            "verify_srms_mapping_present(%s): present=%s",
            mapping_id, present
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_srms_mapping_not_present(device, mapping_id: str,
                                    ni: str = 'default',
                                    max_time: int = 60,
                                    check_interval: int = 10) -> bool:
    """Verify that an SRMS mapping is NOT present.

    This is the logical negation of :func:`verify_srms_mapping_present`.

    Args:
        device: pyATS device object.
        mapping_id: Mapping identifier (local-id) to check.
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the mapping is absent within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_srms_mapping_present(
                device, mapping_id, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_srms_mapping_present failed for %s: %s",
                mapping_id, exc
            )
            present = True

        log.debug(
            "verify_srms_mapping_not_present(%s): present=%s",
            mapping_id, present
        )

        if not present:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# SRv6 encapsulation verify
# ---------------------------------------------------------------------------

def verify_srv6_encap_source_address(device, expected: str,
                                     ni: str = 'default',
                                     max_time: int = 60,
                                     check_interval: int = 10) -> bool:
    """Verify the SRv6 encapsulation source address matches expected.

    Uses :func:`get_srv6_encap_source_address` to poll the device.

    Args:
        device: pyATS device object.
        expected: Expected source IPv6 address string.
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the source address matches within the timeout,
        False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            actual: Optional[str] = get_srv6_encap_source_address(
                device, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_srv6_encap_source_address failed: %s", exc)
            actual = None

        log.debug(
            "verify_srv6_encap_source_address(): actual=%s, expected=%s",
            actual, expected
        )

        if actual is not None and actual == expected:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# SRv6 locator count verify
# ---------------------------------------------------------------------------

def verify_srv6_locator_count(device, expected_count: int,
                              ni: str = 'default',
                              max_time: int = 60,
                              check_interval: int = 10) -> bool:
    """Verify the number of SRv6 locators matches expected.

    Uses :func:`get_srv6_locator_count` to poll the device.

    Args:
        device: pyATS device object.
        expected_count: Expected number of locators.
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the count matches within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            actual: int = get_srv6_locator_count(device, ni=ni)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_srv6_locator_count failed: %s", exc)
            actual = -1

        log.debug(
            "verify_srv6_locator_count(): actual=%s, expected=%s",
            actual, expected_count
        )

        if actual == expected_count:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# SRv6 locator algorithm verify
# ---------------------------------------------------------------------------

def verify_srv6_locator_algorithm(device, locator_name: str,
                                  expected_algorithm: int,
                                  ni: str = 'default',
                                  max_time: int = 60,
                                  check_interval: int = 10) -> bool:
    """Verify an SRv6 locator has the expected algorithm value.

    Uses :func:`get_srv6_locator_algorithm` to poll the device.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator.
        expected_algorithm: Expected algorithm integer (e.g. 128).
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the algorithm matches within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            actual: Optional[int] = get_srv6_locator_algorithm(
                device, locator_name, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_srv6_locator_algorithm failed for %s: %s",
                locator_name, exc
            )
            actual = None

        log.debug(
            "verify_srv6_locator_algorithm(%s): actual=%s, expected=%s",
            locator_name, actual, expected_algorithm
        )

        if actual is not None and actual == expected_algorithm:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# SRv6 locator micro-segment verify
# ---------------------------------------------------------------------------

def verify_srv6_locator_micro_segment_enabled(
    device, locator_name: str, expected: bool,
    ni: str = 'default',
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify micro-segment-behavior-unode state on an SRv6 locator.

    Uses :func:`get_srv6_locator_micro_segment_enabled` to poll the
    device.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator.
        expected: Expected micro-segment state (True/False).
        ni: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the micro-segment state matches within the timeout,
        False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            actual: Optional[bool] = get_srv6_locator_micro_segment_enabled(
                device, locator_name, ni=ni
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_srv6_locator_micro_segment_enabled failed for %s: %s",
                locator_name, exc
            )
            actual = None

        log.debug(
            "verify_srv6_locator_micro_segment_enabled(%s): "
            "actual=%s, expected=%s",
            locator_name, actual, expected
        )

        if actual is not None and actual == expected:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# SRv6 local-SID verifiers
# ---------------------------------------------------------------------------

def verify_srv6_local_sid_present(device,
                                  locator_name: Optional[str] = None,
                                  behavior: Optional[str] = None,
                                  sid: Optional[str] = None,
                                  network_instance: str = 'default',
                                  max_time: int = 30,
                                  check_interval: int = 5) -> bool:
    """Verify that an SRv6 local-SID matching the given filters is present.

    At least one local-SID entry must match ALL of the provided
    (non-``None``) filters. Any filter left as ``None`` is ignored.

    Args:
        device: pyATS device object.
        locator_name: Locator name to match, or None to ignore.
        behavior: Behavior string to match, or None to ignore.
        sid: Specific SID to match, or None to ignore.
        network_instance: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if a matching local-SID is present within the timeout,
        False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            sids = get_srv6_local_sids(
                device, network_instance=network_instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_srv6_local_sids failed: %s", exc)
            sids = {}

        present = False
        for cur_sid, entry in sids.items():
            if sid is not None and cur_sid != sid:
                continue
            if locator_name is not None and entry.get(
                "locator_name"
            ) != locator_name:
                continue
            if behavior is not None and entry.get("behavior") != behavior:
                continue
            present = True
            break

        log.debug(
            "verify_srv6_local_sid_present(sid=%s, locator_name=%s, "
            "behavior=%s): present=%s",
            sid, locator_name, behavior, present
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_srv6_local_sid_behavior(device, sid: str, behavior: str,
                                   network_instance: str = 'default',
                                   max_time: int = 30,
                                   check_interval: int = 5) -> bool:
    """Verify the behavior of an SRv6 local-SID matches expected.

    Uses :func:`get_srv6_local_sid_behavior` to poll the device.

    Args:
        device: pyATS device object.
        sid: SID value to check.
        behavior: Expected behavior string (e.g. ``'END_PSP_USD'``).
        network_instance: Network instance name (default: 'default').
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the SID's behavior matches within the timeout, False
        otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            actual: Optional[str] = get_srv6_local_sid_behavior(
                device, sid, network_instance=network_instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_srv6_local_sid_behavior failed for %s: %s", sid, exc
            )
            actual = None

        log.debug(
            "verify_srv6_local_sid_behavior(%s): actual=%s, expected=%s",
            sid, actual, behavior
        )

        if actual is not None and actual == behavior:
            return True

        timeout.sleep()

    return False
