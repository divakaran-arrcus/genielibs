"""ArcOS Segment Routing verify APIs.

Verification helpers built on top of the ArcOS Segment Routing get APIs
in ``genie.libs.sdk.apis.arcos.segment_routing.get``.

These functions poll the device for a bounded amount of time and return
a boolean result.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.segment_routing.get import (
    is_srv6_locator_present,
    is_srms_mapping_present,
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
