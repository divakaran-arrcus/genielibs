"""ArcOS Keychain verify APIs.

Verification helpers built on top of the ArcOS Keychain get APIs
in ``genie.libs.sdk.apis.arcos.keychain.get``.

These functions poll the device for a bounded amount of time and return
a boolean result.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.keychain.get import (
    is_keychain_present,
)

log = logging.getLogger(__name__)


def verify_keychain_present(device, name: str,
                            max_time: int = 60,
                            check_interval: int = 10) -> bool:
    """Verify that a keychain is present in running configuration.

    Args:
        device: pyATS device object.
        name: Keychain name to check.
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the keychain is present within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_keychain_present(device, name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_keychain_present failed for %s: %s",
                name, exc
            )
            present = False

        log.debug(
            "verify_keychain_present(%s): present=%s",
            name, present
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_keychain_not_present(device, name: str,
                                max_time: int = 60,
                                check_interval: int = 10) -> bool:
    """Verify that a keychain is NOT present in running configuration.

    Args:
        device: pyATS device object.
        name: Keychain name to check.
        max_time: Maximum time to wait in seconds.
        check_interval: Poll interval in seconds.

    Returns:
        True if the keychain is absent within the timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_keychain_present(device, name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_keychain_present failed for %s: %s",
                name, exc
            )
            present = True

        log.debug(
            "verify_keychain_not_present(%s): present=%s",
            name, present
        )

        if not present:
            return True

        timeout.sleep()

    return False
