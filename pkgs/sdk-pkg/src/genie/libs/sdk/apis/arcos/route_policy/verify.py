"""ArcOS routing policy verify APIs.

Verification helpers built on top of the ArcOS routing policy get APIs in
``genie.libs.sdk.apis.arcos.route_policy.get``.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.route_policy.get import (
    get_prefix_set,
    get_policy_definition,
    get_tag_set,
)

log = logging.getLogger(__name__)


def verify_prefix_set_present(
    device,
    name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a prefix-set exists on the device.

    Polls ``get_prefix_set`` until it returns a non-``None`` result or the
    timeout expires.

    Args:
        device: Device object.
        name: Prefix-set name to look up.
        max_time: Maximum time in seconds to keep polling.
        check_interval: Seconds between polling attempts.

    Returns:
        True if the prefix-set is found within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            result = get_prefix_set(device, name)
            if result is not None:
                log.debug("Prefix-set %r found on %s", name, device.name)
                return True
            log.debug("Prefix-set %r not yet present on %s", name, device.name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Error checking prefix-set %r on %s: %s", name, device.name, exc
            )

        timeout.sleep()

    return False


def verify_prefix_set_not_present(
    device,
    name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a prefix-set does *not* exist on the device.

    Polls ``get_prefix_set`` until it returns ``None`` or the timeout expires.

    Args:
        device: Device object.
        name: Prefix-set name to look up.
        max_time: Maximum time in seconds to keep polling.
        check_interval: Seconds between polling attempts.

    Returns:
        True if the prefix-set is absent within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            result = get_prefix_set(device, name)
            if result is None:
                log.debug("Prefix-set %r absent on %s", name, device.name)
                return True
            log.debug("Prefix-set %r still present on %s", name, device.name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Error checking prefix-set %r on %s: %s", name, device.name, exc
            )

        timeout.sleep()

    return False


def verify_policy_definition_present(
    device,
    policy_name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a policy definition exists on the device.

    Polls ``get_policy_definition`` until it returns a non-``None`` result or
    the timeout expires.

    Args:
        device: Device object.
        policy_name: Policy definition name to look up.
        max_time: Maximum time in seconds to keep polling.
        check_interval: Seconds between polling attempts.

    Returns:
        True if the policy definition is found within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            result = get_policy_definition(device, policy_name)
            if result is not None:
                log.debug(
                    "Policy definition %r found on %s", policy_name, device.name
                )
                return True
            log.debug(
                "Policy definition %r not yet present on %s",
                policy_name,
                device.name,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Error checking policy definition %r on %s: %s",
                policy_name,
                device.name,
                exc,
            )

        timeout.sleep()

    return False


def verify_policy_definition_not_present(
    device,
    policy_name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a policy definition does *not* exist on the device.

    Polls ``get_policy_definition`` until it returns ``None`` or the timeout
    expires.

    Args:
        device: Device object.
        policy_name: Policy definition name to look up.
        max_time: Maximum time in seconds to keep polling.
        check_interval: Seconds between polling attempts.

    Returns:
        True if the policy definition is absent within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            result = get_policy_definition(device, policy_name)
            if result is None:
                log.debug(
                    "Policy definition %r absent on %s", policy_name, device.name
                )
                return True
            log.debug(
                "Policy definition %r still present on %s",
                policy_name,
                device.name,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Error checking policy definition %r on %s: %s",
                policy_name,
                device.name,
                exc,
            )

        timeout.sleep()

    return False


def verify_tag_set_present(
    device,
    name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a tag-set exists on the device.

    Polls ``get_tag_set`` until it returns a non-``None`` result or the
    timeout expires.

    Args:
        device: Device object.
        name: Tag-set name to look up.
        max_time: Maximum time in seconds to keep polling.
        check_interval: Seconds between polling attempts.

    Returns:
        True if the tag-set is found within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            result = get_tag_set(device, name)
            if result is not None:
                log.debug("Tag-set %r found on %s", name, device.name)
                return True
            log.debug("Tag-set %r not yet present on %s", name, device.name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Error checking tag-set %r on %s: %s", name, device.name, exc
            )

        timeout.sleep()

    return False
