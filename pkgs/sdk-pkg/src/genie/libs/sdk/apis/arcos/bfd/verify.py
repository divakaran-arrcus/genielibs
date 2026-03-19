"""ArcOS BFD verify APIs.

Verification helpers built on top of the ArcOS BFD get APIs in
``genie.libs.sdk.apis.arcos.bfd.get``.

These functions typically poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.bfd.get import (
    get_bfd_session_state,
    is_bfd_profile_present,
    is_bfd_session_present,
)

log = logging.getLogger(__name__)


def verify_bfd_session_state(
    device,
    profile_name: str,
    discriminator: str,
    expected_state: str = "UP",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BFD session reaches the expected state within a timeout.

    Polls ``get_bfd_session_state`` repeatedly until the session state
    matches *expected_state* (case-insensitive) or the timeout expires.

    Args:
        device: Device object.
        profile_name: BFD profile name.
        discriminator: BFD session discriminator.
        expected_state: Expected session state (default ``"UP"``).
        max_time: Maximum polling time in seconds.
        check_interval: Seconds between poll attempts.

    Returns:
        ``True`` if the session state matches *expected_state* within the
        timeout window, ``False`` otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        value: Optional[str] = None
        try:
            value = get_bfd_session_state(device, profile_name, discriminator)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Exception while retrieving BFD session state for "
                "profile=%s discriminator=%s: %s",
                profile_name,
                discriminator,
                exc,
            )

        current = value.upper() if value else None
        log.debug(
            "verify_bfd_session_state: profile=%s discriminator=%s "
            "current=%s expected=%s",
            profile_name,
            discriminator,
            current,
            expected_state.upper(),
        )

        if current == expected_state.upper():
            return True

        timeout.sleep()

    return False


def verify_bfd_session_up(
    device,
    profile_name: str,
    discriminator: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BFD session is in the UP state.

    Convenience wrapper around :func:`verify_bfd_session_state` with
    ``expected_state="UP"``.

    Args:
        device: Device object.
        profile_name: BFD profile name.
        discriminator: BFD session discriminator.
        max_time: Maximum polling time in seconds.
        check_interval: Seconds between poll attempts.

    Returns:
        ``True`` if the session reaches the UP state within the timeout
        window, ``False`` otherwise.
    """

    return verify_bfd_session_state(
        device,
        profile_name,
        discriminator,
        expected_state="UP",
        max_time=max_time,
        check_interval=check_interval,
    )


def verify_bfd_session_down(
    device,
    profile_name: str,
    discriminator: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BFD session is in the DOWN state.

    Convenience wrapper around :func:`verify_bfd_session_state` with
    ``expected_state="DOWN"``.

    Args:
        device: Device object.
        profile_name: BFD profile name.
        discriminator: BFD session discriminator.
        max_time: Maximum polling time in seconds.
        check_interval: Seconds between poll attempts.

    Returns:
        ``True`` if the session reaches the DOWN state within the timeout
        window, ``False`` otherwise.
    """

    return verify_bfd_session_state(
        device,
        profile_name,
        discriminator,
        expected_state="DOWN",
        max_time=max_time,
        check_interval=check_interval,
    )


def verify_bfd_profile_present(
    device,
    profile_name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BFD profile exists on the device.

    Polls ``is_bfd_profile_present`` repeatedly until the profile is
    found or the timeout expires.

    Args:
        device: Device object.
        profile_name: BFD profile name to check for.
        max_time: Maximum polling time in seconds.
        check_interval: Seconds between poll attempts.

    Returns:
        ``True`` if the profile is present within the timeout window,
        ``False`` otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        present = False
        try:
            present = is_bfd_profile_present(device, profile_name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Exception while checking BFD profile presence for "
                "profile=%s: %s",
                profile_name,
                exc,
            )

        log.debug(
            "verify_bfd_profile_present: profile=%s present=%s",
            profile_name,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_bfd_session_present(
    device,
    profile_name: str,
    discriminator: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BFD session exists on the device.

    Polls ``is_bfd_session_present`` repeatedly until the session is
    found or the timeout expires.

    Args:
        device: Device object.
        profile_name: BFD profile name.
        discriminator: BFD session discriminator.
        max_time: Maximum polling time in seconds.
        check_interval: Seconds between poll attempts.

    Returns:
        ``True`` if the session is present within the timeout window,
        ``False`` otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        present = False
        try:
            present = is_bfd_session_present(
                device, profile_name, discriminator
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Exception while checking BFD session presence for "
                "profile=%s discriminator=%s: %s",
                profile_name,
                discriminator,
                exc,
            )

        log.debug(
            "verify_bfd_session_present: profile=%s discriminator=%s "
            "present=%s",
            profile_name,
            discriminator,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False
