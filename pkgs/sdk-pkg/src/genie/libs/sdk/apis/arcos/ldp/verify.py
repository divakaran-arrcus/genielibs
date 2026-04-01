"""ArcOS LDP verify APIs.

Verification helpers built on top of the ArcOS LDP get APIs in
``genie.libs.sdk.apis.arcos.ldp.get``.

These functions poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.ldp.get import (
    get_ldp_session_state,
    get_ldp_sessions,
)

log = logging.getLogger(__name__)


def verify_ldp_session_operational(
    device,
    peer_address: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an LDP session to a peer reaches Operational state.

    This uses :func:`get_ldp_session_state` to poll the device.

    Args:
        device: pyATS device object.
        peer_address: Peer address to check (e.g., '1.1.1.1').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the session reaches Operational within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            state = get_ldp_session_state(device, peer_address)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_ldp_session_state failed for %s: %s",
                peer_address, exc,
            )
            state = None

        log.debug(
            "verify_ldp_session_operational(%s): state=%s",
            peer_address, state,
        )

        if state is not None and state == "Operational":
            return True

        timeout.sleep()

    return False


def verify_ldp_session_not_present(
    device,
    peer_address: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an LDP session to a peer is NOT present.

    This uses :func:`get_ldp_sessions` to poll the device.

    Args:
        device: pyATS device object.
        peer_address: Peer address that should be absent.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the session is absent within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            sessions = get_ldp_sessions(device)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_ldp_sessions failed: %s", exc,
            )
            sessions = {peer_address: True}  # assume present on error

        present = peer_address in sessions

        log.debug(
            "verify_ldp_session_not_present(%s): present=%s",
            peer_address, present,
        )

        if not present:
            return True

        timeout.sleep()

    return False
