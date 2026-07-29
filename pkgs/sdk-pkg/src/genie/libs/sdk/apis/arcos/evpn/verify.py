"""ArcOS EVPN verify APIs.

Verification helpers built on top of the ArcOS EVPN get APIs in
``genie.libs.sdk.apis.arcos.evpn.get``.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.evpn.get import (
    get_evpn_anycast_gateway_mac,
    get_evpn_df_election_time,
)

log = logging.getLogger(__name__)


def verify_evpn_anycast_gateway_mac(
    device,
    expected_mac: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify EVPN anycast gateway MAC matches expected value.

    Args:
        device: pyATS device object.
        expected_mac: Expected MAC address string (e.g., 'aa:bb:cc:01:02:03').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if MAC matches within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)
    expected_lower = expected_mac.lower()

    while timeout.iterate():
        try:
            mac = get_evpn_anycast_gateway_mac(device)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_evpn_anycast_gateway_mac failed: %s", exc)
            mac = None

        log.debug(
            "verify_evpn_anycast_gateway_mac: current=%s, expected=%s",
            mac,
            expected_lower,
        )

        if mac is not None and mac.lower() == expected_lower:
            return True

        timeout.sleep()

    return False


def verify_evpn_df_election_time(
    device,
    expected_time: int,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify EVPN DF election hold timer matches expected value.

    Args:
        device: pyATS device object.
        expected_time: Expected DF election time in seconds.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if timer matches within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            current = get_evpn_df_election_time(device)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_evpn_df_election_time failed: %s", exc)
            current = None

        log.debug(
            "verify_evpn_df_election_time: current=%s, expected=%s",
            current,
            expected_time,
        )

        if current is not None:
            try:
                if int(current) == int(expected_time):
                    return True
            except (ValueError, TypeError):
                pass

        timeout.sleep()

    return False
