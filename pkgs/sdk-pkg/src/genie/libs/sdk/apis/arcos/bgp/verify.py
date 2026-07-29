"""ArcOS BGP verify APIs.

Verification helpers built on top of the ArcOS BGP get APIs in
``genie.libs.sdk.apis.arcos.bgp.get``.

These functions typically poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.bgp.get import (
    get_bgp_neighbor_state,
    get_bgp_running_config_global,
    is_bgp_neighbor_present,
    is_bgp_route_present,
)

log = logging.getLogger(__name__)


def verify_bgp_neighbor_state(
    device,
    neighbor: str,
    expected_state: str,
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify BGP neighbor is in the expected session state.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address (e.g., '10.0.0.1').
        expected_state: Expected session state string (e.g., 'ESTABLISHED').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if neighbor state matches within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)
    expected_upper = expected_state.upper()

    while timeout.iterate():
        try:
            state = get_bgp_neighbor_state(
                device,
                neighbor=neighbor,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:
            log.error("get_bgp_neighbor_state failed for %s: %s", neighbor, exc)
            state = None

        log.debug(
            "verify_bgp_neighbor_state(%s): current=%s, expected=%s",
            neighbor,
            state,
            expected_upper,
        )

        if state is not None and str(state).upper() == expected_upper:
            return True

        timeout.sleep()

    return False


def verify_bgp_neighbor_established(
    device,
    neighbor: str,
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify BGP neighbor is in ESTABLISHED state.

    Convenience wrapper around :func:`verify_bgp_neighbor_state`.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if neighbor is ESTABLISHED within timeout, False otherwise.
    """
    return verify_bgp_neighbor_state(
        device,
        neighbor=neighbor,
        expected_state="ESTABLISHED",
        network_instance=network_instance,
        protocol_instance=protocol_instance,
        max_time=max_time,
        check_interval=check_interval,
    )


def verify_bgp_neighbor_present(
    device,
    neighbor: str,
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BGP neighbor is present.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address to look for.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if neighbor is present within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_bgp_neighbor_present(
                device,
                neighbor=neighbor,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:
            log.error("is_bgp_neighbor_present failed for %s: %s", neighbor, exc)
            present = False

        log.debug(
            "verify_bgp_neighbor_present(%s): present=%s",
            neighbor,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_bgp_neighbor_not_present(
    device,
    neighbor: str,
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BGP neighbor is NOT present.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address to check absence of.
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if neighbor is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_bgp_neighbor_present(
                device,
                neighbor=neighbor,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:
            log.error("is_bgp_neighbor_present failed for %s: %s", neighbor, exc)
            present = True

        log.debug(
            "verify_bgp_neighbor_not_present(%s): present=%s",
            neighbor,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_bgp_route_present(
    device,
    prefix: str,
    afi_safi: str = "IPV4_UNICAST",
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BGP route is present in the RIB.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '10.0.0.0/24').
        afi_safi: AFI-SAFI name (default: 'IPV4_UNICAST').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if route is present within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_bgp_route_present(
                device,
                prefix=prefix,
                afi_safi=afi_safi,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:
            log.error("is_bgp_route_present failed for %s: %s", prefix, exc)
            present = False

        log.debug(
            "verify_bgp_route_present(%s, afi_safi=%s): present=%s",
            prefix,
            afi_safi,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_bgp_route_not_present(
    device,
    prefix: str,
    afi_safi: str = "IPV4_UNICAST",
    network_instance: str = "default",
    protocol_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a BGP route is NOT present in the RIB.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '10.0.0.0/24').
        afi_safi: AFI-SAFI name (default: 'IPV4_UNICAST').
        network_instance: Network instance name (default: "default").
        protocol_instance: BGP protocol instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if route is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_bgp_route_present(
                device,
                prefix=prefix,
                afi_safi=afi_safi,
                network_instance=network_instance,
                protocol_instance=protocol_instance,
            )
        except Exception as exc:
            log.error("is_bgp_route_present failed for %s: %s", prefix, exc)
            present = True

        log.debug(
            "verify_bgp_route_not_present(%s, afi_safi=%s): present=%s",
            prefix,
            afi_safi,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# Verify — Running config
# ---------------------------------------------------------------------------


def verify_bgp_as_configured(
    device,
    expected_as: int,
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify BGP AS number in running configuration.

    Polls the running-config until the AS matches the expected value.

    Args:
        device: pyATS device object.
        expected_as: Expected AS number.
        network_instance: Network instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if AS matches within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            cfg = get_bgp_running_config_global(
                device, network_instance=network_instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_bgp_running_config_global failed: %s", exc)
            cfg = {}

        actual_as = cfg.get("as")
        log.debug(
            "verify_bgp_as_configured(): actual=%s, expected=%s",
            actual_as,
            expected_as,
        )

        if actual_as is not None and int(actual_as) == int(expected_as):
            return True

        timeout.sleep()

    return False


def verify_bgp_router_id_configured(
    device,
    expected_router_id: str,
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify BGP router-id in running configuration.

    Polls the running-config until the router-id matches.

    Args:
        device: pyATS device object.
        expected_router_id: Expected router-id string.
        network_instance: Network instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if router-id matches within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            cfg = get_bgp_running_config_global(
                device, network_instance=network_instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_bgp_running_config_global failed: %s", exc)
            cfg = {}

        actual_rid = cfg.get("router-id")
        log.debug(
            "verify_bgp_router_id_configured(): actual=%s, expected=%s",
            actual_rid,
            expected_router_id,
        )

        if actual_rid is not None and actual_rid == expected_router_id:
            return True

        timeout.sleep()

    return False


def verify_bgp_neighbor_configured(
    device,
    neighbor: str,
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify a BGP neighbor exists in running configuration.

    Args:
        device: pyATS device object.
        neighbor: Neighbor address (IPv4 or IPv6).
        network_instance: Network instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if neighbor is in running-config within timeout, False otherwise.
    """
    from genie.libs.sdk.apis.arcos.bgp.get import get_bgp_running_config_neighbors

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            nbrs = get_bgp_running_config_neighbors(
                device, network_instance=network_instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_bgp_running_config_neighbors failed: %s", exc)
            nbrs = {}

        present = neighbor in nbrs
        log.debug(
            "verify_bgp_neighbor_configured(%s): present=%s",
            neighbor,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_bgp_peer_group_configured(
    device,
    peer_group: str,
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify a BGP peer-group exists in running configuration.

    Args:
        device: pyATS device object.
        peer_group: Peer-group name.
        network_instance: Network instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if peer-group is in running-config within timeout, False otherwise.
    """
    from genie.libs.sdk.apis.arcos.bgp.get import get_bgp_running_config_peer_groups

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            pgs = get_bgp_running_config_peer_groups(
                device, network_instance=network_instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_bgp_running_config_peer_groups failed: %s", exc)
            pgs = {}

        present = peer_group in pgs
        log.debug(
            "verify_bgp_peer_group_configured(%s): present=%s",
            peer_group,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False
