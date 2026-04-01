"""ArcOS ISIS verify APIs.

Verification helpers built on top of the ArcOS ISIS get APIs in
``genie.libs.sdk.apis.arcos.isis.get``.

These functions typically poll the device for a bounded amount of time
and return a boolean result.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.isis.get import (
    get_isis_adjacency_state,
    get_isis_routes,
    get_isis_system_id,
    is_isis_adjacency_present,
    is_isis_flex_algo_route_present,
    is_isis_flex_algo_fast_reroute_present,
    get_isis_flex_algo_definitions,
)

log = logging.getLogger(__name__)


def verify_isis_system_id(
    device,
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that ISIS system-id is available.

    This is useful to verify that ISIS subsystem has started and is responding
    to queries after configuration.

    Args:
        device: pyATS device object.
        instance: ISIS instance name (default: "default").
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the system-id is available within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            system_id = get_isis_system_id(device, instance=instance)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_system_id failed for instance %s: %s", instance, exc)
            system_id = None

        log.debug(
            "verify_isis_system_id(instance=%s): system_id=%s",
            instance,
            system_id,
        )

        if system_id is not None:
            return True

        timeout.sleep()

    return False


def verify_isis_adjacency_present(
    device,
    adjacency: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS adjacency is present.

    Args:
        device: pyATS device object.
        adjacency: Adjacency system-id to look for.
        instance: ISIS instance name (default: "default").
        interface: Optional interface filter.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the adjacency is present within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_adjacency_present(
                device,
                adjacency=adjacency,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_adjacency_present failed for %s: %s", adjacency, exc)
            present = False

        log.debug(
            "verify_isis_adjacency_present(%s): present=%s",
            adjacency,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_adjacency_not_present(
    device,
    adjacency: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS adjacency is NOT present.

    This is the logical negation of :func:`verify_isis_adjacency_present`.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_adjacency_present(
                device,
                adjacency=adjacency,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_adjacency_present failed for %s: %s", adjacency, exc)
            present = True

        log.debug(
            "verify_isis_adjacency_not_present(%s): present=%s",
            adjacency,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_isis_adjacency_state(
    device,
    adjacency: str,
    expected_state: str,
    instance: str = "default",
    interface: Optional[str] = None,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify ISIS adjacency state for a given adjacency.

    Args:
        device: pyATS device object.
        adjacency: Adjacency system-id.
        expected_state: Expected adjacency state string (e.g. 'UP').
        instance: ISIS instance name.
        interface: Optional interface filter.

    Returns:
        True if the adjacency state matches within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)
    expected_state = expected_state.upper()

    while timeout.iterate():
        try:
            state = get_isis_adjacency_state(
                device,
                adjacency=adjacency,
                instance=instance,
                interface=interface,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_adjacency_state failed for %s: %s", adjacency, exc)
            state = None

        log.debug(
            "verify_isis_adjacency_state(%s): current=%s, expected=%s",
            adjacency,
            state,
            expected_state,
        )

        if state is not None and str(state).upper() == expected_state:
            return True

        timeout.sleep()

    return False


def verify_isis_route_present(
    device,
    prefix: str,
    address_family: str = "ipv4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS route is present for the given prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. '10.0.0.0/24', '2001:db8::/64').
        address_family: 'ipv4' or 'ipv6'.
        instance: ISIS instance name (currently always 'default' on ArcOS).
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the route is present within the timeout, False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            routes = get_isis_routes(
                device,
                address_family=address_family,
                instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_isis_routes failed for AF %s: %s", address_family, exc)
            routes = {}

        present = prefix in routes

        log.debug(
            "verify_isis_route_present(%s, af=%s): present=%s",
            prefix,
            address_family,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


# ---------------------------------------------------------------------------
# Flex-Algo Verify APIs
# ---------------------------------------------------------------------------

def verify_isis_flex_algo_route_present(
    device,
    prefix: str,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo route is present.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check (e.g., '10.0.0.0/24').
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*' for all.
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if route is present within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_route_present(
                device, prefix=prefix, afi=afi, algo=algo, instance=instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_flex_algo_route_present failed for %s: %s", prefix, exc)
            present = False

        log.debug(
            "verify_isis_flex_algo_route_present(%s, algo=%s): present=%s",
            prefix,
            algo,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_route_not_present(
    device,
    prefix: str,
    afi: str = "IPV4",
    algo: str = "*",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo route is NOT present.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check.
        afi: Address family ('IPV4' or 'IPV6').
        algo: Flexible-algorithm ID or '*'.
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if route is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_route_present(
                device, prefix=prefix, afi=afi, algo=algo, instance=instance
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_isis_flex_algo_route_present failed for %s: %s", prefix, exc)
            present = True

        log.debug(
            "verify_isis_flex_algo_route_not_present(%s, algo=%s): present=%s",
            prefix,
            algo,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_definition_present(
    device,
    algo_id: int,
    instance: str = "default",
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo definition is configured.

    Args:
        device: pyATS device object.
        algo_id: Flexible-algorithm ID (128-255).
        instance: ISIS protocol instance name.
        network_instance: Network instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if definition exists within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            definitions = get_isis_flex_algo_definitions(
                device, instance=instance, network_instance=network_instance
            )
            present = str(algo_id) in definitions
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_isis_flex_algo_definitions failed for algo %s: %s", algo_id, exc
            )
            present = False

        log.debug(
            "verify_isis_flex_algo_definition_present(%s): present=%s",
            algo_id,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_definition_not_present(
    device,
    algo_id: int,
    instance: str = "default",
    network_instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an ISIS flex-algo definition does NOT exist.

    Args:
        device: pyATS device object.
        algo_id: Flexible-algorithm ID (128-255).
        instance: ISIS protocol instance name.
        network_instance: Network instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if definition is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            definitions = get_isis_flex_algo_definitions(
                device, instance=instance, network_instance=network_instance
            )
            present = str(algo_id) in definitions
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_isis_flex_algo_definitions failed for algo %s: %s", algo_id, exc
            )
            present = True  # assume present on error

        log.debug(
            "verify_isis_flex_algo_definition_not_present(%s): present=%s",
            algo_id,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_fast_reroute_present(
    device,
    prefix: str,
    algo: int,
    afi: str = "IPV4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a flex-algo fast-reroute entry exists for a prefix.

    This uses :func:`is_isis_flex_algo_fast_reroute_present` to poll
    the device.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '3.3.3.3/32').
        algo: Flexible-algorithm ID (e.g., 128).
        afi: Address family ('IPV4' or 'IPV6').
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the FRR entry appears within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_fast_reroute_present(
                device, prefix=prefix, algo=algo,
                afi=afi, instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_isis_flex_algo_fast_reroute_present failed for "
                "%s algo %s: %s", prefix, algo, exc,
            )
            present = False

        log.debug(
            "verify_isis_flex_algo_fast_reroute_present(%s, algo=%s): "
            "present=%s",
            prefix, algo, present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_isis_flex_algo_fast_reroute_not_present(
    device,
    prefix: str,
    algo: int,
    afi: str = "IPV4",
    instance: str = "default",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a flex-algo fast-reroute entry does NOT exist for a prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g., '3.3.3.3/32').
        algo: Flexible-algorithm ID (e.g., 128).
        afi: Address family ('IPV4' or 'IPV6').
        instance: ISIS instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the FRR entry is absent within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_isis_flex_algo_fast_reroute_present(
                device, prefix=prefix, algo=algo,
                afi=afi, instance=instance,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "is_isis_flex_algo_fast_reroute_present failed for "
                "%s algo %s: %s", prefix, algo, exc,
            )
            present = True  # assume present on error

        log.debug(
            "verify_isis_flex_algo_fast_reroute_not_present(%s, algo=%s): "
            "present=%s",
            prefix, algo, present,
        )

        if not present:
            return True

        timeout.sleep()

    return False
