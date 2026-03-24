"""ArcOS Network Instance verify APIs.

Verification helpers built on top of the ArcOS Network Instance get APIs in
``genie.libs.sdk.apis.arcos.network_instance.get``.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.network_instance.get import (
    is_network_instance_present,
    get_network_instance_interfaces,
    get_network_instance_fdb_mac_entries,
)

log = logging.getLogger(__name__)


def verify_network_instance_present(
    device,
    ni_name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a network instance exists.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if NI exists within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_network_instance_present(device, ni_name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_network_instance_present failed for %s: %s", ni_name, exc)
            present = False

        log.debug("verify_network_instance_present(%s): present=%s", ni_name, present)

        if present:
            return True

        timeout.sleep()

    return False


def verify_network_instance_not_present(
    device,
    ni_name: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a network instance does NOT exist.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if NI is absent within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            present = is_network_instance_present(device, ni_name)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("is_network_instance_present failed for %s: %s", ni_name, exc)
            present = True

        log.debug(
            "verify_network_instance_not_present(%s): present=%s", ni_name, present
        )

        if not present:
            return True

        timeout.sleep()

    return False


def verify_network_instance_interface_present(
    device,
    ni_name: str,
    interface: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that an interface is bound to a network instance.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.
        interface: Interface ID to check (e.g., 'swp1.100').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if interface is bound within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            interfaces = get_network_instance_interfaces(device, ni_name)
            present = interface in interfaces
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_network_instance_interfaces failed for %s: %s", ni_name, exc
            )
            present = False

        log.debug(
            "verify_network_instance_interface_present(%s, %s): present=%s",
            ni_name,
            interface,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_network_instance_fdb_mac_present(
    device,
    ni_name: str,
    mac_address: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a MAC address is present in a network instance FDB.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.
        mac_address: MAC address to check (e.g., 'aa:bb:cc:dd:ee:ff').
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if MAC is in FDB within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            mac_entries = get_network_instance_fdb_mac_entries(device, ni_name)
            present = mac_address in mac_entries
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_network_instance_fdb_mac_entries failed for %s: %s", ni_name, exc
            )
            present = False

        log.debug(
            "verify_network_instance_fdb_mac_present(%s, %s): present=%s",
            ni_name,
            mac_address,
            present,
        )

        if present:
            return True

        timeout.sleep()

    return False


def verify_network_instance_fdb_mac_not_present(
    device,
    ni_name: str,
    mac_address: str,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that a MAC address is NOT present in a network instance FDB.

    Args:
        device: pyATS device object.
        ni_name: Network instance name.
        mac_address: MAC address to check.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if MAC is absent from FDB within timeout, False otherwise.
    """
    timeout = Timeout(max_time, check_interval)

    while timeout.iterate():
        try:
            mac_entries = get_network_instance_fdb_mac_entries(device, ni_name)
            present = mac_address in mac_entries
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "get_network_instance_fdb_mac_entries failed for %s: %s", ni_name, exc
            )
            present = True

        log.debug(
            "verify_network_instance_fdb_mac_not_present(%s, %s): present=%s",
            ni_name,
            mac_address,
            present,
        )

        if not present:
            return True

        timeout.sleep()

    return False
