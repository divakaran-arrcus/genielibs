"""Common configure functions for ArcOS interfaces.

This module provides high-level helper APIs to administratively
shut / unshut interfaces on ArcOS devices using pyATS/Genie
devices and Unicon.

APIs:
- shut_interface(device, interface)
- unshut_interface(device, interface)
"""

import logging

from unicon.core.errors import SubCommandFailure
from genie.harness.utils import connect_device


log = logging.getLogger(__name__)


def shut_interface(device, interface):
    """Shut (administratively disable) an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface: Interface name, e.g. "swp1", "Ethernet1/1".

    Raises:
        SubCommandFailure: If the configuration fails.
    """

    if not device.is_connected():
        connect_device(device=device)

    log.info("Shutting interface %s on device %s", interface, device.name)

    try:
        device.configure([
            f"interface {interface}",
            "enabled false",
        ])
    except SubCommandFailure as e:
        msg = (
            "Could not shut interface {intf} on device {dev}. Error:\n{error}".format(
                intf=interface,
                dev=device.name,
                error=e,
            )
        )
        log.error(msg)
        raise SubCommandFailure(msg)


def unshut_interface(device, interface):
    """Unshut (administratively enable) an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface: Interface name, e.g. "swp1", "Ethernet1/1".

    Raises:
        SubCommandFailure: If the configuration fails.
    """

    if not device.is_connected():
        connect_device(device=device)

    log.info("Unshutting interface %s on device %s", interface, device.name)

    try:
        device.configure([
            f"interface {interface}",
            "enabled true",
        ])
    except SubCommandFailure as e:
        msg = (
            "Could not unshut interface {intf} on device {dev}. Error:\n{error}".format(
                intf=interface,
                dev=device.name,
                error=e,
            )
        )
        log.error(msg)
        raise SubCommandFailure(msg)

