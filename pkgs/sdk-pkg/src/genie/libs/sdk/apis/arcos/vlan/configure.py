"""Common configure functions for VLAN on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_vlan(device, vlan_name, vlan_id):
    """Create a VLAN with the given name and ID.

    Args:
        device (obj): Device object
        vlan_name (str): VLAN name (e.g. 'marketing')
        vlan_id (int): VLAN ID number

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails

    Example:
        >>> configure_vlan(device, 'marketing', 100)
    """
    log.info(
        f"Configuring VLAN '{vlan_name}' with ID {vlan_id} on {device.name}"
    )
    cmd = [
        f'vlan {vlan_name}',
        f'vlan-id {vlan_id}',
        '!',
    ]
    try:
        device.configure(cmd)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Failed to configure VLAN '{vlan_name}' on {device.name}: {e}"
        ) from e


def unconfigure_vlan(device, vlan_name):
    """Remove a VLAN.

    Args:
        device (obj): Device object
        vlan_name (str): VLAN name to remove

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails

    Example:
        >>> unconfigure_vlan(device, 'marketing')
    """
    log.info(f"Removing VLAN '{vlan_name}' from {device.name}")
    cmd = [
        f'no vlan {vlan_name}',
        '!',
    ]
    try:
        device.configure(cmd)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Failed to remove VLAN '{vlan_name}' on {device.name}: {e}"
        ) from e


def configure_vlan_name(device, vlan_name, new_name):
    """Set or update the name attribute on an existing VLAN.

    Args:
        device (obj): Device object
        vlan_name (str): Existing VLAN name
        new_name (str): New name attribute value

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails

    Example:
        >>> configure_vlan_name(device, 'marketing', 'marketing-floor2')
    """
    log.info(
        f"Setting name '{new_name}' on VLAN '{vlan_name}' on {device.name}"
    )
    cmd = [
        f'vlan {vlan_name}',
        f'name {new_name}',
        '!',
    ]
    try:
        device.configure(cmd)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Failed to set name on VLAN '{vlan_name}' on {device.name}: {e}"
        ) from e


def unconfigure_vlan_name(device, vlan_name):
    """Remove the name attribute from a VLAN.

    Args:
        device (obj): Device object
        vlan_name (str): VLAN name whose name attribute to remove

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails

    Example:
        >>> unconfigure_vlan_name(device, 'marketing')
    """
    log.info(f"Removing name attribute from VLAN '{vlan_name}' on {device.name}")
    cmd = [
        f'vlan {vlan_name}',
        'no name',
        '!',
    ]
    try:
        device.configure(cmd)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Failed to remove name from VLAN '{vlan_name}' on {device.name}: {e}"
        ) from e
