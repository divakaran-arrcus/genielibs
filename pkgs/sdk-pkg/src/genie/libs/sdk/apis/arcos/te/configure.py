"""Common configure functions for TE on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_te_admin_group(device, name, bit_position,
                              network_instance='default'):
    """Configure a TE admin-group (color) with a bit position.

    Args:
        device (obj): Device object
        name (str): Admin-group name (e.g., 'red', 'green', 'blue')
        bit_position (int): Bit position for the admin-group
        network_instance (str, optional): Network instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure TE admin-group

    Example:
        >>> configure_te_admin_group(device, 'red', 11)
    """
    log.info(
        f"Configuring TE admin-group '{name}' bit-position {bit_position} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {network_instance}',
        f'te admin-group {name}',
        f'bit-position {bit_position}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure TE admin-group '{name}' on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_te_admin_group(device, name, network_instance='default'):
    """Remove a TE admin-group.

    Args:
        device (obj): Device object
        name (str): Admin-group name to remove
        network_instance (str, optional): Network instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove TE admin-group

    Example:
        >>> unconfigure_te_admin_group(device, 'red')
    """
    log.info(f"Removing TE admin-group '{name}' from {device.name}")

    config = [
        f'network-instance {network_instance}',
        f'no te admin-group {name}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove TE admin-group '{name}' from {device.name}. "
            f"Error:\n{e}"
        )
