"""Common configure functions for LLDP on ArcOS.

ArcOS LLDP uses flat global commands (no network-instance/protocol context):

    lldp hello-timer <seconds>
    lldp interface <name> mode <TX_RX|TX_ONLY|RX_ONLY>
    lldp interface <name> enabled <true|false>
"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# =====================================================================
# Hello Timer
# =====================================================================

def configure_lldp_hello_timer(device, seconds):
    """Configure LLDP hello-timer interval.

    Args:
        device (obj): Device object.
        seconds (int): Hello timer interval in seconds.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LLDP hello-timer.

    Example:
        >>> configure_lldp_hello_timer(device, 35)
    """

    log.info(
        f"Configuring LLDP hello-timer {seconds} on {device.name}"
    )

    config = [
        f'lldp hello-timer {seconds}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LLDP hello-timer {seconds} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_lldp_hello_timer(device):
    """Remove LLDP hello-timer configuration (restore default).

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LLDP hello-timer.

    Example:
        >>> unconfigure_lldp_hello_timer(device)
    """

    log.info(
        f"Removing LLDP hello-timer from {device.name}"
    )

    config = [
        'no lldp hello-timer',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LLDP hello-timer from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# Interface Mode
# =====================================================================

def configure_lldp_interface_mode(device, interface, mode):
    """Configure LLDP operation mode on an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp1').
        mode (str): Operation mode — TX_RX, TX_ONLY, or RX_ONLY.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LLDP interface mode.

    Example:
        >>> configure_lldp_interface_mode(device, 'swp1', 'RX_ONLY')
    """

    log.info(
        f"Configuring LLDP interface {interface} mode {mode} on "
        f"{device.name}"
    )

    config = [
        f'lldp interface {interface} mode {mode}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LLDP interface {interface} mode {mode} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_lldp_interface_mode(device, interface):
    """Remove LLDP mode configuration from an interface (resets to TX_RX).

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp1').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LLDP interface mode.

    Example:
        >>> unconfigure_lldp_interface_mode(device, 'swp1')
    """

    log.info(
        f"Removing LLDP interface {interface} mode from {device.name}"
    )

    config = [
        f'no lldp interface {interface} mode',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LLDP interface {interface} mode from "
            f"{device.name}. Error:\n{e}"
        )


# =====================================================================
# Interface Enabled
# =====================================================================

def configure_lldp_interface_enabled(device, interface, enabled=True):
    """Enable or disable LLDP on an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp1').
        enabled (bool): True to enable, False to disable. Defaults to True.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LLDP interface enabled.

    Example:
        >>> configure_lldp_interface_enabled(device, 'swp2', enabled=False)
    """

    enabled_str = 'true' if enabled else 'false'

    log.info(
        f"Configuring LLDP interface {interface} enabled {enabled_str} "
        f"on {device.name}"
    )

    config = [
        f'lldp interface {interface} enabled {enabled_str}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LLDP interface {interface} enabled "
            f"{enabled_str} on {device.name}. Error:\n{e}"
        )


def unconfigure_lldp_interface_enabled(device, interface):
    """Remove LLDP enabled configuration from an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp2').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LLDP interface enabled config.

    Example:
        >>> unconfigure_lldp_interface_enabled(device, 'swp2')
    """

    log.info(
        f"Removing LLDP interface {interface} enabled config from "
        f"{device.name}"
    )

    config = [
        f'no lldp interface {interface} enabled',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LLDP interface {interface} enabled config "
            f"from {device.name}. Error:\n{e}"
        )


def configure_lldp_interface_disabled(device, interface):
    """Disable LLDP on an interface (shortcut for enabled=false).

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp2').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to disable LLDP on interface.

    Example:
        >>> configure_lldp_interface_disabled(device, 'swp2')
    """

    configure_lldp_interface_enabled(device, interface, enabled=False)


def unconfigure_lldp_interface_disabled(device, interface):
    """Re-enable LLDP on an interface (removes disabled config).

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp2').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to re-enable LLDP on interface.

    Example:
        >>> unconfigure_lldp_interface_disabled(device, 'swp2')
    """

    configure_lldp_interface_enabled(device, interface, enabled=True)
