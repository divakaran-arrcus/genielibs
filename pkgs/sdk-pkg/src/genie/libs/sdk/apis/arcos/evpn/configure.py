"""Common configure functions for EVPN on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_evpn_anycast_gateway_mac(device, mac):
    """Configure EVPN anycast gateway MAC address.

    Args:
        device (obj): Device object
        mac (str): MAC address (e.g., 'aa:bb:cc:01:02:03')

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure EVPN anycast gateway MAC

    Example:
        >>> configure_evpn_anycast_gateway_mac(device, 'aa:bb:cc:01:02:03')
    """
    log.info(f"Configuring EVPN anycast-gateway-mac {mac} on {device.name}")

    config = [
        f'evpn anycast-gateway-mac {mac}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure EVPN anycast-gateway-mac on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_evpn_anycast_gateway_mac(device):
    """Remove EVPN anycast gateway MAC address.

    Args:
        device (obj): Device object

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove EVPN anycast gateway MAC

    Example:
        >>> unconfigure_evpn_anycast_gateway_mac(device)
    """
    log.info(f"Removing EVPN anycast-gateway-mac from {device.name}")

    config = [
        'no evpn anycast-gateway-mac',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove EVPN anycast-gateway-mac from {device.name}. "
            f"Error:\n{e}"
        )


def configure_evpn_df_election_time(device, seconds):
    """Configure EVPN DF election hold timer.

    Args:
        device (obj): Device object
        seconds (int): DF election time in seconds

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure EVPN DF election time

    Example:
        >>> configure_evpn_df_election_time(device, 15)
    """
    log.info(f"Configuring EVPN df-election-time {seconds} on {device.name}")

    config = [
        f'evpn df-election-time {seconds}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure EVPN df-election-time on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_evpn_df_election_time(device):
    """Remove EVPN DF election hold timer configuration.

    Args:
        device (obj): Device object

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove EVPN DF election time

    Example:
        >>> unconfigure_evpn_df_election_time(device)
    """
    log.info(f"Removing EVPN df-election-time from {device.name}")

    config = [
        'no evpn df-election-time',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove EVPN df-election-time from {device.name}. "
            f"Error:\n{e}"
        )


def configure_evpn_duplicate_mac_detection(device, window=None, threshold=None,
                                            auto_recovery_time=None):
    """Configure EVPN duplicate MAC detection parameters.

    At least one parameter must be provided.

    Args:
        device (obj): Device object
        window (int, optional): Detection window in seconds
        threshold (int, optional): Detection threshold (move count)
        auto_recovery_time (int, optional): Auto-recovery time in seconds (0 disables)

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure duplicate MAC detection

    Example:
        >>> configure_evpn_duplicate_mac_detection(device, window=60, threshold=7)
    """
    log.info(f"Configuring EVPN duplicate-mac-detection on {device.name}")

    config = []
    if window is not None:
        config.append(f'evpn duplicate-mac-detection window {window}')
    if threshold is not None:
        config.append(f'evpn duplicate-mac-detection threshold {threshold}')
    if auto_recovery_time is not None:
        config.append(
            f'evpn duplicate-mac-detection auto-recovery-time {auto_recovery_time}'
        )

    if not config:
        log.warning("No duplicate-mac-detection parameters provided")
        return

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure EVPN duplicate-mac-detection on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_evpn_duplicate_mac_detection(device):
    """Remove EVPN duplicate MAC detection configuration.

    Removes all three duplicate-mac-detection parameters.

    Args:
        device (obj): Device object

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove duplicate MAC detection

    Example:
        >>> unconfigure_evpn_duplicate_mac_detection(device)
    """
    log.info(f"Removing EVPN duplicate-mac-detection from {device.name}")

    config = [
        'no evpn duplicate-mac-detection window',
        'no evpn duplicate-mac-detection threshold',
        'no evpn duplicate-mac-detection auto-recovery-time',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove EVPN duplicate-mac-detection from {device.name}. "
            f"Error:\n{e}"
        )
