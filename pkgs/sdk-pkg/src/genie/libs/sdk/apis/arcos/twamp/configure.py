"""Common configure functions for TWAMP on ArcOS"""

import logging

from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_twamp_session_reflector(device, enabled=True,
                                       reflector_udp_port=None,
                                       network_instance='default'):
    """Configure TWAMP session reflector.

    Enables the TWAMP Light session reflector which is required for ISIS
    dynamic delay measurement (flex-algo LINK_DELAY metric).

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable or disable the session reflector.
            Defaults to True.
        reflector_udp_port (int, optional): TWAMP reflector UDP port number.
            Defaults to None (uses system default 862).
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure TWAMP session reflector

    Example:
        >>> configure_twamp_session_reflector(device)
        >>> configure_twamp_session_reflector(device, reflector_udp_port=862)
    """
    ni = network_instance
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring TWAMP session-reflector admin-state {val} on {device.name} "
        f"(network-instance: {ni})"
    )

    config = [
        f'network-instance {ni}',
        f'twamp session-reflector admin-state {val}',
    ]

    if reflector_udp_port is not None:
        config.append(f'twamp session-reflector reflector-udp-port {reflector_udp_port}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure TWAMP session-reflector on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_twamp_session_reflector(device, network_instance='default'):
    """Remove TWAMP session reflector configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove TWAMP session reflector

    Example:
        >>> unconfigure_twamp_session_reflector(device)
    """
    ni = network_instance
    log.info(
        f"Removing TWAMP session-reflector from {device.name} "
        f"(network-instance: {ni})"
    )

    config = [
        f'network-instance {ni}',
        'no twamp session-reflector admin-state',
        'no twamp session-reflector reflector-udp-port',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove TWAMP session-reflector from {device.name}. "
            f"Error:\n{e}"
        )
