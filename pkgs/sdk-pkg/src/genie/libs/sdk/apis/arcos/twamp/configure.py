"""Common configure functions for TWAMP on ArcOS"""

import logging

from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

# arcos-twamp.yang: `range "862 | 49152..65535"` on reflector-udp-port
# (oam/twamp/ui/arcos-twamp.yang:381, grouping
# twamp-session-reflector-common). 862 is the IANA TWAMP-Control port; the
# upper band is the ephemeral range.
_REFLECTOR_PORT_DEFAULT = 862
_REFLECTOR_PORT_DYNAMIC = range(49152, 65536)


def _valid_reflector_udp_port(port: int) -> bool:
    """True when arcOS would accept this reflector-udp-port.

    Worth a guard rather than letting the device decide, because arcOS does NOT
    reject the transaction: it answers `syntax error: "<n>" is out of range.`,
    drops that one leaf, and commits the rest -- so `device.configure()` raises
    nothing and the caller is told the port was set.

    Measured on 54 archived CI builds pushing 9862: the commit came back
    `% No modifications to commit`, the port was never once configured, and the
    testcase whose entire purpose was to exercise it passed 54/54.
    """
    return port == _REFLECTOR_PORT_DEFAULT or port in _REFLECTOR_PORT_DYNAMIC


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
            Must be 862 or in 49152..65535 -- arcOS rejects anything else
            leaf-only, dropping it while still committing, so an invalid value
            would silently not apply. Defaults to None (device default 862).
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure TWAMP session reflector
        ValueError: reflector_udp_port is outside the range arcOS accepts

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
        if not _valid_reflector_udp_port(int(reflector_udp_port)):
            raise ValueError(
                f"reflector_udp_port={reflector_udp_port} is outside the range "
                f"arcOS accepts (862 | 49152..65535). Pushing it would draw "
                f"`syntax error: \"{reflector_udp_port}\" is out of range.`, "
                f"drop the leaf, and still commit clean -- so the port would "
                f"silently not be set."
            )
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
