"""ArcOS Storm Control configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_storm_control(device, interface, broadcast_level=None,
                             multicast_level=None, unknown_unicast_level=None,
                             broadcast_kbps=None, multicast_kbps=None,
                             unknown_unicast_kbps=None):
    """Configure storm control on an interface.

    Args:
        device: Device object.
        interface: Interface name.
        broadcast_level: Broadcast rate limit as percentage (0.01-99.99).
        multicast_level: Multicast rate limit as percentage.
        unknown_unicast_level: Unknown unicast rate limit as percentage.
        broadcast_kbps: Broadcast rate limit in kbps.
        multicast_kbps: Multicast rate limit in kbps.
        unknown_unicast_kbps: Unknown unicast rate limit in kbps.
    """
    log.info(f"Configuring storm control on {interface} on {device.name}")
    config = [f'interface {interface}']
    if broadcast_level is not None:
        config.append(f'storm-control broadcast-level {broadcast_level}')
    if multicast_level is not None:
        config.append(f'storm-control multicast-level {multicast_level}')
    if unknown_unicast_level is not None:
        config.append(f'storm-control unknown-unicast-level {unknown_unicast_level}')
    if broadcast_kbps is not None:
        config.append(f'storm-control broadcast-kbps {broadcast_kbps}')
    if multicast_kbps is not None:
        config.append(f'storm-control multicast-kbps {multicast_kbps}')
    if unknown_unicast_kbps is not None:
        config.append(f'storm-control unknown-unicast-kbps {unknown_unicast_kbps}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Storm control failed on {device.name}: {e}")


def unconfigure_storm_control(device, interface):
    """Remove all storm control from an interface."""
    log.info(f"Removing storm control from {interface} on {device.name}")
    try:
        device.configure([f'interface {interface}', 'no storm-control', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Storm control removal failed on {device.name}: {e}")
