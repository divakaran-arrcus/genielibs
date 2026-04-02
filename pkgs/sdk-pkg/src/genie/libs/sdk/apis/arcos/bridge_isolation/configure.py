"""ArcOS Bridge Isolation configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_bridge_isolation(device, interface, enabled=True):
    """Configure bridge isolation on an interface.

    Args:
        device: Device object.
        interface: Physical interface name (e.g., swp1).
        enabled: Enable bridge isolation (default True).
    """
    log.info(f"Configuring bridge isolation on {interface} on {device.name}")
    action = 'enable' if enabled else 'disable'
    config = [
        f'interface {interface}',
        f'bridge-isolation isolation {action}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Bridge isolation failed on {device.name}: {e}")


def unconfigure_bridge_isolation(device, interface):
    """Remove bridge isolation from an interface."""
    log.info(f"Removing bridge isolation from {interface} on {device.name}")
    try:
        device.configure([f'interface {interface}', 'no bridge-isolation', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Bridge isolation removal failed on {device.name}: {e}")
