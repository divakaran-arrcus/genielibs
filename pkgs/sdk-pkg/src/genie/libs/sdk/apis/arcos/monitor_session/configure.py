"""ArcOS Monitor Session (SPAN) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_monitor_session(device, name, source_interface=None,
                                source_direction=None, dest_interface=None,
                                dest_cpu=False, enabled=True):
    """Create a monitor session (port mirror / SPAN).

    Args:
        device (obj): Device object.
        name (str): Session name.
        source_interface (str, optional): Source interface name.
        source_direction (str, optional): INGRESS or EGRESS.
        dest_interface (str, optional): Destination interface.
        dest_cpu (bool, optional): Mirror to CPU.
        enabled (bool, optional): Enable the session.
    """
    log.info(f"Configuring monitor-session {name} on {device.name}")
    config = [f'monitor-session {name}']
    config.append(f'enable {"true" if enabled else "false"}')

    if source_interface and source_direction:
        config.append(f'source interface {source_interface} {source_direction}')

    if dest_interface:
        config.append(f'destination interface {dest_interface}')
    elif dest_cpu:
        config.append('destination cpu')

    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Monitor session failed on {device.name}: {e}")


def unconfigure_monitor_session(device, name):
    """Remove a monitor session."""
    log.info(f"Removing monitor-session {name} from {device.name}")
    try:
        device.configure([f'no monitor-session {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Monitor session removal failed on {device.name}: {e}")
