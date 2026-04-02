"""ArcOS Interface Damping configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_interface_damping(device, interface, max_suppress_time=20000,
                                 decay_half_life=5000, suppress_threshold=5000,
                                 reuse_threshold=2000, flap_penalty=1000):
    """Configure interface damping.

    Args:
        device: Device object.
        interface: Interface name.
        max_suppress_time: Max suppress time in ms (default 20000).
        decay_half_life: Decay half-life in ms (default 5000).
        suppress_threshold: Suppress threshold in ms (default 5000).
        reuse_threshold: Reuse threshold in ms (default 2000).
        flap_penalty: Flap penalty in ms (default 1000).
    """
    log.info(f"Configuring damping on {interface} on {device.name}")
    config = [
        f'interface {interface}',
        'damping enabled true',
        f'damping max-suppress-time {max_suppress_time}',
        f'damping decay-half-life {decay_half_life}',
        f'damping suppress-threshold {suppress_threshold}',
        f'damping reuse-threshold {reuse_threshold}',
        f'damping flap-penalty {flap_penalty}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Damping config failed on {device.name}: {e}")


def unconfigure_interface_damping(device, interface):
    """Remove interface damping."""
    log.info(f"Removing damping from {interface} on {device.name}")
    try:
        device.configure([f'interface {interface}', 'damping enabled false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Damping removal failed on {device.name}: {e}")
