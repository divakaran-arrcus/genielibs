"""ArcOS ICMP Tunneling configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_icmp_tunneling(device, enabled=True):
    """Configure MPLS ICMP tunneling.

    Args:
        device: Device object.
        enabled: Enable ICMP tunneling (default True, which is also device default).
    """
    log.info(f"Configuring ICMP tunneling on {device.name}")
    flag = 'true' if enabled else 'false'
    try:
        device.configure([
            'network-instance default',
            f'mpls global config icmp-tunnelling {flag}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"ICMP tunneling config failed on {device.name}: {e}")


def unconfigure_icmp_tunneling(device):
    """Disable ICMP tunneling (set to false)."""
    configure_icmp_tunneling(device, enabled=False)
