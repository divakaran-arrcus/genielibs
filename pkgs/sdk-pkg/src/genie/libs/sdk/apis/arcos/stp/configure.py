"""ArcOS STP configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_stp_protocol(device, protocol='RAPID_PVST'):
    """Configure STP enabled-protocol.

    Args:
        device (obj): Device object.
        protocol (str): RAPID_PVST or NONE.
    """
    log.info(f"Configuring STP protocol {protocol} on {device.name}")
    try:
        device.configure([f'stp enabled-protocol {protocol}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"STP config failed on {device.name}: {e}")


def unconfigure_stp_protocol(device):
    """Remove STP enabled-protocol configuration."""
    log.info(f"Removing STP protocol from {device.name}")
    try:
        device.configure(['no stp enabled-protocol', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"STP removal failed on {device.name}: {e}")
