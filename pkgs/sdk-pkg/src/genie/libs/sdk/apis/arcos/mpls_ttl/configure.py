"""ArcOS MPLS TTL configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_mpls_ttl_propagation(device, enabled=True):
    """Configure MPLS TTL propagation.

    Args:
        device: Device object.
        enabled: Enable TTL propagation (default True).
    """
    log.info(f"Configuring MPLS TTL propagation on {device.name}")
    flag = 'true' if enabled else 'false'
    try:
        device.configure([
            'network-instance default',
            f'mpls global config ttl-propagation {flag}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"MPLS TTL propagation failed on {device.name}: {e}")


def get_mpls_ttl_propagation(device) -> bool:
    """Get MPLS TTL propagation state.

    Returns:
        True if TTL propagation is enabled, False otherwise.
    """
    try:
        output = device.execute(
            'show network-instance default mpls global state ttl-propagation '
            '| display json | nomore'
        )
        if 'true' in output.lower():
            return True
        return False
    except Exception as exc:
        log.error("Failed to get MPLS TTL propagation: %s", exc)
        return True  # default is true
