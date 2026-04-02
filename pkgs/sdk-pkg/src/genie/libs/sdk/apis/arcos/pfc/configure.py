"""ArcOS PFC (Priority Flow Control) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_pfc_profile(device, name, tx_enable=False, rx_enable=False,
                           cable_length=None, traffic_classes=None):
    """Configure a PFC profile.

    Args:
        device: Device object.
        name: Profile name.
        tx_enable: Enable PFC Tx (default False).
        rx_enable: Enable PFC Rx (default False).
        cable_length: Cable length in meters for headroom calculation.
        traffic_classes: Dict of tc_id -> {lossless: bool, xoff: int, ...}.
    """
    log.info(f"Configuring PFC profile {name} on {device.name}")
    config = [f'hardware platform pfc profile {name}']
    if tx_enable:
        config.append('tx enable true')
    if rx_enable:
        config.append('rx enable true')
    if cable_length is not None:
        config.append(f'cable-length {cable_length}')
    if traffic_classes:
        for tc_id, tc_cfg in sorted(traffic_classes.items()):
            if tc_cfg.get('lossless'):
                config.append(f'traffic-class-{tc_id} lossless enable true')
            if 'xoff' in tc_cfg:
                config.append(f'traffic-class-{tc_id} lossless xoff {tc_cfg["xoff"]}')
            if 'xon_offset' in tc_cfg:
                config.append(f'traffic-class-{tc_id} lossless xon-offset {tc_cfg["xon_offset"]}')
            if tc_cfg.get('watchdog'):
                config.append(f'traffic-class-{tc_id} watchdog enable true')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PFC profile failed on {device.name}: {e}")


def unconfigure_pfc_profile(device, name):
    """Remove a PFC profile."""
    log.info(f"Removing PFC profile {name} from {device.name}")
    try:
        device.configure([f'no hardware platform pfc profile {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PFC profile removal failed on {device.name}: {e}")


def configure_pfc_interface(device, interface, profile):
    """Attach PFC profile to an interface."""
    log.info(f"Attaching PFC profile {profile} to {interface} on {device.name}")
    try:
        device.configure([f'interface {interface}', f'platform pfc profile {profile}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PFC interface failed on {device.name}: {e}")


def unconfigure_pfc_interface(device, interface):
    """Remove PFC profile from an interface."""
    log.info(f"Removing PFC from {interface} on {device.name}")
    try:
        device.configure([f'interface {interface}', 'no platform pfc profile', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PFC interface removal failed on {device.name}: {e}")
