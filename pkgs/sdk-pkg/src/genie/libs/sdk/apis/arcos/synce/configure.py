"""ArcOS SyncE configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_synce_global(device, enabled=True, holdover=None,
                            quality_level_enabled=None,
                            revertive_enabled=None,
                            network_option=None):
    """Configure SyncE global settings.

    Args:
        device: Device object.
        enabled: Enable SyncE globally (default True).
        holdover: Holdover duration in seconds.
        quality_level_enabled: Enable quality level tracking.
        revertive_enabled: Enable revertive switching.
        network_option: 'option-1' or 'option-2'.
    """
    log.info(f"Configuring SyncE global on {device.name}")
    config = ['sync-e']
    config.append(f'enabled {"true" if enabled else "false"}')
    if holdover is not None:
        config.append(f'holdover {holdover}')
    if quality_level_enabled is not None:
        config.append(f'quality-level-enabled {"true" if quality_level_enabled else "false"}')
    if revertive_enabled is not None:
        config.append(f'revertive-enabled {"true" if revertive_enabled else "false"}')
    if network_option:
        config.append(f'synchronization-network-option {network_option}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SyncE global config failed on {device.name}: {e}")


def unconfigure_synce_global(device):
    """Disable SyncE globally."""
    log.info(f"Disabling SyncE on {device.name}")
    try:
        device.configure(['sync-e', 'enabled false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SyncE disable failed on {device.name}: {e}")


def configure_synce_interface(device, interface, enabled=True,
                               priority=None, quality_level=None):
    """Configure SyncE on an interface.

    Args:
        device: Device object.
        interface: Interface name.
        enabled: Enable SyncE on interface.
        priority: Input source priority.
        quality_level: QL_PRC, QL_SSU_A, QL_SSU_B, QL_EEC1, QL_EEC2, QL_DNU.
    """
    log.info(f"Configuring SyncE on {interface} on {device.name}")
    config = [f'interface {interface}', 'sync-e']
    config.append(f'enabled {"true" if enabled else "false"}')
    if priority is not None:
        config.append(f'input-source-priority {priority}')
    if quality_level:
        config.append(f'quality-level {quality_level}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SyncE interface failed on {device.name}: {e}")


def unconfigure_synce_interface(device, interface):
    """Disable SyncE on an interface."""
    log.info(f"Disabling SyncE on {interface} on {device.name}")
    try:
        device.configure([f'interface {interface}', 'sync-e', 'enabled false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SyncE interface disable failed on {device.name}: {e}")
