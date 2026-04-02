"""ArcOS Port Security configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_port_security_profile(device, name, limit,
                                     sticky=False,
                                     violation_policy='restrict'):
    """Configure a port-security profile.

    Args:
        device: Device object.
        name: Profile name.
        limit: Maximum number of learned MAC addresses.
        sticky: Add learned MACs as static FDB entries (default False).
        violation_policy: 'restrict' or 'port-shut' (default 'restrict').
    """
    log.info(f"Configuring port-security profile {name} on {device.name}")
    sticky_str = 'true' if sticky else 'false'
    config = [
        f'port-security profile {name}',
        f'limit {limit}',
        f'sticky {sticky_str}',
        f'violation-policy {violation_policy}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Port security profile failed on {device.name}: {e}")


def unconfigure_port_security_profile(device, name):
    """Remove a port-security profile."""
    log.info(f"Removing port-security profile {name} from {device.name}")
    try:
        device.configure([f'no port-security profile {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Port security profile removal failed on {device.name}: {e}")


def configure_port_security_interface(device, interface, profile,
                                       enabled=True, static_mac_list=None):
    """Configure port-security on an interface.

    Args:
        device: Device object.
        interface: Interface name.
        profile: Port-security profile name.
        enabled: Enable port security (default True).
        static_mac_list: Optional list of static MAC addresses.
    """
    log.info(f"Configuring port-security on {interface} on {device.name}")
    enabled_str = 'true' if enabled else 'false'
    config = [
        f'interface {interface}',
        f'port-security profile {profile}',
        f'enable {enabled_str}',
    ]
    if static_mac_list:
        if isinstance(static_mac_list, (list, tuple)):
            mac_str = ' '.join(static_mac_list)
        else:
            mac_str = static_mac_list
        config.append(f'static-mac-list [ {mac_str} ]')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Port security interface failed on {device.name}: {e}")


def unconfigure_port_security_interface(device, interface):
    """Remove port-security from an interface."""
    log.info(f"Removing port-security from {interface} on {device.name}")
    try:
        device.configure([
            f'interface {interface}',
            'no port-security',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Port security interface removal failed on {device.name}: {e}")
