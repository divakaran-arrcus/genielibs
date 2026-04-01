"""ArcOS VRRP configure APIs.

VRRP is configured under interface address context:
    interface <intf> subinterface <sub> ipv4 address <ip>
     prefix-length <len>
     vrrp vrrp-group <vrid>
      virtual-address [ <vip1> <vip2> ]
      priority <0-255>
      ...
"""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_vrrp_group(device, interface, sub_id, af, address,
                          prefix_length, vrid, virtual_addresses=None,
                          priority=None, advertisement_interval=None,
                          accept_mode=None, vrrp_version=None,
                          virtual_link_local=None):
    """Configure a VRRP group on an interface address.

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp10').
        sub_id (int): Subinterface ID (e.g., 0).
        af (str): Address family — 'ipv4' or 'ipv6'.
        address (str): Interface IP address.
        prefix_length (int): Prefix length (mandatory).
        vrid (int): Virtual router ID (1-255).
        virtual_addresses (list, optional): Virtual IP addresses.
        priority (int, optional): VRRP priority (1-254).
        advertisement_interval (int, optional): Interval in centiseconds.
        accept_mode (bool, optional): Accept mode.
        vrrp_version (str, optional): VRRP_V2, VRRP_V3, VRRP_V2_V3.
        virtual_link_local (str, optional): IPv6 link-local address.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure VRRP group.

    Example:
        >>> configure_vrrp_group(device, 'swp10', 0, 'ipv4',
        ...     '172.16.1.1', 24, 10,
        ...     virtual_addresses=['172.16.1.100'],
        ...     priority=200)
    """

    log.info(
        f"Configuring VRRP group {vrid} on {interface} "
        f"{af} {address}/{prefix_length} on {device.name}"
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'{af} address {address}',
        f'prefix-length {prefix_length}',
        f'vrrp vrrp-group {vrid}',
    ]

    if virtual_addresses:
        if isinstance(virtual_addresses, (list, tuple)):
            vips = ' '.join(str(v) for v in virtual_addresses)
        else:
            vips = str(virtual_addresses)
        config.append(f'virtual-address [ {vips} ]')

    if priority is not None:
        config.append(f'priority {priority}')

    if advertisement_interval is not None:
        config.append(f'advertisement-interval {advertisement_interval}')

    if accept_mode is not None:
        config.append(f'accept-mode {"true" if accept_mode else "false"}')

    if vrrp_version is not None:
        config.append(f'vrrp-version {vrrp_version}')

    if virtual_link_local is not None:
        config.append(f'virtual-link-local {virtual_link_local}')

    config.extend(['!', '!', '!', '!'])

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure VRRP group {vrid} on {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_vrrp_group(device, interface, sub_id, af, address, vrid):
    """Remove a VRRP group from an interface address.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface ID.
        af (str): Address family.
        address (str): Interface IP address.
        vrid (int): Virtual router ID.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove VRRP group.

    Example:
        >>> unconfigure_vrrp_group(device, 'swp10', 0, 'ipv4',
        ...     '172.16.1.1', 10)
    """

    log.info(
        f"Removing VRRP group {vrid} from {interface} "
        f"{af} {address} on {device.name}"
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'{af} address {address}',
        f'no vrrp vrrp-group {vrid}',
        '!', '!', '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove VRRP group {vrid} from {interface} "
            f"on {device.name}. Error:\n{e}"
        )
