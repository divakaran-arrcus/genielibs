"""Common configure functions for ArcOS interfaces.

This module provides high-level helper APIs to configure
interfaces on ArcOS devices using pyATS/Genie devices and Unicon.

APIs:
- shut_interface(device, interface)
- unshut_interface(device, interface)
- configure_interface_mtu(device, interface, mtu)
- unconfigure_interface_mtu(device, interface)
- configure_interface_description(device, interface, description)
- unconfigure_interface_description(device, interface)
- configure_interface_port_speed(device, interface, speed)
- unconfigure_interface_port_speed(device, interface)
- configure_interface_aggregate_id(device, interface, aggregate_id)
- unconfigure_interface_aggregate_id(device, interface)
- configure_interface_lag(device, interface, lag_type, min_links)
- unconfigure_interface_lag(device, interface)
- configure_interface_subinterface_ipv4(device, interface, sub_id, ipv4_addr, prefix_length)
- unconfigure_interface_subinterface_ipv4(device, interface, sub_id, ipv4_addr)
- configure_interface_subinterface_ipv6(device, interface, sub_id, ipv6_addr, prefix_length)
- unconfigure_interface_subinterface_ipv6(device, interface, sub_id, ipv6_addr)
- configure_interface_subinterface_vlan(device, interface, sub_id, vlan_id, match_type)
- unconfigure_interface_subinterface_vlan(device, interface, sub_id)
- configure_interface_debounce(device, interface, up, down)
- unconfigure_interface_debounce(device, interface)
- configure_interface_bfd_micro(device, interface, remote_ipv4, remote_ipv6, enabled)
- unconfigure_interface_bfd_micro(device, interface)
- configure_interface_type(device, interface, intf_type)
- unconfigure_interface_type(device, interface)
"""

import logging

from unicon.core.errors import SubCommandFailure
from genie.harness.utils import connect_device


log = logging.getLogger(__name__)


def shut_interface(device, interface):
    """Shut (administratively disable) an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface: Interface name, e.g. "swp1", "Ethernet1/1".

    Raises:
        SubCommandFailure: If the configuration fails.
    """

    if not device.is_connected():
        connect_device(device=device)

    log.info("Shutting interface %s on device %s", interface, device.name)

    try:
        device.configure([
            f"interface {interface}",
            "enabled false",
        ])
    except SubCommandFailure as e:
        msg = (
            "Could not shut interface {intf} on device {dev}. Error:\n{error}".format(
                intf=interface,
                dev=device.name,
                error=e,
            )
        )
        log.error(msg)
        raise SubCommandFailure(msg)


def unshut_interface(device, interface):
    """Unshut (administratively enable) an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface: Interface name, e.g. "swp1", "Ethernet1/1".

    Raises:
        SubCommandFailure: If the configuration fails.
    """

    if not device.is_connected():
        connect_device(device=device)

    log.info("Unshutting interface %s on device %s", interface, device.name)

    try:
        device.configure([
            f"interface {interface}",
            "enabled true",
        ])
    except SubCommandFailure as e:
        msg = (
            "Could not unshut interface {intf} on device {dev}. Error:\n{error}".format(
                intf=interface,
                dev=device.name,
                error=e,
            )
        )
        log.error(msg)
        raise SubCommandFailure(msg)


def configure_interface_mtu(device, interface, mtu):
    """Configure MTU on an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "swp1", "ethernet-1/1".
        mtu (int): MTU value to set.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_mtu(device, 'ethernet-1/1', 9000)
    """
    log.info("Configuring MTU %s on interface %s on device %s",
             mtu, interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'mtu {mtu}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure MTU on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_mtu(device, interface):
    """Remove MTU configuration from an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "swp1", "ethernet-1/1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_mtu(device, 'ethernet-1/1')
    """
    log.info("Removing MTU configuration on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no mtu',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove MTU on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def configure_interface_description(device, interface, description):
    """Configure description on an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "swp1", "ethernet-1/1".
        description (str): Description string to set.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_description(device, 'ethernet-1/1', 'Uplink to spine')
    """
    log.info("Configuring description on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'description "{description}"',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure description on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_description(device, interface):
    """Remove description from an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "swp1", "ethernet-1/1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_description(device, 'ethernet-1/1')
    """
    log.info("Removing description on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no description',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove description on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def configure_interface_port_speed(device, interface, speed):
    """Configure ethernet port speed on an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        speed (str): Port speed value, e.g. "SPEED_10G", "SPEED_100G".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_port_speed(device, 'ethernet-1/1', 'SPEED_10G')
    """
    log.info("Configuring port speed %s on interface %s on device %s",
             speed, interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'ethernet port-speed {speed}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure port speed on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_port_speed(device, interface):
    """Remove ethernet port speed configuration from an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_port_speed(device, 'ethernet-1/1')
    """
    log.info("Removing port speed on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no ethernet port-speed',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove port speed on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def configure_interface_aggregate_id(device, interface, aggregate_id):
    """Configure ethernet aggregate-id on an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        aggregate_id (str): Aggregate interface ID, e.g. "ae1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_aggregate_id(device, 'ethernet-1/1', 'ae1')
    """
    log.info("Configuring aggregate-id %s on interface %s on device %s",
             aggregate_id, interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'ethernet aggregate-id {aggregate_id}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure aggregate-id on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_aggregate_id(device, interface):
    """Remove ethernet aggregate-id from an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_aggregate_id(device, 'ethernet-1/1')
    """
    log.info("Removing aggregate-id on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no ethernet aggregate-id',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove aggregate-id on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def configure_interface_lag(device, interface, lag_type='LACP', min_links=None):
    """Configure LAG (aggregation) on an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ae1".
        lag_type (str): LAG type, e.g. "LACP", "STATIC". Defaults to "LACP".
        min_links (int, optional): Minimum number of active links. Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_lag(device, 'ae1', lag_type='LACP', min_links=2)
    """
    log.info("Configuring LAG on interface %s on device %s",
             interface, device.name)
    config = [
        f'interface {interface}',
        f'aggregation lag-type {lag_type}',
    ]
    if min_links is not None:
        config.append(f'aggregation min-links {min_links}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LAG on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_lag(device, interface):
    """Remove LAG (aggregation) configuration from an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ae1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_lag(device, 'ae1')
    """
    log.info("Removing LAG configuration on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no aggregation lag-type',
            'no aggregation min-links',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LAG configuration on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def configure_interface_subinterface_ipv4(device, interface, sub_id, ipv4_addr,
                                          prefix_length=24):
    """Configure IPv4 address on a subinterface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        sub_id (int): Subinterface index.
        ipv4_addr (str): IPv4 address, e.g. "10.0.0.1".
        prefix_length (int): Prefix length. Defaults to 24.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_subinterface_ipv4(device, 'ethernet-1/1', 0, '10.0.0.1', 24)
    """
    log.info("Configuring IPv4 %s/%s on interface %s subinterface %s on device %s",
             ipv4_addr, prefix_length, interface, sub_id, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'subinterface {sub_id}',
            f'ipv4 address {ipv4_addr}',
            f'prefix-length {prefix_length}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv4 on interface {interface} "
            f"subinterface {sub_id} on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_subinterface_ipv4(device, interface, sub_id, ipv4_addr):
    """Remove IPv4 address from a subinterface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        sub_id (int): Subinterface index.
        ipv4_addr (str): IPv4 address to remove.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_subinterface_ipv4(device, 'ethernet-1/1', 0, '10.0.0.1')
    """
    log.info("Removing IPv4 %s on interface %s subinterface %s on device %s",
             ipv4_addr, interface, sub_id, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'subinterface {sub_id}',
            f'no ipv4 address {ipv4_addr}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv4 on interface {interface} "
            f"subinterface {sub_id} on device {device.name}. Error:\n{e}"
        )


def configure_interface_subinterface_ipv6(device, interface, sub_id, ipv6_addr,
                                          prefix_length=64):
    """Configure IPv6 address on a subinterface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        sub_id (int): Subinterface index.
        ipv6_addr (str): IPv6 address, e.g. "2001:db8::1".
        prefix_length (int): Prefix length. Defaults to 64.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_subinterface_ipv6(device, 'ethernet-1/1', 0, '2001:db8::1', 64)
    """
    log.info("Configuring IPv6 %s/%s on interface %s subinterface %s on device %s",
             ipv6_addr, prefix_length, interface, sub_id, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'subinterface {sub_id}',
            f'ipv6 address {ipv6_addr}',
            f'prefix-length {prefix_length}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv6 on interface {interface} "
            f"subinterface {sub_id} on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_subinterface_ipv6(device, interface, sub_id, ipv6_addr):
    """Remove IPv6 address from a subinterface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        sub_id (int): Subinterface index.
        ipv6_addr (str): IPv6 address to remove.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_subinterface_ipv6(device, 'ethernet-1/1', 0, '2001:db8::1')
    """
    log.info("Removing IPv6 %s on interface %s subinterface %s on device %s",
             ipv6_addr, interface, sub_id, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'subinterface {sub_id}',
            f'no ipv6 address {ipv6_addr}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv6 on interface {interface} "
            f"subinterface {sub_id} on device {device.name}. Error:\n{e}"
        )


def configure_interface_subinterface_vlan(device, interface, sub_id, vlan_id,
                                          match_type='single-tagged'):
    """Configure VLAN on a subinterface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        sub_id (int): Subinterface index.
        vlan_id (int): VLAN ID.
        match_type (str): VLAN match type. Defaults to "single-tagged".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_subinterface_vlan(device, 'ethernet-1/1', 100, 100)
    """
    log.info("Configuring VLAN %s on interface %s subinterface %s on device %s",
             vlan_id, interface, sub_id, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'subinterface {sub_id}',
            f'vlan match {match_type} vlan-id {vlan_id}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure VLAN on interface {interface} "
            f"subinterface {sub_id} on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_subinterface_vlan(device, interface, sub_id):
    """Remove VLAN configuration from a subinterface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        sub_id (int): Subinterface index.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_subinterface_vlan(device, 'ethernet-1/1', 100)
    """
    log.info("Removing VLAN on interface %s subinterface %s on device %s",
             interface, sub_id, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'subinterface {sub_id}',
            'no vlan',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove VLAN on interface {interface} "
            f"subinterface {sub_id} on device {device.name}. Error:\n{e}"
        )


def configure_interface_debounce(device, interface, up=None, down=None):
    """Configure debounce interval on an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        up (int, optional): Debounce up interval in milliseconds. Defaults to None.
        down (int, optional): Debounce down interval in milliseconds. Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_debounce(device, 'ethernet-1/1', up=3000, down=1000)
    """
    log.info("Configuring debounce on interface %s on device %s",
             interface, device.name)
    config = [f'interface {interface}']
    if up is not None:
        config.append(f'debounce-interval up {up}')
    if down is not None:
        config.append(f'debounce-interval down {down}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure debounce on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_debounce(device, interface):
    """Remove debounce interval configuration from an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_debounce(device, 'ethernet-1/1')
    """
    log.info("Removing debounce on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no debounce-interval up',
            'no debounce-interval down',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove debounce on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def configure_interface_bfd_micro(device, interface, remote_ipv4=None,
                                  remote_ipv6=None, enabled=True):
    """Configure BFD micro on an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        remote_ipv4 (str, optional): Remote IPv4 address for BFD micro.
            Defaults to None.
        remote_ipv6 (str, optional): Remote IPv6 address for BFD micro.
            Defaults to None.
        enabled (bool): Whether BFD micro is enabled. Defaults to True.

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_bfd_micro(device, 'ethernet-1/1',
        ...                               remote_ipv4='10.0.0.2', enabled=True)
    """
    log.info("Configuring BFD micro on interface %s on device %s",
             interface, device.name)
    config = [f'interface {interface}']
    if remote_ipv4 is not None:
        config.append(f'bfd micro remote-address ipv4 {remote_ipv4}')
    if remote_ipv6 is not None:
        config.append(f'bfd micro remote-address ipv6 {remote_ipv6}')
    config.append(f'bfd micro enabled {"true" if enabled else "false"}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD micro on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_bfd_micro(device, interface):
    """Remove BFD micro configuration from an interface on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_bfd_micro(device, 'ethernet-1/1')
    """
    log.info("Removing BFD micro on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no bfd micro',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD micro on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def configure_interface_type(device, interface, intf_type):
    """Configure interface type on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".
        intf_type (str): Interface type, e.g. "IF_ETHERNET", "IF_AGGREGATE".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> configure_interface_type(device, 'ethernet-1/1', 'IF_ETHERNET')
    """
    log.info("Configuring type %s on interface %s on device %s",
             intf_type, interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            f'type {intf_type}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure type on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


def unconfigure_interface_type(device, interface):
    """Remove interface type configuration on ArcOS.

    Args:
        device: pyATS/Genie device object.
        interface (str): Interface name, e.g. "ethernet-1/1".

    Returns:
        None

    Raises:
        SubCommandFailure: If the configuration fails.

    Example:
        >>> unconfigure_interface_type(device, 'ethernet-1/1')
    """
    log.info("Removing type on interface %s on device %s",
             interface, device.name)
    try:
        device.configure([
            f'interface {interface}',
            'no type',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove type on interface {interface} "
            f"on device {device.name}. Error:\n{e}"
        )


# =====================================================================
# VLAN Double-Tagged
# =====================================================================


def configure_interface_subinterface_vlan_double_tagged(
    device, interface, sub_id, inner_id, outer_id
):
    """Configure double-tagged VLAN match on a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp5').
        sub_id (int): Subinterface ID.
        inner_id (int): Inner VLAN ID.
        outer_id (int): Outer VLAN ID.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_interface_subinterface_vlan_double_tagged(
        ...     device, 'swp5', 5001, 50, 101)
    """

    log.info(
        "Configuring double-tagged VLAN (inner=%s, outer=%s) on "
        "%s.%s on %s", inner_id, outer_id, interface, sub_id, device.name
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'vlan match double-tagged inner-vlan-id {inner_id} '
        f'outer-vlan-id {outer_id}',
        '!',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure double-tagged VLAN on {interface}.{sub_id} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_interface_subinterface_vlan_double_tagged(
    device, interface, sub_id
):
    """Remove double-tagged VLAN match from a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface ID.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> unconfigure_interface_subinterface_vlan_double_tagged(
        ...     device, 'swp5', 5001)
    """

    log.info(
        "Removing double-tagged VLAN from %s.%s on %s",
        interface, sub_id, device.name,
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        'no vlan match double-tagged',
        '!',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove double-tagged VLAN from {interface}.{sub_id} "
            f"on {device.name}. Error:\n{e}"
        )


# =====================================================================
# VLAN Ingress/Egress Mapping
# =====================================================================


def configure_interface_subinterface_vlan_ingress_mapping(
    device, interface, sub_id, action
):
    """Configure VLAN ingress mapping on a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface ID.
        action (str): Stack action — POP or POP-POP.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_interface_subinterface_vlan_ingress_mapping(
        ...     device, 'swp5', 5001, 'POP')
    """

    log.info(
        "Configuring VLAN ingress-mapping %s on %s.%s on %s",
        action, interface, sub_id, device.name,
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'vlan ingress-mapping vlan-stack-action {action}',
        '!',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure VLAN ingress-mapping on "
            f"{interface}.{sub_id} on {device.name}. Error:\n{e}"
        )


def unconfigure_interface_subinterface_vlan_ingress_mapping(
    device, interface, sub_id
):
    """Remove VLAN ingress mapping from a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface ID.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """

    log.info(
        "Removing VLAN ingress-mapping from %s.%s on %s",
        interface, sub_id, device.name,
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        'no vlan ingress-mapping',
        '!',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove VLAN ingress-mapping from "
            f"{interface}.{sub_id} on {device.name}. Error:\n{e}"
        )


def configure_interface_subinterface_vlan_egress_mapping(
    device, interface, sub_id, action, vlan_id=None, inner_vlan_id=None
):
    """Configure VLAN egress mapping on a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface ID.
        action (str): Stack action — PUSH, PUSH-PUSH, SWAP, SWAP-SWAP.
        vlan_id (int, optional): Outer VLAN ID for PUSH/SWAP.
        inner_vlan_id (int, optional): Inner VLAN ID for PUSH-PUSH/SWAP-SWAP.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_interface_subinterface_vlan_egress_mapping(
        ...     device, 'swp5', 5001, 'PUSH-PUSH',
        ...     vlan_id=101, inner_vlan_id=50)
    """

    log.info(
        "Configuring VLAN egress-mapping %s on %s.%s on %s",
        action, interface, sub_id, device.name,
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'vlan egress-mapping vlan-stack-action {action}',
    ]

    if vlan_id is not None:
        config.append(f'vlan egress-mapping vlan-id {vlan_id}')

    if inner_vlan_id is not None:
        config.append(f'vlan egress-mapping inner-vlan-id {inner_vlan_id}')

    config.extend(['!', '!'])

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure VLAN egress-mapping on "
            f"{interface}.{sub_id} on {device.name}. Error:\n{e}"
        )


def unconfigure_interface_subinterface_vlan_egress_mapping(
    device, interface, sub_id
):
    """Remove VLAN egress mapping from a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface ID.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """

    log.info(
        "Removing VLAN egress-mapping from %s.%s on %s",
        interface, sub_id, device.name,
    )

    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        'no vlan egress-mapping',
        '!',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove VLAN egress-mapping from "
            f"{interface}.{sub_id} on {device.name}. Error:\n{e}"
        )


# =====================================================================
# QoS Service-Policy Binding on Interface
# =====================================================================


def configure_interface_qos_service_policy(
    device, interface, direction, policy_name
):
    """Attach a QoS service-policy to an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        direction (str): INGRESS or EGRESS.
        policy_name (str): QoS policy name.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_interface_qos_service_policy(
        ...     device, 'swp1', 'INGRESS', 'ingress-pol')
    """

    log.info(
        "Attaching QoS service-policy %s %s to %s on %s",
        direction, policy_name, interface, device.name,
    )

    config = [
        f'interface {interface}',
        f'qos service-policy {direction} name {policy_name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not attach QoS service-policy to {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_interface_qos_service_policy(
    device, interface, direction
):
    """Remove QoS service-policy from an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        direction (str): INGRESS or EGRESS.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """

    log.info(
        "Removing QoS service-policy %s from %s on %s",
        direction, interface, device.name,
    )

    config = [
        f'interface {interface}',
        f'no qos service-policy {direction}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove QoS service-policy from {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# =====================================================================
# ACL Binding on Interface
# =====================================================================


def configure_interface_acl_binding(
    device, interface, acl_type, acl_name, target_attr='ACL_INTF'
):
    """Attach an ACL to an interface (ingress).

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        acl_type (str): ACL type — ACL_IPV4, ACL_IPV6, ACL_L2.
        acl_name (str): ACL set name.
        target_attr (str, optional): Target attribute. Defaults to 'ACL_INTF'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_interface_acl_binding(
        ...     device, 'swp1', 'ACL_IPV4', 'v4-acl')
    """

    log.info(
        "Attaching ACL %s/%s to %s on %s",
        acl_type, acl_name, interface, device.name,
    )

    config = [
        f'interface {interface}',
        f'acl-service-policies ingress-acl-sets {target_attr} '
        f'acl-set {acl_type} set-name {acl_name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not attach ACL to {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_interface_acl_binding(device, interface):
    """Remove ACL binding from an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """

    log.info(
        "Removing ACL binding from %s on %s",
        interface, device.name,
    )

    config = [
        f'interface {interface}',
        'no acl-service-policies ingress-acl-sets',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ACL from {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def configure_interface_priority_vlan(device, interface, sub_id=0):
    """Configure priority-vlan on a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface index (default 0).

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        "Configuring priority-vlan on %s subinterface %s on %s",
        interface, sub_id, device.name,
    )
    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        'priority-vlan true',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure priority-vlan on {interface} "
            f"sub {sub_id} on {device.name}. Error:\n{e}"
        )


def unconfigure_interface_priority_vlan(device, interface, sub_id=0):
    """Remove priority-vlan from a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface index (default 0).

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        "Removing priority-vlan from %s subinterface %s on %s",
        interface, sub_id, device.name,
    )
    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        'no priority-vlan',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove priority-vlan from {interface} "
            f"sub {sub_id} on {device.name}. Error:\n{e}"
        )


def configure_interface_subinterface_ipv4_enabled(device, interface,
                                                   sub_id=0, enabled=True):
    """Configure IPv4 enabled flag on a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface index (default 0).
        enabled (bool): IPv4 enabled (default True).

    Raises:
        SubCommandFailure: If configuration fails.
    """
    flag = 'true' if enabled else 'false'
    log.info(
        "Setting ipv4 enabled=%s on %s sub %s on %s",
        flag, interface, sub_id, device.name,
    )
    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'ipv4 enabled {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not set ipv4 enabled on {interface} "
            f"sub {sub_id} on {device.name}. Error:\n{e}"
        )


def configure_interface_subinterface_ipv6_enabled(device, interface,
                                                   sub_id=0, enabled=True):
    """Configure IPv6 enabled flag on a subinterface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        sub_id (int): Subinterface index (default 0).
        enabled (bool): IPv6 enabled (default True).

    Raises:
        SubCommandFailure: If configuration fails.
    """
    flag = 'true' if enabled else 'false'
    log.info(
        "Setting ipv6 enabled=%s on %s sub %s on %s",
        flag, interface, sub_id, device.name,
    )
    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'ipv6 enabled {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not set ipv6 enabled on {interface} "
            f"sub {sub_id} on {device.name}. Error:\n{e}"
        )
