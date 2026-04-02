"""ArcOS DHCP Relay configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_CTX = 'relay-agent dhcp'
_CTX6 = 'relay-agent dhcpv6'


def configure_dhcp_relay_helper(device, helper_addresses):
    """Configure DHCP relay global helper addresses.

    Args:
        device: Device object.
        helper_addresses: Single address string or list of addresses.
    """
    log.info(f"Configuring DHCP relay helper on {device.name}")
    if isinstance(helper_addresses, (list, tuple)):
        addr_str = ' '.join(helper_addresses)
        config = [_CTX, f'helper-address [ {addr_str} ]', '!']
    else:
        config = [_CTX, f'helper-address {helper_addresses}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCP relay helper failed on {device.name}: {e}")


def unconfigure_dhcp_relay_helper(device):
    """Remove DHCP relay global helper addresses."""
    log.info(f"Removing DHCP relay helper from {device.name}")
    try:
        device.configure([_CTX, 'no helper-address', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCP relay helper removal failed on {device.name}: {e}")


def configure_dhcp_relay_interface(device, interface, helper_addresses=None,
                                    server_vrf=None, option82=False,
                                    circuit_id=None, circuit_id_format=None):
    """Configure DHCP relay on an interface.

    Args:
        device: Device object.
        interface: Interface name (e.g., swp1, vlan100).
        helper_addresses: Optional helper address(es) to override global.
        server_vrf: Optional VRF name for relay.
        option82: Enable Option 82 (agent-information-option).
        circuit_id: Custom circuit-id string.
        circuit_id_format: HOSTNAME_PORT or PORT_VLAN.
    """
    log.info(f"Configuring DHCP relay on interface {interface} on {device.name}")
    config = [f'{_CTX} interface {interface}', 'enable true']
    if helper_addresses:
        if isinstance(helper_addresses, (list, tuple)):
            addr_str = ' '.join(helper_addresses)
            config.append(f'helper-address [ {addr_str} ]')
        else:
            config.append(f'helper-address {helper_addresses}')
    if server_vrf:
        config.append(f'server-vrf {server_vrf}')
    if option82:
        config.append('agent-information-option enable true')
    if circuit_id:
        config.append(f'agent-information-option circuit-id {circuit_id}')
    if circuit_id_format:
        config.append(f'agent-information-option circuit-id-format {circuit_id_format}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCP relay interface failed on {device.name}: {e}")


def unconfigure_dhcp_relay_interface(device, interface):
    """Remove DHCP relay from an interface."""
    log.info(f"Removing DHCP relay from interface {interface} on {device.name}")
    try:
        device.configure([f'{_CTX} interface {interface}', 'enable false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCP relay interface removal failed on {device.name}: {e}")


def configure_dhcpv6_relay_helper(device, helper_addresses):
    """Configure DHCPv6 relay global helper addresses."""
    log.info(f"Configuring DHCPv6 relay helper on {device.name}")
    if isinstance(helper_addresses, (list, tuple)):
        addr_str = ' '.join(helper_addresses)
        config = [_CTX6, f'helper-address [ {addr_str} ]', '!']
    else:
        config = [_CTX6, f'helper-address {helper_addresses}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCPv6 relay helper failed on {device.name}: {e}")


def unconfigure_dhcpv6_relay_helper(device):
    """Remove DHCPv6 relay global helper addresses."""
    log.info(f"Removing DHCPv6 relay helper from {device.name}")
    try:
        device.configure([_CTX6, 'no helper-address', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCPv6 relay helper removal failed on {device.name}: {e}")


def configure_dhcpv6_relay_interface(device, interface, helper_addresses=None,
                                      server_vrf=None, enable_interface_id=False):
    """Configure DHCPv6 relay on an interface."""
    log.info(f"Configuring DHCPv6 relay on interface {interface} on {device.name}")
    config = [f'{_CTX6} interface {interface}', 'enable true']
    if helper_addresses:
        if isinstance(helper_addresses, (list, tuple)):
            addr_str = ' '.join(helper_addresses)
            config.append(f'helper-address [ {addr_str} ]')
        else:
            config.append(f'helper-address {helper_addresses}')
    if server_vrf:
        config.append(f'server-vrf {server_vrf}')
    if enable_interface_id:
        config.append('options enable-interface-id true')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCPv6 relay interface failed on {device.name}: {e}")


def unconfigure_dhcpv6_relay_interface(device, interface):
    """Remove DHCPv6 relay from an interface."""
    log.info(f"Removing DHCPv6 relay from interface {interface} on {device.name}")
    try:
        device.configure([f'{_CTX6} interface {interface}', 'enable false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"DHCPv6 relay interface removal failed on {device.name}: {e}")
