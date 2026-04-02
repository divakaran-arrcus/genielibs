"""ArcOS SNMP configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_CTX = 'system snmp-server'


def configure_snmp_server(device, enabled=True, community=None,
                          listen_addresses=None, network_instance=None,
                          port=None, contact=None, location=None,
                          protocol_version=None, trap_source_ip=None):
    """Configure SNMP server global settings.

    Args:
        device: Device object.
        enabled: Enable SNMP server (default True).
        community: Community string.
        listen_addresses: List of listen addresses or single address.
        network_instance: Network instance name.
        port: SNMP port number.
        contact: Contact string.
        location: Location string.
        protocol_version: V2C or V3.
        trap_source_ip: Trap source IP address.
    """
    log.info(f"Configuring SNMP server on {device.name}")
    config = [_CTX]
    enabled_str = 'true' if enabled else 'false'
    config.append(f'enable {enabled_str}')
    if community:
        config.append(f'community {community}')
    if listen_addresses:
        if isinstance(listen_addresses, (list, tuple)):
            for addr in listen_addresses:
                config.append(f'listen-addresses {addr}')
        else:
            config.append(f'listen-addresses {listen_addresses}')
    if network_instance:
        config.append(f'network-instance {network_instance}')
    if port is not None:
        config.append(f'port {port}')
    if contact:
        config.append(f'contact {contact}')
    if location:
        config.append(f'location "{location}"')
    if protocol_version:
        config.append(f'protocol-version {protocol_version}')
    if trap_source_ip:
        config.append(f'trap-source-ip {trap_source_ip}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SNMP server config failed on {device.name}: {e}")


def unconfigure_snmp_server(device):
    """Remove SNMP server configuration."""
    log.info(f"Removing SNMP server from {device.name}")
    try:
        device.configure([_CTX, 'enable false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SNMP server removal failed on {device.name}: {e}")


def configure_snmp_target(device, name, address, port=162,
                          target_parameters=None):
    """Configure SNMP trap target."""
    log.info(f"Configuring SNMP target {name} on {device.name}")
    config = [f'{_CTX} target {name}']
    config.append(f'address {address}')
    config.append(f'port {port}')
    if target_parameters:
        config.append(f'target-parameters {target_parameters}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SNMP target config failed on {device.name}: {e}")


def unconfigure_snmp_target(device, name):
    """Remove SNMP trap target."""
    log.info(f"Removing SNMP target {name} from {device.name}")
    try:
        device.configure([f'no {_CTX} target {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SNMP target removal failed on {device.name}: {e}")


def configure_snmp_threshold_traps(device, cpu=None, memory=None):
    """Configure SNMP threshold traps for CPU and memory."""
    log.info(f"Configuring SNMP threshold traps on {device.name}")
    config = [_CTX]
    if cpu is not None:
        config.append(f'threshold-traps cpu {cpu}')
    if memory is not None:
        config.append(f'threshold-traps memory {memory}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SNMP threshold traps failed on {device.name}: {e}")


def unconfigure_snmp_threshold_traps(device):
    """Remove SNMP threshold traps."""
    log.info(f"Removing SNMP threshold traps from {device.name}")
    try:
        device.configure([_CTX, 'no threshold-traps cpu', 'no threshold-traps memory', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SNMP threshold removal failed on {device.name}: {e}")
