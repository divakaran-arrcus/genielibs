"""ArcOS gNMI (gRPC) server configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_CTX = 'system grpc-server'


def configure_gnmi_server(device, enabled=True, transport_security=None,
                           cert_file=None, key_file=None):
    """Configure gNMI gRPC server global settings.

    Args:
        device: Device object.
        enabled: Enable gRPC server (default True).
        transport_security: Enable TLS (bool).
        cert_file: TLS certificate file path.
        key_file: TLS key file path.
    """
    log.info(f"Configuring gNMI server on {device.name}")
    config = [_CTX]
    config.append(f'enable {"true" if enabled else "false"}')
    if transport_security is not None:
        config.append(f'transport-security {"true" if transport_security else "false"}')
    if cert_file:
        config.append(f'tls certificate-file {cert_file}')
    if key_file:
        config.append(f'tls key-file {key_file}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"gNMI server config failed on {device.name}: {e}")


def unconfigure_gnmi_server(device):
    """Disable gNMI gRPC server."""
    log.info(f"Disabling gNMI server on {device.name}")
    try:
        device.configure([_CTX, 'enable false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"gNMI server disable failed on {device.name}: {e}")


def configure_gnmi_connection(device, vrf_name, listen_addresses=None,
                               port=None, listen_interface=None):
    """Configure gNMI connection for a VRF.

    Args:
        device: Device object.
        vrf_name: VRF/network-instance name.
        listen_addresses: List of IPs or single IP to listen on.
        port: Port number.
        listen_interface: Interface name to listen on.
    """
    log.info(f"Configuring gNMI connection for {vrf_name} on {device.name}")
    config = [f'{_CTX} connections {vrf_name}']
    if listen_addresses:
        if isinstance(listen_addresses, (list, tuple)):
            addr_str = ' '.join(listen_addresses)
        else:
            addr_str = listen_addresses
        config.append(f'listen-addresses [ {addr_str} ]')
    if port is not None:
        config.append(f'port {port}')
    if listen_interface:
        config.append(f'listen-interface {listen_interface}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"gNMI connection config failed on {device.name}: {e}")


def unconfigure_gnmi_connection(device, vrf_name):
    """Remove gNMI connection for a VRF."""
    log.info(f"Removing gNMI connection for {vrf_name} from {device.name}")
    try:
        device.configure([f'no {_CTX} connections {vrf_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"gNMI connection removal failed on {device.name}: {e}")
