"""ArcOS SRv6 Mobile (MUP) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_pfcp_proxy(device, instance_id, pfcp_ip, pid,
                          smf_ip, smf_port, upf_ip, upf_port,
                          network_instance='default', passthrough=False,
                          enable_nat=False, interface=None,
                          buffer_size=None, worker=None):
    """Configure PFCP proxy instance for SRv6 Mobile.

    Args:
        device: Device object.
        instance_id: Instance ID (0-64).
        pfcp_ip: Local PFCP IP address.
        pid: Process ID (0-64).
        smf_ip: SMF IP address.
        smf_port: SMF port (not 8805).
        upf_ip: UPF IP address.
        upf_port: UPF port (not 8805).
        network_instance: Network instance (default 'default').
        passthrough: Enable passthrough mode.
        enable_nat: Enable NAT mode.
        interface: Interface for passthrough mode.
        buffer_size: Socket buffer size.
        worker: Worker thread count.
    """
    log.info(f"Configuring PFCP proxy {instance_id} on {device.name}")
    config = [f'system pfcp-proxy {instance_id}']
    config.append(f'pfcp {pfcp_ip}')
    config.append(f'pid {pid}')
    config.append(f'smf {smf_ip}')
    config.append(f'smf-port {smf_port}')
    config.append(f'upf {upf_ip}')
    config.append(f'upf-port {upf_port}')
    config.append(f'network-instance {network_instance}')
    if passthrough:
        config.append('passthrough true')
    if enable_nat:
        config.append('enable-nat true')
    if interface:
        config.append(f'interface {interface}')
    if buffer_size:
        config.append(f'buffer-size {buffer_size}')
    if worker is not None:
        config.append(f'worker {worker}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PFCP proxy failed on {device.name}: {e}")


def unconfigure_pfcp_proxy(device, instance_id):
    """Remove PFCP proxy instance."""
    log.info(f"Removing PFCP proxy {instance_id} from {device.name}")
    try:
        device.configure([f'no system pfcp-proxy {instance_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PFCP proxy removal failed on {device.name}: {e}")
