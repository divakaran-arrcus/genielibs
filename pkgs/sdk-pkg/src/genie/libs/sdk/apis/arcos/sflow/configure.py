"""ArcOS sFlow configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_sflow_global(device, counter_interval=None, sampling_rate=None,
                            network_instance=None, collector_ipv4=None,
                            collector_port=None, agent_interface=None):
    """Configure sFlow global settings.

    Args:
        device (obj): Device object.
        counter_interval (int, optional): Counter sampling interval (10-300).
        sampling_rate (int, optional): Packet sampling rate.
        network_instance (str, optional): Network instance name.
        collector_ipv4 (str, optional): IPv4 collector address.
        collector_port (int, optional): Collector port.
        agent_interface (str, optional): Agent IP interface.
    """
    log.info(f"Configuring sFlow global on {device.name}")
    config = []
    if counter_interval is not None:
        config.append(f'sflow global counter-sampling-interval {counter_interval}')
    if sampling_rate is not None:
        config.append(f'sflow global packet-sampling-rate {sampling_rate}')
    if network_instance is not None:
        config.append(f'sflow global network-instance {network_instance}')
    if collector_ipv4 is not None:
        cmd = f'sflow global ipv4 collector {collector_ipv4}'
        if collector_port is not None:
            cmd += f' port {collector_port}'
        config.append(cmd)
    if agent_interface is not None:
        config.append(f'sflow global agent-ip-interface {agent_interface}')
    if config:
        config.append('!')
        try:
            device.configure(config)
        except SubCommandFailure as e:
            raise SubCommandFailure(f"sFlow global config failed on {device.name}: {e}")


def unconfigure_sflow_global(device):
    """Remove all sFlow global configuration."""
    log.info(f"Removing sFlow global config from {device.name}")
    config = [
        'no sflow global counter-sampling-interval',
        'no sflow global packet-sampling-rate',
        'no sflow global network-instance',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"sFlow global removal failed on {device.name}: {e}")


def configure_sflow_interface(device, interface, direction='ingress',
                               sampling_rate=None):
    """Enable sFlow on an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        direction (str): ingress, egress, or egress-access-port.
        sampling_rate (int, optional): Per-interface sampling rate.
    """
    log.info(f"Configuring sFlow on {interface} {direction} on {device.name}")
    cmd = f'sflow interface {interface} {direction}'
    if sampling_rate is not None:
        cmd += f' packet-sampling-rate {sampling_rate}'
    try:
        device.configure([cmd, '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"sFlow interface config failed on {device.name}: {e}")


def unconfigure_sflow_interface(device, interface, direction='ingress'):
    """Remove sFlow from an interface."""
    log.info(f"Removing sFlow from {interface} {direction} on {device.name}")
    try:
        device.configure([f'no sflow interface {interface} {direction}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"sFlow interface removal failed on {device.name}: {e}")
