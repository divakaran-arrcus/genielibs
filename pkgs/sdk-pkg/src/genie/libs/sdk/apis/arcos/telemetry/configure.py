"""ArcOS Telemetry (Kafka streaming) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_CTX = 'telemetry-system'


def configure_telemetry_global(device, status='on', cuid=None):
    """Configure telemetry global settings.

    Args:
        device: Device object.
        status: 'on' or 'off' (default 'on').
        cuid: Customer unique ID (required when enabling).
    """
    log.info(f"Configuring telemetry global on {device.name}")
    config = [f'{_CTX} global status {status}']
    if cuid:
        config.append(f'{_CTX} global cuid {cuid}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Telemetry global config failed on {device.name}: {e}")


def unconfigure_telemetry_global(device):
    """Disable telemetry."""
    log.info(f"Disabling telemetry on {device.name}")
    try:
        device.configure([f'{_CTX} global status off', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Telemetry disable failed on {device.name}: {e}")


def configure_telemetry_destination_group(device, group_name, address, port,
                                            source_interface=None,
                                            network_instance=None,
                                            ssl=False):
    """Configure telemetry destination group.

    Args:
        device: Device object.
        group_name: Destination group name.
        address: Destination IP address or hostname.
        port: Destination port.
        source_interface: Optional source interface.
        network_instance: Optional VRF name.
        ssl: Enable SSL/TLS (default False).
    """
    log.info(f"Configuring telemetry destination group {group_name} on {device.name}")
    config = [
        f'{_CTX} destination-group {group_name}',
        f'destination {address} {port}',
    ]
    if source_interface:
        config.append(f'source-interface {source_interface}')
    if network_instance:
        config.append(f'network-instance {network_instance}')
    if ssl:
        config.append('ssl')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Telemetry dest group failed on {device.name}: {e}")


def unconfigure_telemetry_destination_group(device, group_name):
    """Remove telemetry destination group."""
    log.info(f"Removing telemetry destination group {group_name} from {device.name}")
    try:
        device.configure([f'no {_CTX} destination-group {group_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Telemetry dest group removal failed on {device.name}: {e}")


def configure_telemetry_subscription(device, sub_name, sensors,
                                       destination_group):
    """Configure telemetry persistent subscription.

    Args:
        device: Device object.
        sub_name: Subscription name.
        sensors: List of sensor names.
        destination_group: Destination group name.
    """
    log.info(f"Configuring telemetry subscription {sub_name} on {device.name}")
    if isinstance(sensors, (list, tuple)):
        sensor_str = ' '.join(sensors)
    else:
        sensor_str = sensors
    config = [
        f'{_CTX} persistent-subscription {sub_name}',
        f'sensors [ {sensor_str} ]',
        f'destination-group {destination_group}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Telemetry subscription failed on {device.name}: {e}")


def unconfigure_telemetry_subscription(device, sub_name):
    """Remove telemetry subscription."""
    log.info(f"Removing telemetry subscription {sub_name} from {device.name}")
    try:
        device.configure([f'no {_CTX} persistent-subscription {sub_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Telemetry subscription removal failed on {device.name}: {e}")
