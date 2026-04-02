"""ArcOS IPFIX configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_ipfix_observation_point(device, name, domain_id,
                                       selection_process, interfaces):
    """Configure IPFIX observation point.

    Args:
        device: Device object.
        name: Observation point name.
        domain_id: Observation domain ID.
        selection_process: Selection process name.
        interfaces: List of interface names or single interface.
    """
    log.info(f"Configuring IPFIX observation point {name} on {device.name}")
    if isinstance(interfaces, (list, tuple)):
        intf_str = ' '.join(interfaces)
    else:
        intf_str = interfaces
    config = [
        f'ipfix observationPoint {name}',
        f'observationDomainId {domain_id}',
        f'selectionProcess [ {selection_process} ]',
        f'interface [ {intf_str} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPFIX observation point failed on {device.name}: {e}")


def unconfigure_ipfix_observation_point(device, name):
    """Remove IPFIX observation point."""
    log.info(f"Removing IPFIX observation point {name} from {device.name}")
    try:
        device.configure([f'no ipfix observationPoint {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPFIX observation point removal failed on {device.name}: {e}")


def configure_ipfix_selection_process(device, name, sample_afi,
                                       selector_name, packet_space):
    """Configure IPFIX selection process.

    Args:
        device: Device object.
        name: Selection process name.
        sample_afi: List of AFIs (e.g., ['IPv4', 'IPv6']).
        selector_name: Selector name.
        packet_space: Gap between consecutive samples.
    """
    log.info(f"Configuring IPFIX selection process {name} on {device.name}")
    if isinstance(sample_afi, (list, tuple)):
        afi_str = ' '.join(sample_afi)
    else:
        afi_str = sample_afi
    config = [
        f'ipfix selectionProcess {name}',
        f'sample-afi [ {afi_str} ]',
        f'selector {selector_name}',
        f'sampCountBased packetSpace {packet_space}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPFIX selection process failed on {device.name}: {e}")


def unconfigure_ipfix_selection_process(device, name):
    """Remove IPFIX selection process."""
    log.info(f"Removing IPFIX selection process {name} from {device.name}")
    try:
        device.configure([f'no ipfix selectionProcess {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPFIX selection process removal failed on {device.name}: {e}")


def configure_ipfix_exporting_process(device, name, dest_name,
                                       dest_port, source_ip, dest_ip):
    """Configure IPFIX exporting process.

    Args:
        device: Device object.
        name: Exporting process name.
        dest_name: Destination name.
        dest_port: UDP destination port.
        source_ip: Source IP address.
        dest_ip: Destination IP address.
    """
    log.info(f"Configuring IPFIX exporting process {name} on {device.name}")
    config = [
        f'ipfix exportingProcess {name}',
        f'destination {dest_name}',
        f'udpExporter destinationPort {dest_port}',
        f'udpExporter sourceIPAddress {source_ip}',
        f'udpExporter destinationIPAddress {dest_ip}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPFIX exporting process failed on {device.name}: {e}")


def unconfigure_ipfix_exporting_process(device, name):
    """Remove IPFIX exporting process."""
    log.info(f"Removing IPFIX exporting process {name} from {device.name}")
    try:
        device.configure([f'no ipfix exportingProcess {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPFIX exporting process removal failed on {device.name}: {e}")
