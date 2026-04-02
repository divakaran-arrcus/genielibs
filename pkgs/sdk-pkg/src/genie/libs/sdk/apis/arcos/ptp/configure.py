"""ArcOS PTP configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_ptp_instance(device, instance_id, clock_profile,
                            clock_role='T-BC', domain_number=None,
                            priority2=None, servo_alg=None):
    """Configure a PTP instance.

    Args:
        device: Device object.
        instance_id: PTP instance number.
        clock_profile: G8275.1 or G8275.2.
        clock_role: T-BC or T-GM (default T-BC).
        domain_number: Domain number.
        priority2: Priority2 value (0-255).
        servo_alg: Servo algorithm name.
    """
    log.info(f"Configuring PTP instance {instance_id} on {device.name}")
    config = [f'ptp instance-list {instance_id}']
    config.append(f'clock-profile {clock_profile}')
    config.append(f'clock-role {clock_role}')
    if domain_number is not None:
        config.append(f'default-ds domain-number {domain_number}')
    if priority2 is not None:
        config.append(f'default-ds priority2 {priority2}')
    if servo_alg:
        config.append(f'servo-alg {servo_alg}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PTP instance failed on {device.name}: {e}")


def unconfigure_ptp_instance(device, instance_id):
    """Remove a PTP instance."""
    log.info(f"Removing PTP instance {instance_id} from {device.name}")
    try:
        device.configure([f'no ptp instance-list {instance_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PTP instance removal failed on {device.name}: {e}")


def configure_ptp_port(device, instance_id, port_id, interface,
                        delay_mechanism='e2e', master_only=None):
    """Configure a PTP port.

    Args:
        device: Device object.
        instance_id: PTP instance number.
        port_id: Port data set number.
        interface: Underlying interface name.
        delay_mechanism: e2e or p2p (default e2e).
        master_only: True/False for master-only mode.
    """
    log.info(f"Configuring PTP port {port_id} on {device.name}")
    config = [f'ptp instance-list {instance_id} port-ds-list {port_id}']
    config.append(f'underlying-interface interface {interface}')
    config.append(f'delay-mechanism {delay_mechanism}')
    if master_only is not None:
        flag = 'true' if master_only else 'false'
        config.append(f'master-only {flag}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PTP port failed on {device.name}: {e}")


def unconfigure_ptp_port(device, instance_id, port_id):
    """Remove a PTP port."""
    log.info(f"Removing PTP port {port_id} from {device.name}")
    try:
        device.configure([
            f'ptp instance-list {instance_id}',
            f'no port-ds-list {port_id}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"PTP port removal failed on {device.name}: {e}")
