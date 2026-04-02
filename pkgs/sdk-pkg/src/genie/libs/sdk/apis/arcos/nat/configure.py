"""ArcOS NAT (SNAT) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_nat_instance(device, instance_id, name, enabled=True):
    """Configure a NAT instance.

    Args:
        device: Device object.
        instance_id: Instance ID (1-32).
        name: Instance name.
        enabled: Enable the instance (default True).
    """
    log.info(f"Configuring NAT instance {instance_id} on {device.name}")
    enabled_str = 'true' if enabled else 'false'
    config = [
        f'nat instance {instance_id}',
        f'name {name}',
        f'enable {enabled_str}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"NAT instance failed on {device.name}: {e}")


def unconfigure_nat_instance(device, instance_id):
    """Remove a NAT instance."""
    log.info(f"Removing NAT instance {instance_id} from {device.name}")
    try:
        device.configure([f'no nat instance {instance_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"NAT instance removal failed on {device.name}: {e}")


def configure_nat_mapping_entry(device, instance_id, entry_id,
                                 internal_src_address):
    """Configure a NAT mapping entry.

    Args:
        device: Device object.
        instance_id: NAT instance ID.
        entry_id: Mapping entry ID (1-32).
        internal_src_address: Internal source CIDR (e.g., '10.10.0.0/16').
    """
    log.info(f"Configuring NAT mapping entry {entry_id} on {device.name}")
    config = [
        f'nat instance {instance_id}',
        f'mapping-entry {entry_id} internal-src-address {internal_src_address}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"NAT mapping entry failed on {device.name}: {e}")


def unconfigure_nat_mapping_entry(device, instance_id, entry_id):
    """Remove a NAT mapping entry."""
    log.info(f"Removing NAT mapping entry {entry_id} from {device.name}")
    try:
        device.configure([
            f'nat instance {instance_id}',
            f'no mapping-entry {entry_id}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"NAT mapping removal failed on {device.name}: {e}")


def configure_nat_policy(device, instance_id, policy_id, external_interface):
    """Configure a NAT policy with external interface.

    Args:
        device: Device object.
        instance_id: NAT instance ID.
        policy_id: Policy ID.
        external_interface: External interface name (e.g., 'swp1').
    """
    log.info(f"Configuring NAT policy {policy_id} on {device.name}")
    config = [
        f'nat instance {instance_id}',
        f'policy {policy_id} external-interface {external_interface}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"NAT policy failed on {device.name}: {e}")


def unconfigure_nat_policy(device, instance_id, policy_id):
    """Remove a NAT policy."""
    log.info(f"Removing NAT policy {policy_id} from {device.name}")
    try:
        device.configure([
            f'nat instance {instance_id}',
            f'no policy {policy_id}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"NAT policy removal failed on {device.name}: {e}")
