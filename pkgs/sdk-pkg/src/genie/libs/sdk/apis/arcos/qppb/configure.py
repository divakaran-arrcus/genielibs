"""ArcOS QPPB (QoS Policy Propagation via BGP) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_routing_policy_set_qos_class_id(device, policy_name, statement,
                                                qos_class_id,
                                                match_next_hop_set=None,
                                                match_set_options='ANY'):
    """Configure routing policy with set-qos-class-id BGP action for QPPB.

    Args:
        device: Device object.
        policy_name: Policy definition name.
        statement: Statement number.
        qos_class_id: QoS class ID (0-255).
        match_next_hop_set: Optional next-hop-set name to match.
        match_set_options: Match set options (ANY or ALL).
    """
    log.info(f"Configuring QPPB policy {policy_name} statement {statement} on {device.name}")
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement}',
    ]
    if match_next_hop_set:
        config.append(
            f'conditions match-next-hop-set next-hop-set {match_next_hop_set}')
        config.append(f'conditions match-next-hop-set match-set-options {match_set_options}')
    config.append('actions accept-route')
    config.append(f'actions bgp-actions set-qos-class-id {qos_class_id}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"QPPB policy failed on {device.name}: {e}")


def unconfigure_routing_policy_set_qos_class_id(device, policy_name):
    """Remove a QPPB routing policy."""
    log.info(f"Removing QPPB policy {policy_name} from {device.name}")
    try:
        device.configure([f'no routing-policy policy-definition {policy_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"QPPB policy removal failed on {device.name}: {e}")


def configure_bgp_rib_install_policy(device, afi_safi, policy_name,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure BGP rib-install policy for QPPB.

    Args:
        device: Device object.
        afi_safi: AFI-SAFI name (e.g., IPV4_UNICAST).
        policy_name: Routing policy name for rib-install.
        network_instance: Network instance name.
        protocol_instance: BGP protocol instance.
    """
    log.info(f"Configuring BGP rib-install policy on {device.name}")
    config = [
        f'network-instance {network_instance} protocol BGP {protocol_instance}',
        f'global afi-safi {afi_safi}',
        f'rib-install policy [ {policy_name} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP rib-install policy failed on {device.name}: {e}")


def unconfigure_bgp_rib_install_policy(device, afi_safi,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Remove BGP rib-install policy."""
    log.info(f"Removing BGP rib-install policy on {device.name}")
    config = [
        f'network-instance {network_instance} protocol BGP {protocol_instance}',
        f'global afi-safi {afi_safi}',
        'no rib-install policy',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP rib-install removal failed on {device.name}: {e}")


def configure_qos_classifier_qppb(device, classifier_name, filter_type,
                                     qos_class_id):
    """Configure QoS classifier with QPPB filter type.

    Args:
        device: Device object.
        classifier_name: Classifier name.
        filter_type: SRC_QOS_CLASS or DST_QOS_CLASS.
        qos_class_id: QoS class ID to match.
    """
    log.info(f"Configuring QPPB QoS classifier {classifier_name} on {device.name}")
    config = [
        f'qos classifier {classifier_name}',
        f'filter {filter_type}',
        f'qos-class-id {qos_class_id}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"QPPB QoS classifier failed on {device.name}: {e}")


def unconfigure_qos_classifier_qppb(device, classifier_name):
    """Remove QPPB QoS classifier."""
    log.info(f"Removing QPPB QoS classifier {classifier_name} from {device.name}")
    try:
        device.configure([f'no qos classifier {classifier_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"QPPB classifier removal failed on {device.name}: {e}")
