"""ArcOS CoPP (Control Plane Policer) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_copp_classifier(device, name, filter_type, acl_type=None,
                               acl_name=None, exception_type=None):
    """Create a CoPP classifier.

    Args:
        device (obj): Device object.
        name (str): Classifier name.
        filter_type (str): ACL or EXCEPTION.
        acl_type (str, optional): ACL_IPV4, ACL_IPV6, ACL_L2.
        acl_name (str, optional): ACL set name.
        exception_type (str, optional): Exception type.

    Example:
        >>> configure_copp_classifier(device, 'MY-COPP', 'ACL',
        ...     acl_type='ACL_IPV4', acl_name='v4-acl')
    """
    log.info(f"Configuring CoPP classifier {name} on {device.name}")
    config = [f'copp classifier {name}']
    if filter_type == 'ACL' and acl_type and acl_name:
        config.append(f'filter ACL acl-type {acl_type} acl-name {acl_name}')
    elif filter_type == 'EXCEPTION' and exception_type:
        config.append(f'filter EXCEPTION {exception_type}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"CoPP classifier failed on {device.name}: {e}")


def unconfigure_copp_classifier(device, name):
    """Remove a CoPP classifier."""
    log.info(f"Removing CoPP classifier {name} from {device.name}")
    try:
        device.configure([f'no copp classifier {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"CoPP classifier removal failed on {device.name}: {e}")


def configure_copp_policy(device, name, classifier_actions):
    """Create a CoPP policy with classifier→action mappings.

    Args:
        device (obj): Device object.
        name (str): Policy name.
        classifier_actions (list): List of dicts with classifier, action_type, action_args.
    """
    log.info(f"Configuring CoPP policy {name} on {device.name}")
    config = [f'copp policy {name}']
    for ca in classifier_actions:
        cls = ca.get("classifier")
        if cls:
            config.append(f'classifier {cls}')
        action = ca.get("action_type")
        if action == "POLICE":
            rate = ca.get("rate", 1000)
            config.append(f'action POLICE committed rate value {rate}')
            burst = ca.get("burst")
            if burst:
                config.append(f'action POLICE committed burst value {burst}')
        elif action == "MARK":
            tc = ca.get("local_tc", 7)
            config.append(f'action MARK marking local-tc {tc}')
        elif action == "DROP":
            config.append('action DROP')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"CoPP policy failed on {device.name}: {e}")


def unconfigure_copp_policy(device, name):
    """Remove a CoPP policy."""
    log.info(f"Removing CoPP policy {name} from {device.name}")
    try:
        device.configure([f'no copp policy {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"CoPP policy removal failed on {device.name}: {e}")


def configure_copp_service_policy(device, policy_name):
    """Attach CoPP policy to control-plane (ingress).

    Args:
        device (obj): Device object.
        policy_name (str): CoPP policy name.
    """
    log.info(f"Attaching CoPP service-policy {policy_name} on {device.name}")
    try:
        device.configure([f'control-plane service-policy INGRESS name {policy_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"CoPP service-policy failed on {device.name}: {e}")


def unconfigure_copp_service_policy(device):
    """Remove CoPP policy from control-plane."""
    log.info(f"Removing CoPP service-policy from {device.name}")
    try:
        device.configure(['no control-plane service-policy INGRESS', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"CoPP service-policy removal failed on {device.name}: {e}")
