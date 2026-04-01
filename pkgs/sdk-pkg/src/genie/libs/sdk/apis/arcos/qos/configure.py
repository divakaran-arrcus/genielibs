"""Common configure functions for QoS on ArcOS."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_qos_classifier(device, name, filter_type, **filter_args):
    """Create a QoS classifier.

    Args:
        device (obj): Device object.
        name (str): Classifier name.
        filter_type (str): Filter type — DSCP, LOCAL_TC, ACL_IPV4, ANY, etc.
        **filter_args: Filter-specific args (dscp_values, local_tc_value, acl_name).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure classifier.

    Example:
        >>> configure_qos_classifier(device, 'class-dscp-46', 'DSCP', dscp_values=[46])
    """

    log.info(f"Configuring QoS classifier {name} on {device.name}")

    config = [f'qos classifier {name}']

    if filter_type == "DSCP":
        vals = filter_args.get("dscp_values", [])
        if isinstance(vals, (list, tuple)):
            vals_str = ' '.join(str(v) for v in vals)
        else:
            vals_str = str(vals)
        config.append(f'filter DSCP dscp-value [ {vals_str} ]')
    elif filter_type == "LOCAL_TC":
        val = filter_args.get("local_tc_value")
        if val is not None:
            config.append(f'filter LOCAL_TC local-tc-value {val}')
    elif filter_type == "ACL_IPV4":
        acl = filter_args.get("acl_name")
        if acl:
            config.append(f'filter ACL_IPV4 acl-name {acl}')
    elif filter_type == "ANY":
        config.append('filter ANY')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure QoS classifier {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_qos_classifier(device, name):
    """Remove a QoS classifier.

    Args:
        device (obj): Device object.
        name (str): Classifier name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove classifier.

    Example:
        >>> unconfigure_qos_classifier(device, 'class-dscp-46')
    """

    log.info(f"Removing QoS classifier {name} from {device.name}")

    config = [f'no qos classifier {name}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove QoS classifier {name} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_qos_policy(device, name, classifier_actions):
    """Create a QoS policy with classifier→action mappings.

    Args:
        device (obj): Device object.
        name (str): Policy name.
        classifier_actions (list): List of dicts with:
            - classifier (str): Classifier name
            - action_type (str): POLICE, PRIORITY, RATE_MAX, etc.
            - action_args (dict): Action-specific params

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure policy.

    Example:
        >>> configure_qos_policy(device, 'ingress-pol', [
        ...     {'classifier': 'class-dscp-46',
        ...      'action_type': 'POLICE',
        ...      'action_args': {'rate_value': 500, 'rate_unit': 'mbps'}},
        ... ])
    """

    log.info(f"Configuring QoS policy {name} on {device.name}")

    config = [f'qos policy {name}']

    for ca in classifier_actions:
        cls = ca.get("classifier")
        if not cls:
            continue

        config.append(f'classifier {cls}')

        action_type = ca.get("action_type")
        args = ca.get("action_args", {})

        if action_type == "POLICE":
            rate = args.get("rate_value")
            unit = args.get("rate_unit", "mbps")
            if rate is not None:
                config.append(
                    f'action POLICE committed rate value {rate} unit {unit}'
                )
        elif action_type == "PRIORITY":
            level = args.get("level", 1)
            config.append(f'action PRIORITY level {level}')
        elif action_type == "RATE_MAX":
            rate = args.get("rate_value")
            unit = args.get("rate_unit", "mbps")
            if rate is not None:
                config.append(
                    f'action RATE_MAX value {rate} unit {unit}'
                )
        elif action_type == "RATE_EXCESS":
            ratio = args.get("ratio")
            if ratio is not None:
                config.append(f'action RATE_EXCESS ratio {ratio}')
        elif action_type == "MARKING":
            local_tc = args.get("local_tc")
            if local_tc is not None:
                config.append(f'action MARKING local-tc {local_tc}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure QoS policy {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_qos_policy(device, name):
    """Remove a QoS policy.

    Args:
        device (obj): Device object.
        name (str): Policy name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove policy.

    Example:
        >>> unconfigure_qos_policy(device, 'ingress-pol')
    """

    log.info(f"Removing QoS policy {name} from {device.name}")

    config = [f'no qos policy {name}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove QoS policy {name} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_qos_service_policy(device, interface, direction, policy_name):
    """Attach a QoS policy to an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        direction (str): INGRESS or EGRESS.
        policy_name (str): Policy name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to attach policy.

    Example:
        >>> configure_qos_service_policy(device, 'swp1', 'INGRESS', 'ingress-pol')
    """

    log.info(
        f"Attaching QoS policy {policy_name} {direction} to "
        f"{interface} on {device.name}"
    )

    config = [
        f'interface {interface}',
        f'qos service-policy {direction} name {policy_name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not attach QoS policy to {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_qos_service_policy(device, interface, direction):
    """Remove QoS policy from an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        direction (str): INGRESS or EGRESS.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove policy binding.

    Example:
        >>> unconfigure_qos_service_policy(device, 'swp1', 'INGRESS')
    """

    log.info(
        f"Removing QoS service-policy {direction} from "
        f"{interface} on {device.name}"
    )

    config = [
        f'interface {interface}',
        f'no qos service-policy {direction}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove QoS policy from {interface} on "
            f"{device.name}. Error:\n{e}"
        )
