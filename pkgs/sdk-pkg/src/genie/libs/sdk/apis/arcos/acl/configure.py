"""Common configure functions for ACL on ArcOS."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_acl_set(device, name, acl_type, entries, description=None):
    """Create an ACL set with entries.

    Args:
        device (obj): Device object.
        name (str): ACL set name (e.g., 'v4-acl').
        acl_type (str): ACL type — ACL_IPV4, ACL_IPV6, ACL_L2.
        entries (list): List of ACE dicts, each with:
            - sequence_id (int)
            - ipv4_source_address (str, optional)
            - ipv4_destination_address (str, optional)
            - forwarding_action (str) — ACCEPT, DROP, REDIRECT
            - description (str, optional)
        description (str, optional): ACL set description.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ACL.

    Example:
        >>> configure_acl_set(device, 'v4-acl', 'ACL_IPV4', [
        ...     {'sequence_id': 10, 'ipv4_source_address': '10.0.0.0/8',
        ...      'forwarding_action': 'DROP'},
        ...     {'sequence_id': 1000, 'ipv4_source_address': '0.0.0.0/0',
        ...      'forwarding_action': 'ACCEPT'},
        ... ])
    """

    log.info(f"Configuring ACL {name} {acl_type} on {device.name}")

    config = [f'acl acl-set {name} {acl_type}']

    if description:
        config.append(f'description {description}')

    for entry in entries:
        seq = entry.get("sequence_id")
        if seq is None:
            continue

        config.append(f'acl-entry {seq}')

        desc = entry.get("description")
        if desc:
            config.append(f'description {desc}')

        for field, cli_key in [
            ("ipv4_source_address", "ipv4 source-address"),
            ("ipv4_destination_address", "ipv4 destination-address"),
            ("ipv4_protocol", "ipv4 protocol"),
            ("ipv6_source_address", "ipv6 source-address"),
            ("ipv6_destination_address", "ipv6 destination-address"),
            ("ipv6_protocol", "ipv6 protocol"),
            ("l2_source_mac", "l2 source-mac"),
            ("transport_source_port", "transport source-port"),
            ("transport_destination_port", "transport destination-port"),
        ]:
            v = entry.get(field)
            if v is not None:
                config.append(f'{cli_key} {v}')

        fwd = entry.get("forwarding_action")
        if fwd:
            config.append(f'actions forwarding-action {fwd}')

        log_act = entry.get("log_action")
        if log_act:
            config.append(f'actions log-action {log_act}')

        config.append('!')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ACL {name} {acl_type} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_acl_set(device, name, acl_type):
    """Remove an ACL set.

    Args:
        device (obj): Device object.
        name (str): ACL set name.
        acl_type (str): ACL type.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ACL.

    Example:
        >>> unconfigure_acl_set(device, 'v4-acl', 'ACL_IPV4')
    """

    log.info(f"Removing ACL {name} {acl_type} from {device.name}")

    config = [f'no acl acl-set {name} {acl_type}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ACL {name} {acl_type} from "
            f"{device.name}. Error:\n{e}"
        )
