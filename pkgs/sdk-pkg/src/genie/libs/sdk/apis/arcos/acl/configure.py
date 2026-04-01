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
            ("ipv4_source_address_prefix_set", "ipv4 source-address-prefix-set"),
            ("ipv4_destination_address_prefix_set", "ipv4 destination-address-prefix-set"),
            ("ipv4_protocol", "ipv4 protocol"),
            ("ipv4_dscp", "ipv4 dscp"),
            ("ipv4_hop_limit", "ipv4 hop-limit"),
            ("ipv4_packet_length", "ipv4 packet-length"),
            ("ipv6_source_address", "ipv6 source-address"),
            ("ipv6_destination_address", "ipv6 destination-address"),
            ("ipv6_source_address_prefix_set", "ipv6 source-address-prefix-set"),
            ("ipv6_destination_address_prefix_set", "ipv6 destination-address-prefix-set"),
            ("ipv6_protocol", "ipv6 protocol"),
            ("ipv6_dscp", "ipv6 dscp"),
            ("ipv6_hop_limit", "ipv6 hop-limit"),
            ("ipv6_packet_length", "ipv6 packet-length"),
            ("ipv6_source_flow_label", "ipv6 source-flow-label"),
            ("l2_source_mac", "l2 source-mac"),
            ("l2_source_mac_mask", "l2 source-mac-mask"),
            ("l2_destination_mac", "l2 destination-mac"),
            ("l2_destination_mac_mask", "l2 destination-mac-mask"),
            ("l2_ethertype", "l2 ethertype"),
            ("transport_source_port", "transport source-port"),
            ("transport_destination_port", "transport destination-port"),
        ]:
            v = entry.get(field)
            if v is not None:
                config.append(f'{cli_key} {v}')

        # ACL counter reference
        acl_counter = entry.get("acl_counter")
        if acl_counter:
            config.append(f'acl-counter {acl_counter}')

        fwd = entry.get("forwarding_action")
        if fwd:
            config.append(f'actions forwarding-action {fwd}')

        log_act = entry.get("log_action")
        if log_act:
            config.append(f'actions log-action {log_act}')

        # Redirect actions
        redirect_ipv4_nh = entry.get("redirect_ipv4_next_hop")
        if redirect_ipv4_nh:
            config.append(f'actions ipv4-redirect next-hop {redirect_ipv4_nh}')

        redirect_ipv4_ni = entry.get("redirect_ipv4_network_instance")
        if redirect_ipv4_ni:
            config.append(f'actions ipv4-redirect network-instance {redirect_ipv4_ni}')

        redirect_ipv6_nh = entry.get("redirect_ipv6_next_hop")
        if redirect_ipv6_nh:
            config.append(f'actions ipv6-redirect next-hop {redirect_ipv6_nh}')

        redirect_ipv6_ni = entry.get("redirect_ipv6_network_instance")
        if redirect_ipv6_ni:
            config.append(f'actions ipv6-redirect network-instance {redirect_ipv6_ni}')

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


def configure_acl_counter(device, counter_name):
    """Create an ACL counter.

    Args:
        device (obj): Device object.
        counter_name (str): Counter name.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_acl_counter(device, 'custom-counter1')
    """
    log.info(f"Configuring ACL counter {counter_name} on {device.name}")
    try:
        device.configure([f'acl acl-counter {counter_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ACL counter {counter_name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_acl_counter(device, counter_name):
    """Remove an ACL counter.

    Args:
        device (obj): Device object.
        counter_name (str): Counter name.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Removing ACL counter {counter_name} from {device.name}")
    try:
        device.configure([f'no acl acl-counter {counter_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ACL counter from {device.name}. "
            f"Error:\n{e}"
        )


def configure_control_plane_acl(device, acl_type, set_name):
    """Attach an ACL to the control plane (ingress only).

    Args:
        device (obj): Device object.
        acl_type (str): ACL type — ACL_IPV4 or ACL_IPV6.
        set_name (str): ACL set name.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_control_plane_acl(device, 'ACL_IPV4', 'USER-CP-ACL')
    """
    log.info(
        f"Attaching control-plane ACL {acl_type}/{set_name} on {device.name}"
    )
    config = [
        'control-plane acl-service-policies ingress-acl-sets',
        f'acl-set {acl_type}',
        f'set-name {set_name}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not attach control-plane ACL on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_control_plane_acl(device, acl_type):
    """Remove an ACL from the control plane.

    Args:
        device (obj): Device object.
        acl_type (str): ACL type — ACL_IPV4 or ACL_IPV6.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        f"Removing control-plane ACL {acl_type} from {device.name}"
    )
    config = [
        'control-plane acl-service-policies ingress-acl-sets',
        f'no acl-set {acl_type}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove control-plane ACL from {device.name}. "
            f"Error:\n{e}"
        )


def configure_defined_sets_ipv4_prefix_set(device, name, prefixes):
    """Configure a defined-sets ipv4-prefix-set (used by ACL).

    Args:
        device (obj): Device object.
        name (str): Prefix-set name (e.g., 'DNS-SERVER').
        prefixes (list): List of prefix strings (e.g., ['10.0.0.0/8', '172.16.0.0/12']).

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_defined_sets_ipv4_prefix_set(
        ...     device, 'DNS-SERVER', ['10.0.0.0/8'])
    """
    log.info(
        f"Configuring defined-sets ipv4-prefix-set {name} on {device.name}"
    )
    if isinstance(prefixes, (list, tuple)):
        pfx_str = ' '.join(str(p) for p in prefixes)
    else:
        pfx_str = str(prefixes)

    config = [
        f'defined-sets ipv4-prefix-set {name}',
        f'prefix [ {pfx_str} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ipv4-prefix-set {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_defined_sets_ipv4_prefix_set(device, name):
    """Remove a defined-sets ipv4-prefix-set.

    Args:
        device (obj): Device object.
        name (str): Prefix-set name.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        f"Removing defined-sets ipv4-prefix-set {name} from {device.name}"
    )
    try:
        device.configure([f'no defined-sets ipv4-prefix-set {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ipv4-prefix-set {name} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_defined_sets_ipv6_prefix_set(device, name, prefixes):
    """Configure a defined-sets ipv6-prefix-set (used by ACL).

    Args:
        device (obj): Device object.
        name (str): Prefix-set name.
        prefixes (list): List of IPv6 prefix strings.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_defined_sets_ipv6_prefix_set(
        ...     device, 'LOCAL-HOST', ['::1/128'])
    """
    log.info(
        f"Configuring defined-sets ipv6-prefix-set {name} on {device.name}"
    )
    if isinstance(prefixes, (list, tuple)):
        pfx_str = ' '.join(str(p) for p in prefixes)
    else:
        pfx_str = str(prefixes)

    config = [
        f'defined-sets ipv6-prefix-set {name}',
        f'prefix [ {pfx_str} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ipv6-prefix-set {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_defined_sets_ipv6_prefix_set(device, name):
    """Remove a defined-sets ipv6-prefix-set.

    Args:
        device (obj): Device object.
        name (str): Prefix-set name.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        f"Removing defined-sets ipv6-prefix-set {name} from {device.name}"
    )
    try:
        device.configure([f'no defined-sets ipv6-prefix-set {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ipv6-prefix-set {name} from "
            f"{device.name}. Error:\n{e}"
        )
