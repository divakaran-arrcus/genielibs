"""Common configure functions for routing-policy on ArcOS"""

# Python
import logging
from typing import List, Optional

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prefix Set APIs
# ---------------------------------------------------------------------------


def configure_prefix_set(device, set_name, prefixes):
    """Configure a routing-policy prefix-set with one or more prefixes.

    Creates a prefix-set and adds all specified prefixes in a single
    configuration transaction.

    Args:
        device (obj): Device object
        set_name (str): Prefix-set name (e.g., 'LEAK-L2-TO-L1')
        prefixes (list): List of prefix dicts, each with:
            - ``prefix`` (str): IP prefix (e.g., '6.6.6.6/32')
            - ``masklength_range`` (str): Mask range or 'exact'
              (e.g., 'exact', '16..32')

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure prefix-set

    Example:
        >>> configure_prefix_set(
        ...     device=device,
        ...     set_name='LEAK-L2-TO-L1',
        ...     prefixes=[
        ...         {'prefix': '6.6.6.6/32', 'masklength_range': 'exact'},
        ...         {'prefix': '10.0.0.0/8', 'masklength_range': '8..24'},
        ...     ]
        ... )
    """
    log.info(
        f"Configuring prefix-set {set_name} with {len(prefixes)} prefix(es) "
        f"on {device.name}"
    )

    config = [
        f'routing-policy defined-sets prefix-set {set_name}',
    ]

    for entry in prefixes:
        pfx = entry['prefix']
        mask = entry.get('masklength_range', 'exact')
        config.append(f'prefix {pfx} {mask}')
        config.append('exit')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure prefix-set {set_name} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_prefix_set(device, set_name):
    """Remove an entire routing-policy prefix-set.

    Args:
        device (obj): Device object
        set_name (str): Prefix-set name to remove

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove prefix-set

    Example:
        >>> unconfigure_prefix_set(device, 'LEAK-L2-TO-L1')
    """
    log.info(f"Removing prefix-set {set_name} from {device.name}")

    config = [
        f'no routing-policy defined-sets prefix-set {set_name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove prefix-set {set_name} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_prefix_set_entry(device, set_name, prefix, masklength_range='exact'):
    """Add a single prefix entry to an existing prefix-set.

    If the prefix-set does not exist it will be created.

    Args:
        device (obj): Device object
        set_name (str): Prefix-set name
        prefix (str): IP prefix (e.g., '10.0.0.0/8')
        masklength_range (str, optional): Mask range. Defaults to 'exact'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to add prefix entry

    Example:
        >>> configure_prefix_set_entry(device, 'MY-SET', '10.0.0.0/8', '8..24')
    """
    log.info(
        f"Adding prefix {prefix} {masklength_range} to prefix-set {set_name} "
        f"on {device.name}"
    )

    config = [
        f'routing-policy defined-sets prefix-set {set_name}',
        f'prefix {prefix} {masklength_range}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not add prefix {prefix} to prefix-set {set_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_prefix_set_entry(device, set_name, prefix, masklength_range='exact'):
    """Remove a single prefix entry from a prefix-set.

    Args:
        device (obj): Device object
        set_name (str): Prefix-set name
        prefix (str): IP prefix to remove (e.g., '10.0.0.0/8')
        masklength_range (str, optional): Mask range. Defaults to 'exact'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove prefix entry

    Example:
        >>> unconfigure_prefix_set_entry(device, 'MY-SET', '10.0.0.0/8', '8..24')
    """
    log.info(
        f"Removing prefix {prefix} {masklength_range} from prefix-set "
        f"{set_name} on {device.name}"
    )

    config = [
        f'routing-policy defined-sets prefix-set {set_name}',
        f'no prefix {prefix} {masklength_range}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove prefix {prefix} from prefix-set {set_name} "
            f"on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Policy Definition APIs
# ---------------------------------------------------------------------------


def configure_routing_policy(device, policy_name, action='accept-route',
                             statement_name='pass-all',
                             match_prefix_set=None,
                             match_set_options=None):
    """Configure a routing-policy policy-definition with a single statement.

    Creates a policy definition with one statement containing the specified
    action and optional match conditions. For policies that need multiple
    statements, call this function once to create the first statement, then
    use the arcOS CLI directly or extend this API.

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name (e.g., 'ALLOW-ALL')
        action (str, optional): Route disposition action.
            One of 'accept-route', 'reject-route', 'next-policy'.
            Defaults to 'accept-route'.
        statement_name (str, optional): Statement name/number.
            Defaults to 'pass-all'.
        match_prefix_set (str, optional): Name of prefix-set to match.
            If None, the statement matches all routes.
        match_set_options (str, optional): Match-set options for prefix-set
            matching. One of 'ANY', 'ALL', 'INVERT'. Only used when
            match_prefix_set is provided.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure policy definition

    Example:
        >>> configure_routing_policy(
        ...     device=device,
        ...     policy_name='ALLOW-ALL',
        ...     action='accept-route',
        ... )
        >>> configure_routing_policy(
        ...     device=device,
        ...     policy_name='MATCH-LEAKED',
        ...     action='accept-route',
        ...     statement_name='10',
        ...     match_prefix_set='LEAK-PREFIXES',
        ...     match_set_options='ANY',
        ... )
    """
    log.info(
        f"Configuring routing-policy {policy_name} (statement {statement_name}, "
        f"action {action}) on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
    ]

    if match_prefix_set is not None:
        config.append(
            f'conditions match-prefix-set prefix-set {match_prefix_set}'
        )
        if match_set_options is not None:
            config.append(
                f'conditions match-prefix-set match-set-options {match_set_options}'
            )

    config.append(f'actions {action}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure routing-policy {policy_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy(device, policy_name):
    """Remove an entire routing-policy policy-definition.

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name to remove

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove policy definition

    Example:
        >>> unconfigure_routing_policy(device, 'ALLOW-ALL')
    """
    log.info(f"Removing routing-policy {policy_name} from {device.name}")

    config = [
        f'no routing-policy policy-definition {policy_name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove routing-policy {policy_name} "
            f"from {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Ext-Community Set APIs
# ---------------------------------------------------------------------------


def configure_ext_community_set(device, name, members):
    """Configure a BGP ext-community-set.

    Args:
        device (obj): Device object.
        name (str): Ext-community-set name.
        members (list): List of ext-community member strings
            (e.g., ['route-target:2001:2001', 'route-origin:22:.*']).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ext-community-set.

    Example:
        >>> configure_ext_community_set(device, 'RT-SET-1',
        ...     ['route-target:2001:2001'])
    """

    log.info(
        f"Configuring ext-community-set {name} on {device.name}"
    )

    if isinstance(members, (list, tuple)):
        members_str = ' '.join(str(m) for m in members)
    else:
        members_str = str(members)

    config = [
        f'routing-policy defined-sets bgp-defined-sets '
        f'ext-community-set {name}',
        f'ext-community-member [ {members_str} ]',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ext-community-set {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_ext_community_set(device, name):
    """Remove a BGP ext-community-set.

    Args:
        device (obj): Device object.
        name (str): Ext-community-set name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ext-community-set.

    Example:
        >>> unconfigure_ext_community_set(device, 'RT-SET-1')
    """

    log.info(f"Removing ext-community-set {name} from {device.name}")

    config = [
        f'no routing-policy defined-sets bgp-defined-sets '
        f'ext-community-set {name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ext-community-set {name} from "
            f"{device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Advanced Policy Statement APIs (BGP conditions + actions)
# ---------------------------------------------------------------------------


def configure_routing_policy_bgp_actions(device, policy_name, statement_name,
                                          set_local_pref=None,
                                          set_med=None,
                                          set_next_hop=None,
                                          set_ext_community_method=None,
                                          set_ext_community_options=None,
                                          set_ext_community_inline=None,
                                          set_ext_community_ref=None):
    """Configure BGP actions on a routing-policy statement.

    Args:
        device (obj): Device object.
        policy_name (str): Policy definition name.
        statement_name (str): Statement name/number.
        set_local_pref (int, optional): Set local-preference value.
        set_med (int, optional): Set MED value.
        set_next_hop (str, optional): Set next-hop (IP or 'SELF').
        set_ext_community_method (str, optional): INLINE or REFERENCE.
        set_ext_community_options (str, optional): ADD, REMOVE, or REPLACE.
        set_ext_community_inline (list, optional): Inline ext-communities.
        set_ext_community_ref (str, optional): Reference ext-community-set name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP actions.

    Example:
        >>> configure_routing_policy_bgp_actions(device, 'MY-POLICY', '10',
        ...     set_local_pref=220)
    """

    log.info(
        f"Configuring BGP actions on {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
    ]

    if set_local_pref is not None:
        config.append(f'actions bgp-actions set-local-pref {set_local_pref}')

    if set_med is not None:
        config.append(f'actions bgp-actions set-med {set_med}')

    if set_next_hop is not None:
        config.append(f'actions bgp-actions set-next-hop {set_next_hop}')

    if set_ext_community_method is not None:
        config.append(
            f'actions bgp-actions set-ext-community method '
            f'{set_ext_community_method}'
        )

    if set_ext_community_options is not None:
        config.append(
            f'actions bgp-actions set-ext-community options '
            f'{set_ext_community_options}'
        )

    if set_ext_community_inline is not None:
        if isinstance(set_ext_community_inline, (list, tuple)):
            vals = ' '.join(str(v) for v in set_ext_community_inline)
        else:
            vals = str(set_ext_community_inline)
        config.append(
            f'actions bgp-actions set-ext-community inline '
            f'ext-communities [ {vals} ]'
        )

    if set_ext_community_ref is not None:
        config.append(
            f'actions bgp-actions set-ext-community reference '
            f'ext-community-set-ref {set_ext_community_ref}'
        )

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP actions on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_bgp_conditions(device, policy_name,
                                             statement_name,
                                             match_ext_community_set=None,
                                             match_set_options=None):
    """Configure BGP conditions on a routing-policy statement.

    Args:
        device (obj): Device object.
        policy_name (str): Policy definition name.
        statement_name (str): Statement name/number.
        match_ext_community_set (str, optional): Ext-community-set name to match.
        match_set_options (str, optional): Match options — ANY, ALL, INVERT.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP conditions.

    Example:
        >>> configure_routing_policy_bgp_conditions(device, 'MY-POLICY', '10',
        ...     match_ext_community_set='RT-SET-1', match_set_options='ANY')
    """

    log.info(
        f"Configuring BGP conditions on {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
    ]

    if match_ext_community_set is not None:
        config.append(
            f'conditions bgp-conditions match-ext-community-set '
            f'ext-community-set {match_ext_community_set}'
        )

    if match_set_options is not None:
        config.append(
            f'conditions bgp-conditions match-ext-community-set '
            f'match-set-options {match_set_options}'
        )

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP conditions on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )
