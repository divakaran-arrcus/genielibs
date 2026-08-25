"""Common configure functions for routing-policy on ArcOS"""

# Python
import logging

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


# ---------------------------------------------------------------------------
# Community Set APIs
# ---------------------------------------------------------------------------


def configure_community_set(device, name, members):
    """Configure a BGP community-set.

    Args:
        device (obj): Device object.
        name (str): Community-set name.
        members (list): Community member strings (e.g., ['65001:100', '65001:200']).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure community-set.

    Example:
        >>> configure_community_set(device, 'COMM-SET-1', ['65001:100'])
    """
    log.info(f"Configuring community-set {name} on {device.name}")

    if isinstance(members, (list, tuple)):
        members_str = ' '.join(str(m) for m in members)
    else:
        members_str = str(members)

    config = [
        f'routing-policy defined-sets bgp-defined-sets community-set {name}',
        f'community-member [ {members_str} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure community-set {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_community_set(device, name):
    """Remove a BGP community-set.

    Args:
        device (obj): Device object.
        name (str): Community-set name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove community-set.
    """
    log.info(f"Removing community-set {name} from {device.name}")
    config = [
        f'no routing-policy defined-sets bgp-defined-sets community-set {name}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove community-set {name} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_as_path_set(device, name, members):
    """Configure a BGP as-path-set.

    Args:
        device (obj): Device object.
        name (str): AS-path-set name.
        members (list): AS-path regex strings (e.g., ['^65001_', '.*65002.*']).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure as-path-set.

    Example:
        >>> configure_as_path_set(device, 'AS-SET-1', ['^65001_'])
    """
    log.info(f"Configuring as-path-set {name} on {device.name}")

    if isinstance(members, (list, tuple)):
        members_str = ' '.join(str(m) for m in members)
    else:
        members_str = str(members)

    config = [
        f'routing-policy defined-sets bgp-defined-sets as-path-set {name}',
        f'as-path-set-member [ {members_str} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure as-path-set {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_as_path_set(device, name):
    """Remove a BGP as-path-set.

    Args:
        device (obj): Device object.
        name (str): AS-path-set name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove as-path-set.
    """
    log.info(f"Removing as-path-set {name} from {device.name}")
    config = [
        f'no routing-policy defined-sets bgp-defined-sets as-path-set {name}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove as-path-set {name} from "
            f"{device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Additional BGP Actions
# ---------------------------------------------------------------------------


def configure_routing_policy_set_community(device, policy_name, statement_name,
                                            method='INLINE', options='ADD',
                                            inline_communities=None,
                                            reference_set=None):
    """Configure set-community BGP action on a policy statement.

    Args:
        device (obj): Device object.
        policy_name (str): Policy definition name.
        statement_name (str): Statement name/number.
        method (str): INLINE or REFERENCE.
        options (str): ADD, REMOVE, or REPLACE.
        inline_communities (list, optional): Communities for INLINE method.
        reference_set (str, optional): Community-set name for REFERENCE method.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure set-community.
    """
    log.info(
        f"Configuring set-community on {policy_name}/{statement_name} "
        f"on {device.name}"
    )
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions bgp-actions set-community method {method}',
        f'actions bgp-actions set-community options {options}',
    ]

    if method == 'INLINE' and inline_communities:
        if isinstance(inline_communities, (list, tuple)):
            vals = ' '.join(str(v) for v in inline_communities)
        else:
            vals = str(inline_communities)
        config.append(
            f'actions bgp-actions set-community inline '
            f'communities [ {vals} ]'
        )

    if method == 'REFERENCE' and reference_set:
        config.append(
            f'actions bgp-actions set-community reference '
            f'community-set-ref {reference_set}'
        )

    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure set-community on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_set_as_path_prepend(device, policy_name,
                                                   statement_name, repeat_n):
    """Configure AS-path prepend BGP action.

    Args:
        device (obj): Device object.
        policy_name (str): Policy definition name.
        statement_name (str): Statement name/number.
        repeat_n (int): Number of times to prepend local AS.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure AS-path prepend.
    """
    log.info(
        f"Configuring as-path-prepend repeat-n {repeat_n} on "
        f"{policy_name}/{statement_name} on {device.name}"
    )
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions bgp-actions set-as-path-prepend repeat-n {repeat_n}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure as-path-prepend on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Additional BGP Conditions
# ---------------------------------------------------------------------------


def configure_routing_policy_match_community_set(device, policy_name,
                                                   statement_name,
                                                   community_set,
                                                   match_set_options='ANY'):
    """Configure match-community-set BGP condition.

    Args:
        device (obj): Device object.
        policy_name (str): Policy definition name.
        statement_name (str): Statement name/number.
        community_set (str): Community-set name to match.
        match_set_options (str): ANY, ALL, or INVERT.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure match-community-set.
    """
    log.info(
        f"Configuring match-community-set {community_set} on "
        f"{policy_name}/{statement_name} on {device.name}"
    )
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'conditions bgp-conditions match-community-set '
        f'community-set {community_set}',
        f'conditions bgp-conditions match-community-set '
        f'match-set-options {match_set_options}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure match-community-set on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_match_as_path_set(device, policy_name,
                                                 statement_name,
                                                 as_path_set,
                                                 match_set_options='ANY'):
    """Configure match-as-path-set BGP condition.

    Args:
        device (obj): Device object.
        policy_name (str): Policy definition name.
        statement_name (str): Statement name/number.
        as_path_set (str): AS-path-set name to match.
        match_set_options (str): ANY, ALL, or INVERT.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure match-as-path-set.
    """
    log.info(
        f"Configuring match-as-path-set {as_path_set} on "
        f"{policy_name}/{statement_name} on {device.name}"
    )
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'conditions bgp-conditions match-as-path-set '
        f'as-path-set {as_path_set}',
        f'conditions bgp-conditions match-as-path-set '
        f'match-set-options {match_set_options}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure match-as-path-set on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Large Community Set
# ---------------------------------------------------------------------------


def configure_large_community_set(device, name, members):
    """Configure a BGP large-community-set.

    Args:
        device (obj): Device object.
        name (str): Large-community-set name.
        members (list): Large community strings (e.g., ['65001:100:200']).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure large-community-set.
    """
    log.info(f"Configuring large-community-set {name} on {device.name}")
    if isinstance(members, (list, tuple)):
        members_str = ' '.join(str(m) for m in members)
    else:
        members_str = str(members)

    config = [
        f'routing-policy defined-sets bgp-defined-sets large-community-set {name}',
        f'large-community-member [ {members_str} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure large-community-set {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_large_community_set(device, name):
    """Remove a BGP large-community-set."""
    log.info(f"Removing large-community-set {name} from {device.name}")
    config = [
        f'no routing-policy defined-sets bgp-defined-sets large-community-set {name}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove large-community-set {name} from "
            f"{device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Remaining BGP Actions
# ---------------------------------------------------------------------------


def configure_routing_policy_set_route_origin(device, policy_name,
                                               statement_name, origin):
    """Configure set-route-origin BGP action.

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        origin (str): Origin value (IGP, EGP, INCOMPLETE).
    """
    log.info(f"Configuring set-route-origin {origin} on {policy_name}/{statement_name}")
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions bgp-actions set-route-origin {origin}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure set-route-origin on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_adjust_local_pref(device, policy_name,
                                                statement_name, offset):
    """Configure adjust-local-pref BGP action.

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        offset (int): Offset value (positive to increase, negative to decrease).
    """
    log.info(f"Configuring adjust-local-pref offset {offset} on {policy_name}/{statement_name}")
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions bgp-actions adjust-local-pref offset {offset}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure adjust-local-pref on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_set_aigp(device, policy_name, statement_name,
                                       aigp_value):
    """Configure set-aigp BGP action.

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        aigp_value (int): AIGP metric value.
    """
    log.info(f"Configuring set-aigp {aigp_value} on {policy_name}/{statement_name}")
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions bgp-actions set-aigp {aigp_value}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure set-aigp on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_adjust_med(device, policy_name, statement_name,
                                         offset):
    """Configure adjust-med BGP action.

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        offset (int): MED offset value.
    """
    log.info(f"Configuring adjust-med offset {offset} on {policy_name}/{statement_name}")
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions bgp-actions adjust-med offset {offset}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure adjust-med on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_drop_attr(device, policy_name, statement_name,
                                        attr_codes):
    """Configure drop-attr BGP action (remove attribute codes).

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        attr_codes (list): Attribute codes to drop (e.g., [4, 5, 16]).
    """
    log.info(f"Configuring drop-attr {attr_codes} on {policy_name}/{statement_name}")
    if isinstance(attr_codes, (list, tuple)):
        codes_str = ' '.join(str(c) for c in attr_codes)
    else:
        codes_str = str(attr_codes)

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions bgp-actions drop-attr [ {codes_str} ]',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure drop-attr on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Remaining Conditions
# ---------------------------------------------------------------------------


def configure_routing_policy_match_interface(device, policy_name,
                                              statement_name, interface):
    """Configure match-interface condition (for table-connection policies).

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        interface (str): Interface name to match.
    """
    log.info(f"Configuring match-interface {interface} on {policy_name}/{statement_name}")
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'conditions match-interface interface {interface}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure match-interface on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_match_large_community_set(device, policy_name,
                                                         statement_name,
                                                         large_community_set,
                                                         match_set_options='ANY'):
    """Configure match-large-community-set BGP condition.

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        large_community_set (str): Large-community-set name.
        match_set_options (str): ANY, ALL, or INVERT.
    """
    log.info(
        f"Configuring match-large-community-set {large_community_set} on "
        f"{policy_name}/{statement_name}"
    )
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'conditions bgp-conditions match-large-community-set '
        f'large-community-set {large_community_set}',
        f'conditions bgp-conditions match-large-community-set '
        f'match-set-options {match_set_options}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure match-large-community-set on "
            f"{device.name}. Error:\n{e}"
        )


def configure_routing_policy_call_policy(device, policy_name,
                                          statement_name, called_policy):
    """Configure call-policy action (invoke another policy).

    Args:
        device (obj): Device object.
        policy_name (str): Policy name.
        statement_name (str): Statement name.
        called_policy (str): Name of the policy to call.
    """
    log.info(f"Configuring call-policy {called_policy} on {policy_name}/{statement_name}")
    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'conditions call-policy {called_policy}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure call-policy on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# ISIS-Specific Actions (Batch D)
# ---------------------------------------------------------------------------
# Proposed and approved via:
#   orchestrator/proposals/approved/isis_api_batch_d_redistribution.md
# adoc reference: IS-IS.adoc §2312-2365.
# ---------------------------------------------------------------------------


def configure_routing_policy_isis_actions_set_level(device, policy_name,
                                                     statement_name, level):
    """Configure ISIS set-level action on a routing-policy statement.

    Restricts the level at which a redistributed prefix is advertised
    into ISIS. Default behavior (when this action is absent) is to
    advertise into both L1 AND L2 (adoc §2344).

    CLI emitted::

        routing-policy policy-definition {policy_name}
          statement {statement_name}
            actions igp-actions isis-actions set-level {level}

    Args:
        device (obj): Device object.
        policy_name (str): Existing routing-policy-definition name.
        statement_name (str): Statement name/number within the policy.
        level (int): ISIS level — 1 or 2.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If level is not 1 or 2.

    Example:
        >>> # Redistribute statics into L1 only
        >>> configure_routing_policy_isis_actions_set_level(
        ...     device, 'v4-statics-fltr', '10', level=1)
    """
    if level not in (1, 2):
        raise ValueError(
            f"Invalid ISIS level '{level}'. Must be 1 or 2."
        )

    log.info(
        f"Configuring ISIS set-level={level} on {policy_name}/"
        f"{statement_name} on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions igp-actions isis-actions set-level {level}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS set-level on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_isis_actions_set_level(device, policy_name,
                                                       statement_name):
    """Remove ISIS set-level action from a routing-policy statement.

    Args:
        device (obj): Device object.
        policy_name (str): Routing-policy-definition name.
        statement_name (str): Statement name/number.

    Raises:
        SubCommandFailure: If unconfigure fails.
    """
    log.info(
        f"Removing ISIS set-level from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        'no actions igp-actions isis-actions set-level',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS set-level from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def configure_routing_policy_isis_actions_set_metric(device, policy_name,
                                                      statement_name, metric):
    """Configure ISIS set-metric action on a routing-policy statement.

    Overrides the default ISIS metric (10) for the redistributed prefix.

    CLI emitted::

        routing-policy policy-definition {policy_name}
          statement {statement_name}
            actions igp-actions isis-actions set-metric {metric}

    Args:
        device (obj): Device object.
        policy_name (str): Existing routing-policy-definition name.
        statement_name (str): Statement name/number within the policy.
        metric (int): ISIS wide metric value.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> # Set ISIS metric to 50 on redistributed routes
        >>> configure_routing_policy_isis_actions_set_metric(
        ...     device, 'v4-statics-fltr', '10', metric=50)
    """
    log.info(
        f"Configuring ISIS set-metric={metric} on {policy_name}/"
        f"{statement_name} on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'actions igp-actions isis-actions set-metric {metric}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS set-metric on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_isis_actions_set_metric(device, policy_name,
                                                       statement_name):
    """Remove ISIS set-metric action from a routing-policy statement.

    Args:
        device (obj): Device object.
        policy_name (str): Routing-policy-definition name.
        statement_name (str): Statement name/number.

    Raises:
        SubCommandFailure: If unconfigure fails.
    """
    log.info(
        f"Removing ISIS set-metric from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        'no actions igp-actions isis-actions set-metric',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS set-metric from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Next-Hop Set APIs
# ---------------------------------------------------------------------------


def configure_routing_policy_next_hop_set(device, set_name, addresses):
    """Configure a routing-policy next-hop-set defined-set.

    Creates the next-hop-set and populates its ``address`` leaf-list in a
    single configuration transaction.

    CLI emitted::

        routing-policy defined-sets next-hop-set {set_name}
         address [ {addresses} ]
        !

    Args:
        device (obj): Device object
        set_name (str): Next-hop-set name (e.g., 'NH1')
        addresses (list or str): Next-hop address(es), prefix(es), or the
            literal ``SELF``. A list/tuple is joined space-separated; a bare
            string is used as-is.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure next-hop-set

    Example:
        >>> configure_routing_policy_next_hop_set(device, 'NH1', ['cafe::/16'])

    Note:
        Required before :func:`configure_routing_policy_match_next_hop_set`,
        which references the set by name. Verified on rtr1 2026-08-20.
    """
    log.info(f"Configuring next-hop-set {set_name} on {device.name}")

    if isinstance(addresses, (list, tuple)) and not addresses:
        raise ValueError(
            "configure_routing_policy_next_hop_set requires at least one "
            "entry in 'addresses'. An empty list renders "
            "'address [  ]', which arcOS accepts silently and ignores -- "
            "the leaf is never created, so the caller would get a "
            "successful return and no configuration "
            "(verified on rtr1 2026-08-25)."
        )

    if isinstance(addresses, (list, tuple)):
        addr_str = ' '.join(str(a) for a in addresses)
    else:
        addr_str = str(addresses)

    config = [
        f'routing-policy defined-sets next-hop-set {set_name}',
        f'address [ {addr_str} ]',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure next-hop-set {set_name} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_routing_policy_next_hop_set(device, set_name):
    """Remove an entire routing-policy next-hop-set defined-set.

    CLI emitted::

        no routing-policy defined-sets next-hop-set {set_name}
        !

    Args:
        device (obj): Device object
        set_name (str): Next-hop-set name to remove

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove next-hop-set

    Example:
        >>> unconfigure_routing_policy_next_hop_set(device, 'NH1')

    Note:
        Exact inverse of :func:`configure_routing_policy_next_hop_set`.
        Verified on rtr1 2026-08-20.
    """
    log.info(f"Removing next-hop-set {set_name} from {device.name}")

    config = [
        f'no routing-policy defined-sets next-hop-set {set_name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove next-hop-set {set_name} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_routing_policy_match_next_hop_set(device, policy_name,
                                                  statement_name,
                                                  next_hop_set,
                                                  match_set_options='ANY'):
    """Configure a match-next-hop-set condition on a policy statement.

    CLI emitted::

        routing-policy policy-definition {policy_name}
         statement {statement_name}
          conditions match-next-hop-set next-hop-set {next_hop_set}
          conditions match-next-hop-set match-set-options {match_set_options}
        !

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number
        next_hop_set (str): Next-hop-set name to match
        match_set_options (str): ANY, ALL, or INVERT. Defaults to 'ANY'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure match-next-hop-set

    Example:
        >>> configure_routing_policy_match_next_hop_set(
        ...     device, 'POL1', '10', 'NH1')

    Note:
        The set name goes under a ``next-hop-set`` sub-leaf; the bare form
        ``conditions match-next-hop-set {name}`` is rejected by the device
        with a syntax error. The referenced set must already exist — see
        :func:`configure_routing_policy_next_hop_set`. Verified on rtr1
        2026-08-20.
    """
    log.info(
        f"Configuring match-next-hop-set {next_hop_set} on "
        f"{policy_name}/{statement_name} on {device.name}"
    )

    config = [
        f'routing-policy policy-definition {policy_name}',
        f'statement {statement_name}',
        f'conditions match-next-hop-set next-hop-set {next_hop_set}',
        f'conditions match-next-hop-set match-set-options '
        f'{match_set_options}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure match-next-hop-set on {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_match_next_hop_set(device, policy_name,
                                                    statement_name):
    """Remove the match-next-hop-set condition from a policy statement.

    Removes the whole ``conditions match-next-hop-set`` container, clearing
    both the ``next-hop-set`` and ``match-set-options`` leaves that
    :func:`configure_routing_policy_match_next_hop_set` sets.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} conditions match-next-hop-set
        !

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove match-next-hop-set

    Example:
        >>> unconfigure_routing_policy_match_next_hop_set(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_match_next_hop_set`.
        Emitted flat rather than via submode entry, so a bare ``no`` cannot
        land at the parent scope. An empty ``statement`` container is left
        behind — assert on the leaves, not the block. Verified on rtr1
        2026-08-20.
    """
    log.info(
        f"Removing match-next-hop-set from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} conditions match-next-hop-set',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove match-next-hop-set from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Unconfigure parity (T2R-C)
#
# Every function below removes at the DEEPEST SINGLE-OWNER node and never at
# 'actions bgp-actions' or 'conditions bgp-conditions'. Those two containers are
# shared by 8 and 4 configure functions respectively, and removing one wipes
# leaves its caller never set — verified on rtr1 2026-08-25, where a single
# 'no ... actions bgp-actions' destroyed three leaves owned by three different
# functions. All forms are emitted flat under 'no' rather than via submode entry.
# ---------------------------------------------------------------------------

def unconfigure_routing_policy_adjust_local_pref(device, policy_name, statement_name):
    """Remove the adjust-local-pref action from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} actions bgp-actions adjust-local-pref

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the adjust-local-pref action

    Example:
        >>> unconfigure_routing_policy_adjust_local_pref(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_adjust_local_pref`.
        The ``offset`` keyword is not required on the ``no`` line.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing adjust-local-pref action from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} actions bgp-actions adjust-local-pref',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove adjust-local-pref action from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_adjust_med(device, policy_name, statement_name):
    """Remove the adjust-med action from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} actions bgp-actions adjust-med

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the adjust-med action

    Example:
        >>> unconfigure_routing_policy_adjust_med(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_adjust_med`.
        The ``offset`` keyword is not required on the ``no`` line.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing adjust-med action from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} actions bgp-actions adjust-med',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove adjust-med action from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_set_aigp(device, policy_name, statement_name):
    """Remove the set-aigp action from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} actions bgp-actions set-aigp

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the set-aigp action

    Example:
        >>> unconfigure_routing_policy_set_aigp(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_set_aigp`.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing set-aigp action from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} actions bgp-actions set-aigp',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove set-aigp action from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_set_as_path_prepend(device, policy_name, statement_name):
    """Remove the set-as-path-prepend action from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} actions bgp-actions set-as-path-prepend

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the set-as-path-prepend action

    Example:
        >>> unconfigure_routing_policy_set_as_path_prepend(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_set_as_path_prepend`.
        The ``repeat-n`` keyword is not required on the ``no`` line.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing set-as-path-prepend action from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} actions bgp-actions set-as-path-prepend',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove set-as-path-prepend action from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_set_route_origin(device, policy_name, statement_name):
    """Remove the set-route-origin action from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} actions bgp-actions set-route-origin

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the set-route-origin action

    Example:
        >>> unconfigure_routing_policy_set_route_origin(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_set_route_origin`.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing set-route-origin action from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} actions bgp-actions set-route-origin',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove set-route-origin action from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_drop_attr(device, policy_name, statement_name):
    """Remove the drop-attr action from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} actions bgp-actions drop-attr

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the drop-attr action

    Example:
        >>> unconfigure_routing_policy_drop_attr(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_drop_attr`.
        Removes the whole leaf-list. There is deliberately **no**
        ``attr_codes`` parameter: arcOS does not support per-entry removal,
        and naming a single code removes the ENTIRE list while reporting
        success. Verified on rtr1 2026-08-25 — ``no ... drop-attr [ 40 ]`` on
        ``[ 40 128 ]`` removed both.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing drop-attr action from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} actions bgp-actions drop-attr',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove drop-attr action from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_call_policy(device, policy_name, statement_name):
    """Remove the call-policy condition from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} conditions call-policy

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the call-policy condition

    Example:
        >>> unconfigure_routing_policy_call_policy(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_call_policy`.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing call-policy condition from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} conditions call-policy',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove call-policy condition from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_match_interface(device, policy_name, statement_name):
    """Remove the match-interface condition from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} conditions match-interface

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the match-interface condition

    Example:
        >>> unconfigure_routing_policy_match_interface(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_match_interface`.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing match-interface condition from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} conditions match-interface',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove match-interface condition from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_match_community_set(device, policy_name, statement_name):
    """Remove the match-community-set condition from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} conditions bgp-conditions match-community-set

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the match-community-set condition

    Example:
        >>> unconfigure_routing_policy_match_community_set(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_match_community_set`.
        Removes the single-owner sub-container, clearing both the name leaf
        and ``match-set-options``. Verified on rtr1 2026-08-25.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing match-community-set condition from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} conditions bgp-conditions match-community-set',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove match-community-set condition from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_match_as_path_set(device, policy_name, statement_name):
    """Remove the match-as-path-set condition from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} conditions bgp-conditions match-as-path-set

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the match-as-path-set condition

    Example:
        >>> unconfigure_routing_policy_match_as_path_set(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_match_as_path_set`.
        Removes the single-owner sub-container, clearing both the name leaf
        and ``match-set-options``. Verified on rtr1 2026-08-25.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing match-as-path-set condition from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} conditions bgp-conditions match-as-path-set',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove match-as-path-set condition from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_match_large_community_set(device, policy_name, statement_name):
    """Remove the match-large-community-set condition from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} conditions bgp-conditions match-large-community-set

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the match-large-community-set condition

    Example:
        >>> unconfigure_routing_policy_match_large_community_set(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_match_large_community_set`.
        Removes the single-owner sub-container, clearing both the name leaf
        and ``match-set-options``. Verified on rtr1 2026-08-25.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing match-large-community-set condition from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} conditions bgp-conditions match-large-community-set',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove match-large-community-set condition from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_set_community(device, policy_name, statement_name):
    """Remove the set-community action from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} actions bgp-actions set-community

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the set-community action

    Example:
        >>> unconfigure_routing_policy_set_community(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_set_community`.
        Clears ``method``, ``options`` and whichever of
        ``inline``/``reference`` was set — the whole single-owner
        sub-container. Verified on rtr1 2026-08-25: ``set-aigp`` on the same
        statement was left intact, confirming the removal does not reach the
        shared ``actions bgp-actions`` parent.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing set-community action from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} actions bgp-actions set-community',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove set-community action from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_routing_policy_bgp_conditions(device, policy_name, statement_name):
    """Remove the bgp-conditions ext-community match from a routing-policy statement.

    CLI emitted::

        no routing-policy policy-definition {policy_name} statement
            {statement_name} conditions bgp-conditions match-ext-community-set

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the bgp-conditions ext-community match

    Example:
        >>> unconfigure_routing_policy_bgp_conditions(device, 'POL1', '10')

    Note:
        Exact inverse of :func:`configure_routing_policy_bgp_conditions`.
        Clears both the ``ext-community-set`` name leaf and
        ``match-set-options``.

        Emitted flat rather than via submode entry, and never at the shared
        ``actions bgp-actions`` / ``conditions bgp-conditions`` container. An
        empty ``statement`` container may remain — assert on leaves, not blocks.
    """
    log.info(
        f"Removing bgp-conditions ext-community match from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    config = [
        f'no routing-policy policy-definition {policy_name} '
        f'statement {statement_name} conditions bgp-conditions match-ext-community-set',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove bgp-conditions ext-community match from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )

def unconfigure_routing_policy_bgp_actions(device, policy_name, statement_name,
                                             set_local_pref=False,
                                             set_med=False,
                                             set_next_hop=False,
                                             set_ext_community=False):
    """Remove BGP actions set by :func:`configure_routing_policy_bgp_actions`.

    Mirrors the configure's optional shape. Called with no flags it clears
    **all four** sub-nodes the configure can set — matching arcOS's own
    semantics, where removing a node clears everything beneath it. Passing any
    flag narrows the removal to just those.

    CLI emitted (no flags — all four)::

        no routing-policy policy-definition {p} statement {s} actions bgp-actions set-local-pref
        no routing-policy policy-definition {p} statement {s} actions bgp-actions set-med
        no routing-policy policy-definition {p} statement {s} actions bgp-actions set-next-hop
        no routing-policy policy-definition {p} statement {s} actions bgp-actions set-ext-community

    Args:
        device (obj): Device object
        policy_name (str): Policy definition name
        statement_name (str): Statement name/number
        set_local_pref (bool): Remove the set-local-pref sub-node
        set_med (bool): Remove the set-med sub-node
        set_next_hop (bool): Remove the set-next-hop sub-node
        set_ext_community (bool): Remove the set-ext-community sub-node
            (clears its ``method``, ``options`` and ``inline`` leaves together)

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the BGP actions

    Example:
        >>> # clear everything the configure could have set
        >>> unconfigure_routing_policy_bgp_actions(device, 'POL1', '10')
        >>> # clear only the MED
        >>> unconfigure_routing_policy_bgp_actions(
        ...     device, 'POL1', '10', set_med=True)

    Note:
        Exact inverse of :func:`configure_routing_policy_bgp_actions`.

        **This function emits one ``no`` line per sub-node and never collapses
        to ``no actions bgp-actions``.** That shorter form looks equivalent and
        is not: ``actions bgp-actions`` is shared by 8 configure functions, and
        removing it destroys leaves this caller never set. Verified on rtr1
        2026-08-25 — a single ``no ... actions bgp-actions`` wiped three leaves
        owned by ``set_aigp``, ``set_route_origin`` and ``adjust_med``.

        Emitted flat rather than via submode entry. An empty ``statement``
        container may remain — assert on leaves, not blocks.
    """
    # No flags means "clear the whole thing", per arcOS container semantics.
    if not any((set_local_pref, set_med, set_next_hop, set_ext_community)):
        set_local_pref = set_med = set_next_hop = set_ext_community = True

    log.info(
        f"Removing BGP actions from {policy_name}/{statement_name} "
        f"on {device.name}"
    )

    stmt = (f'no routing-policy policy-definition {policy_name} '
            f'statement {statement_name} actions bgp-actions')

    config = []
    if set_local_pref:
        config.append(f'{stmt} set-local-pref')
    if set_med:
        config.append(f'{stmt} set-med')
    if set_next_hop:
        config.append(f'{stmt} set-next-hop')
    if set_ext_community:
        config.append(f'{stmt} set-ext-community')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP actions from {policy_name}/"
            f"{statement_name} on {device.name}. Error:\n{e}"
        )
