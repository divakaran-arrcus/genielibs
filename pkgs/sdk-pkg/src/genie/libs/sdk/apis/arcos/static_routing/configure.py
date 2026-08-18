"""Common configure functions for static routing on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_static_route(device, prefix, next_hop='null', metric=None, tag=None,
                          network_instance='default'):
    """Configure a static route.
    
    Args:
        device (obj): Device object
        prefix (str): Route prefix (e.g., '100.100.100.0/24')
        next_hop (str, optional): Next hop address or 'null'. Defaults to 'null'.
        metric (int, optional): Route metric. Defaults to None.
        tag (int, optional): Route tag. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure static route
    
    Example:
        >>> configure_static_route(
        ...     device=device,
        ...     prefix='100.100.100.0/24',
        ...     next_hop='null',
        ...     metric=5,
        ...     tag=1000
        ... )
    """
    log.info(
        f"Configuring static route {prefix} on {device.name} "
        f"(next-hop: {next_hop}, metric: {metric}, tag: {tag}, "
        f"network-instance: {network_instance})"
    )
    
    # Build configuration using correct ArcOS protocol STATIC syntax
    config = [
        f'network-instance {network_instance}',
        'protocol STATIC default',
        f'static-route {prefix}'
    ]
    
    # Add set-tag if provided
    if tag is not None:
        config.append(f'set-tag {tag}')
    
    # Configure next-hop-index with DROP or IP address
    config.append('next-hop-index nh1')
    
    if next_hop.lower() == 'null':
        config.append('next-hop DROP')
    else:
        config.append(f'next-hop {next_hop}')
    
    if metric is not None:
        config.append(f'metric {metric}')
    
    # Exit from next-hop-index, static-route, protocol, network-instance
    config.extend(['exit', 'exit', 'exit', 'exit'])
    
    log.info(f"Configuration commands to be sent:\n{chr(10).join(['  ' + cmd for cmd in config])}")
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure static route {prefix} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_static_route(device, prefix, network_instance='default'):
    """Remove a static route.
    
    Args:
        device (obj): Device object
        prefix (str): Route prefix to remove (e.g., '100.100.100.0/24')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove static route
    
    Example:
        >>> unconfigure_static_route(
        ...     device=device,
        ...     prefix='100.100.100.0/24'
        ... )
    """
    log.info(
        f"Removing static route {prefix} from {device.name} "
        f"(network-instance: {network_instance})"
    )
    
    config = [
        f'network-instance {network_instance}',
        'protocol STATIC default',
        f'no static-route {prefix}'
    ]
    
    log.info(f"Configuration commands to be sent:\n{chr(10).join(['  ' + cmd for cmd in config])}")
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove static route {prefix} from {device.name}. "
            f"Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-07 — static-route attributes and per-nexthop knobs
# (arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md)
#
# Submode paths confirmed by `?` capture on rtr1 2026-08-17:
#   static-route <p>       -> bfd, description, local-label-index,
#                             next-hop-index, preference, set-tag
#   next-hop-index <n>     -> bfd, interface, metric, next-hop,
#                             next-network-instance-name, remote-label-stack,
#                             subinterface
#
# Audit correction: the leaf is `next-network-instance-name`, NOT
# `next-network-instance` as the audit row spelled it.
#
# ECMP is expressed by calling configure_static_route_nexthop() once per
# next-hop-index; the pre-existing configure_static_route() hardcodes a single
# `nh1` and is left untouched.
# ---------------------------------------------------------------------------


def _static_route_ctx(prefix, network_instance='default'):
    """Submode entry lines for one static route."""
    return [
        f'network-instance {network_instance}',
        'protocol STATIC default',
        f'static-route {prefix}',
    ]


def configure_static_route_attributes(device, prefix, description=None,
                                      preference=None, local_label_index=None,
                                      network_instance='default'):
    """Configure route-level static-route attributes.

    Args:
        device (obj): Device object
        prefix (str): Route prefix, e.g. ``'10.9.9.0/24'``.
        description (str, optional): Free-text description. Defaults to None.
        preference (int, optional): Administrative distance. Defaults to None.
        local_label_index (int, optional): Local label index. Defaults to None.
        network_instance (str, optional): Network instance. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If no attribute is supplied
        SubCommandFailure: Failed to configure the attributes

    Note:
        PREREQUISITE (commit-time, not parse-time): the route must already have
        at least one next-hop, or the commit aborts with
        ``Static route has no path/next-hop``. Call
        :func:`configure_static_route_nexthop` (or the legacy
        :func:`configure_static_route`) first. Confirmed on rtr1 2026-08-17.

    Example:
        >>> configure_static_route_attributes(
        ...     device, prefix='10.9.9.0/24', description='to-DC', preference=10)
    """
    if description is None and preference is None and local_label_index is None:
        raise ValueError(
            "configure_static_route_attributes requires at least one of "
            "'description', 'preference' or 'local_label_index'"
        )

    log.info(f"Configuring static-route {prefix} attributes on {device.name}")
    config = _static_route_ctx(prefix, network_instance)
    if description is not None:
        config.append(f'description "{description}"')
    if preference is not None:
        config.append(f'preference {preference}')
    if local_label_index is not None:
        config.append(f'local-label-index {local_label_index}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure static-route {prefix} attributes on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_static_route_attributes(device, prefix, description=False,
                                        preference=False, local_label_index=False,
                                        network_instance='default'):
    """Remove selected route-level static-route attributes.

    Each flag defaults to False (leave alone); pass True to clear that leaf.
    The route itself is not removed — use :func:`unconfigure_static_route`.

    Args:
        device (obj): Device object
        prefix (str): Route prefix.
        description (bool, optional): Clear the description. Defaults to False.
        preference (bool, optional): Clear the preference. Defaults to False.
        local_label_index (bool, optional): Clear the local label index.
            Defaults to False.
        network_instance (str, optional): Network instance. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If no attribute is selected
        SubCommandFailure: Failed to remove the attributes

    Example:
        >>> unconfigure_static_route_attributes(
        ...     device, prefix='10.9.9.0/24', preference=True)
    """
    if not (description or preference or local_label_index):
        raise ValueError(
            "unconfigure_static_route_attributes requires at least one of "
            "'description', 'preference' or 'local_label_index' set True"
        )

    log.info(f"Removing static-route {prefix} attributes on {device.name}")
    config = _static_route_ctx(prefix, network_instance)
    if description:
        config.append('no description')
    if preference:
        config.append('no preference')
    if local_label_index:
        config.append('no local-label-index')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove static-route {prefix} attributes on "
            f"{device.name}. Error:\n{e}"
        )


def configure_static_route_nexthop(device, prefix, nh_index, next_hop=None,
                                   interface=None, subinterface=None,
                                   metric=None, next_network_instance=None,
                                   remote_label_stack=None,
                                   bfd_destination_address=None,
                                   network_instance='default'):
    """Configure one next-hop-index of a static route.

    Call once per next-hop-index to build an ECMP set — the pre-existing
    :func:`configure_static_route` only ever emits a single ``nh1``.

    Args:
        device (obj): Device object
        prefix (str): Route prefix, e.g. ``'10.9.9.0/24'``.
        nh_index (str): Next-hop name, e.g. ``'nh1'``, ``'nh2'``.
        next_hop (str, optional): Next-hop address. Defaults to None.
        interface (str, optional): Egress interface. Defaults to None.
        subinterface (str or int, optional): Subinterface on that interface.
            Defaults to None.
        metric (int, optional): Per-next-hop metric. Defaults to None.
        next_network_instance (str, optional): Next VRF for inter-VRF leaking.
            Emitted as ``next-network-instance-name``. Defaults to None.
        remote_label_stack (list or str, optional): Remote label stack, rendered
            as ``[ l1 l2 l3 ]``. Defaults to None.
        bfd_destination_address (str, optional): BFD peer address for this
            next-hop. Defaults to None. See the third constraint below.
        network_instance (str, optional): Network instance. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If no next-hop attribute is supplied
        SubCommandFailure: Failed to configure the next-hop

    Note:
        Two commit-time constraints, both confirmed on rtr1 2026-08-17 and
        neither visible at parse time:

        1. **ECMP paths must be consistent.** Every next-hop-index on a route
           must either specify an ``interface`` or none may — mixing them aborts
           with "All paths must be configured with interface / next-hop as DROP,
           or without interface".
        2. **``next_network_instance`` requires a /32 IPv4 prefix.** Using it on
           a wider prefix aborts with "Expect /32 v4 prefix when configuring
           static route with next-network-instance option".
        3. **``bfd_destination_address`` requires an ``interface``** on the same
           next-hop — the interface's IP becomes the BFD session source
           (Static_Routing.adoc:189). Note the leaf takes a BARE address on this
           build (`bfd destination-address <IP address>`); the adoc's
           `bfd destination-address ipv4 <addr>` form is wrong for this build.

    Example:
        >>> configure_static_route_nexthop(
        ...     device, prefix='10.9.9.0/24', nh_index='nh2',
        ...     next_hop='10.1.1.2', interface='swp1')
    """
    if all(v is None for v in (next_hop, interface, subinterface, metric,
                               next_network_instance, remote_label_stack,
                               bfd_destination_address)):
        raise ValueError(
            f"configure_static_route_nexthop({nh_index}) requires at least one "
            "next-hop attribute"
        )

    log.info(
        f"Configuring static-route {prefix} next-hop-index {nh_index} on "
        f"{device.name}"
    )
    config = _static_route_ctx(prefix, network_instance)
    config.append(f'next-hop-index {nh_index}')
    if next_hop is not None:
        config.append(f'next-hop {next_hop}')
    if interface is not None:
        config.append(f'interface {interface}')
    if subinterface is not None:
        config.append(f'subinterface {subinterface}')
    if metric is not None:
        config.append(f'metric {metric}')
    if next_network_instance is not None:
        config.append(f'next-network-instance-name {next_network_instance}')
    if remote_label_stack is not None:
        labels = ' '.join(str(x) for x in remote_label_stack) \
            if isinstance(remote_label_stack, (list, tuple)) else remote_label_stack
        config.append(f'remote-label-stack [ {labels} ]')
    if bfd_destination_address is not None:
        config.append(f'bfd destination-address {bfd_destination_address}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure static-route {prefix} next-hop-index "
            f"{nh_index} on {device.name}. Error:\n{e}"
        )


def unconfigure_static_route_nexthop(device, prefix, nh_index,
                                     network_instance='default'):
    """Remove one next-hop-index from a static route.

    Args:
        device (obj): Device object
        prefix (str): Route prefix.
        nh_index (str): Next-hop name to remove, e.g. ``'nh2'``.
        network_instance (str, optional): Network instance. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the next-hop

    Example:
        >>> unconfigure_static_route_nexthop(
        ...     device, prefix='10.9.9.0/24', nh_index='nh2')
    """
    log.info(
        f"Removing static-route {prefix} next-hop-index {nh_index} on "
        f"{device.name}"
    )
    config = _static_route_ctx(prefix, network_instance)
    config += [f'no next-hop-index {nh_index}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove static-route {prefix} next-hop-index {nh_index} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_static_route_bfd_profile(device, prefix, profile,
                                       network_instance='default'):
    """Attach a BFD profile to a static route.

    adoc: Static_Routing.adoc:171-183. Pair this with
    ``configure_static_route_nexthop(..., bfd_destination_address=...)``, which
    sets the per-next-hop BFD peer.

    Args:
        device (obj): Device object
        prefix (str): Route prefix, e.g. ``'192.168.100.1/32'``.
        profile (str): BFD profile name, e.g. ``'GLOBAL'``.
        network_instance (str, optional): Network instance. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to attach the BFD profile

    Example:
        >>> configure_static_route_bfd_profile(
        ...     device, prefix='192.168.100.1/32', profile='GLOBAL')
    """
    log.info(f"Configuring static-route {prefix} bfd profile {profile} on {device.name}")
    config = _static_route_ctx(prefix, network_instance)
    config += [f'bfd profile {profile}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure static-route {prefix} bfd profile on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_static_route_bfd_profile(device, prefix,
                                         network_instance='default'):
    """Remove the BFD profile from a static route.

    Args:
        device (obj): Device object
        prefix (str): Route prefix.
        network_instance (str, optional): Network instance. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the BFD profile

    Example:
        >>> unconfigure_static_route_bfd_profile(device, prefix='192.168.100.1/32')
    """
    log.info(f"Removing static-route {prefix} bfd profile on {device.name}")
    config = _static_route_ctx(prefix, network_instance)
    config += ['no bfd profile', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove static-route {prefix} bfd profile on "
            f"{device.name}. Error:\n{e}"
        )
