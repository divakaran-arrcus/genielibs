"""Common configure functions for Segment Routing on ArcOS"""

import logging

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.segment_routing.get import (
    get_mpls_reserved_label_block,
)

log = logging.getLogger(__name__)


def configure_srv6_encap_source_address(device, source_address,
                                        network_instance='default'):
    """Configure SRv6 encapsulation source address.

    Args:
        device (obj): Device object.
        source_address (str): Source IPv6 address for SRv6 encapsulation.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRv6 encapsulation source
            address.

    Example:
        >>> configure_srv6_encap_source_address(
        ...     device=device,
        ...     source_address='2001:db8::1',
        ... )
    """
    ni = network_instance
    log.info(
        "Configuring SRv6 encapsulation source-address %s on %s "
        "(network-instance: %s)", source_address, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'srv6 encapsulation source-address {source_address}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRv6 encapsulation source-address "
            f"{source_address} on {device.name}. Error:\n{e}"
        )


def unconfigure_srv6_encap_source_address(device,
                                          network_instance='default'):
    """Remove SRv6 encapsulation source address.

    Args:
        device (obj): Device object.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRv6 encapsulation source
            address.

    Example:
        >>> unconfigure_srv6_encap_source_address(device=device)
    """
    ni = network_instance
    log.info(
        "Removing SRv6 encapsulation source-address on %s "
        "(network-instance: %s)", device.name, ni
    )

    config = [
        f'network-instance {ni}',
        'no srv6 encapsulation source-address',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRv6 encapsulation source-address on "
            f"{device.name}. Error:\n{e}"
        )


def configure_srv6_locator(device, locator_name, prefix, node_length,
                           func_length=None, algorithm=None,
                           network_instance='default'):
    """Configure an SRv6 locator.

    Args:
        device (obj): Device object.
        locator_name (str): Name of the SRv6 locator.
        prefix (str): IPv6 prefix for the locator (e.g., 'fcbb:bb00:1::/48').
        node_length (int): Locator node length in bits.
        func_length (int, optional): Function length in bits.
        algorithm (int, optional): Algorithm identifier.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRv6 locator.

    Example:
        >>> configure_srv6_locator(
        ...     device=device,
        ...     locator_name='loc1',
        ...     prefix='fcbb:bb00:1::/48',
        ...     node_length=24,
        ...     func_length=16,
        ...     algorithm=128,
        ... )
    """
    ni = network_instance
    log.info(
        "Configuring SRv6 locator %s on %s (network-instance: %s)",
        locator_name, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'srv6 locator {locator_name}',
        f'prefix {prefix}',
        f'locator-node-length {node_length}',
    ]

    if func_length is not None:
        config.append(f'function-length {func_length}')

    if algorithm is not None:
        config.append(f'algorithm {algorithm}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRv6 locator {locator_name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_srv6_locator(device, locator_name,
                             network_instance='default'):
    """Remove an SRv6 locator.

    Args:
        device (obj): Device object.
        locator_name (str): Name of the SRv6 locator to remove.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRv6 locator.

    Example:
        >>> unconfigure_srv6_locator(device=device, locator_name='loc1')
    """
    ni = network_instance
    log.info(
        "Removing SRv6 locator %s on %s (network-instance: %s)",
        locator_name, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'no srv6 locator {locator_name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRv6 locator {locator_name} on "
            f"{device.name}. Error:\n{e}"
        )


def configure_srv6_locator_micro_segment(device, locator_name, enabled=True,
                                         network_instance='default'):
    """Configure SRv6 locator micro-segment behavior unode.

    Args:
        device (obj): Device object.
        locator_name (str): Name of the SRv6 locator.
        enabled (bool, optional): Enable or disable micro-segment behavior.
            Defaults to True.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRv6 locator micro-segment.

    Example:
        >>> configure_srv6_locator_micro_segment(
        ...     device=device,
        ...     locator_name='loc1',
        ...     enabled=True,
        ... )
    """
    ni = network_instance
    value = "true" if enabled else "false"
    log.info(
        "Configuring SRv6 locator %s micro-segment-behavior-unode %s on %s "
        "(network-instance: %s)", locator_name, value, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'srv6 locator {locator_name}',
        f'micro-segment-behavior-unode {value}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRv6 locator {locator_name} "
            f"micro-segment-behavior-unode on {device.name}. Error:\n{e}"
        )


def unconfigure_srv6_locator_micro_segment(device, locator_name,
                                           network_instance='default'):
    """Remove SRv6 locator micro-segment behavior unode configuration.

    Args:
        device (obj): Device object.
        locator_name (str): Name of the SRv6 locator.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRv6 locator micro-segment
            configuration.

    Example:
        >>> unconfigure_srv6_locator_micro_segment(
        ...     device=device,
        ...     locator_name='loc1',
        ... )
    """
    ni = network_instance
    log.info(
        "Removing SRv6 locator %s micro-segment-behavior-unode on %s "
        "(network-instance: %s)", locator_name, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'srv6 locator {locator_name}',
        'no micro-segment-behavior-unode',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRv6 locator {locator_name} "
            f"micro-segment-behavior-unode on {device.name}. Error:\n{e}"
        )


def configure_mpls_reserved_label_block(device, block_id, lower_bound,
                                        upper_bound, usage,
                                        protocol_identifier,
                                        protocol_name=None,
                                        network_instance='default',
                                        verify=True):
    """Configure an MPLS reserved label block, then read it back.

    The read-back is not belt-and-braces -- it is the only thing that catches a
    rejected ``usage`` token. arcOS rejects an unknown enum value as ``syntax
    error: unknown element`` but still commits the surrounding block, so the
    block lands with lower-bound, upper-bound, protocol-identifier,
    protocol-name and NO usage leaf. ``device.configure()`` raises nothing, so
    the caller is told the block was configured when it was not. This shipped
    undetected: nightly build 1541 pushed the pre-migration ``usage SRGB`` to
    six routers, every leaf was rejected, and the suite reported 34/34 PASSED.

    Args:
        device (obj): Device object.
        block_id (str): Label block identifier.
        lower_bound (int): Lower bound of the label range.
        upper_bound (int): Upper bound of the label range.
        usage (str): Label block usage enum. arcOS spells these
            ``<PROTOCOL>_<ROLE>`` -- e.g. 'ISIS_SRGB', 'ISIS_SRLB',
            'BGP_SRGB'. The bare 'SRGB'/'SRLB' forms are NOT valid and are
            rejected leaf-only, as described above.
        protocol_identifier (str): Protocol identifier
            (e.g., 'ISIS', 'OSPF').
        protocol_name (str, optional): Protocol instance name.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.
        verify (bool, optional): Read the block back after configuring and
            fail if a leaf did not land. Defaults to True. Set False only
            where the read path is unavailable.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure MPLS reserved label block, or
            the block read back with a leaf that does not match what was sent.

    Example:
        >>> configure_mpls_reserved_label_block(
        ...     device=device,
        ...     block_id='SRGB_BLOCK',
        ...     lower_bound=16000,
        ...     upper_bound=23999,
        ...     usage='ISIS_SRGB',
        ...     protocol_identifier='ISIS',
        ...     protocol_name='default',
        ... )
    """
    ni = network_instance
    log.info(
        "Configuring MPLS reserved label block %s on %s "
        "(network-instance: %s)", block_id, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'mpls global reserved-label-block {block_id}',
        f'lower-bound {lower_bound}',
        f'upper-bound {upper_bound}',
        f'usage {usage}',
        f'protocol-identifier {protocol_identifier}',
    ]

    if protocol_name is not None:
        config.append(f'protocol-name {protocol_name}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure MPLS reserved label block {block_id} on "
            f"{device.name}. Error:\n{e}"
        )

    if verify:
        _assert_reserved_label_block_applied(
            device, block_id, lower_bound, upper_bound, usage, ni=ni,
        )


def _assert_reserved_label_block_applied(device, block_id, lower_bound,
                                         upper_bound, usage, ni='default'):
    """Raise if a just-configured block did not come back with what we sent.

    Only leaf-level mismatches raise. A ``None`` read-back is logged and let
    through on purpose: ``get_mpls_reserved_label_blocks`` returns ``{}`` both
    for "no blocks configured" and for any parse failure, so it cannot tell an
    absent block from an unreadable one. Raising there would convert a broken
    parser or an unsupported platform into a false red on a block that
    committed fine. A block we DID read is real evidence, and every leaf in it
    is fair game.
    """
    block = get_mpls_reserved_label_block(device, block_id, ni=ni)
    if not block:
        log.warning(
            "reserved-label-block %s on %s could not be read back "
            "(absent, or the read path is unavailable) -- leaf values "
            "unverified", block_id, device.name
        )
        return

    mismatches = []
    if block.get("lower-bound") != lower_bound:
        mismatches.append(
            f"lower-bound: sent {lower_bound!r}, read "
            f"{block.get('lower-bound')!r}"
        )
    if block.get("upper-bound") != upper_bound:
        mismatches.append(
            f"upper-bound: sent {upper_bound!r}, read "
            f"{block.get('upper-bound')!r}"
        )
    # arcOS renders the enum namespace-qualified (`arcos-mpls:ISIS_SRGB`);
    # an absent leaf is the rejected-token signature and reads as ''.
    actual_usage = str(block.get("usage") or "").split(":")[-1]
    if actual_usage != usage:
        mismatches.append(
            f"usage: sent {usage!r}, read {actual_usage or '<leaf absent>'!r}"
            " -- arcOS rejects an unknown usage enum leaf-only while still"
            " committing the block; valid tokens are spelled"
            " <PROTOCOL>_<ROLE>, e.g. ISIS_SRGB"
        )

    if mismatches:
        raise SubCommandFailure(
            f"MPLS reserved label block {block_id} on {device.name} committed "
            f"but did not apply as sent:\n  " + "\n  ".join(mismatches)
        )


def unconfigure_mpls_reserved_label_block(device, block_id,
                                          network_instance='default'):
    """Remove an MPLS reserved label block.

    Args:
        device (obj): Device object.
        block_id (str): Label block identifier to remove.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove MPLS reserved label block.

    Example:
        >>> unconfigure_mpls_reserved_label_block(
        ...     device=device,
        ...     block_id='SRGB_BLOCK',
        ... )
    """
    ni = network_instance
    log.info(
        "Removing MPLS reserved label block %s on %s "
        "(network-instance: %s)", block_id, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'no mpls global reserved-label-block {block_id}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove MPLS reserved label block {block_id} on "
            f"{device.name}. Error:\n{e}"
        )


def configure_srms_mapping(device, mapping_id,
                           network_instance='default'):
    """Configure an SRMS (Segment Routing Mapping Server) mapping entry.

    The mapping_id serves as both the name and local-id for the mapping.

    Args:
        device (obj): Device object.
        mapping_id (str): Mapping identifier (used as local-id on device).
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRMS mapping.

    Example:
        >>> configure_srms_mapping(device=device, mapping_id='map1')
    """
    ni = network_instance
    log.info(
        "Configuring SRMS mapping %s on %s (network-instance: %s)",
        mapping_id, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'segment-routing srms mapping {mapping_id}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRMS mapping {mapping_id} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_srms_mapping(device, mapping_id,
                             network_instance='default'):
    """Remove an SRMS mapping entry.

    Args:
        device (obj): Device object.
        mapping_id (str): Mapping identifier to remove.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRMS mapping.

    Example:
        >>> unconfigure_srms_mapping(device=device, mapping_id='map1')
    """
    ni = network_instance
    log.info(
        "Removing SRMS mapping %s on %s (network-instance: %s)",
        mapping_id, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'no segment-routing srms mapping {mapping_id}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRMS mapping {mapping_id} on "
            f"{device.name}. Error:\n{e}"
        )


def configure_srms_mapping_ipv4_prefix(device, mapping_id, prefix, sid,
                                       range_val,
                                       network_instance='default'):
    """Configure an IPv4 prefix for an SRMS mapping.

    Args:
        device (obj): Device object.
        mapping_id (str): Mapping identifier.
        prefix (str): IPv4 prefix (e.g., '10.0.0.0/24').
        sid (int): Segment Identifier value.
        range_val (int): Number of SIDs in the range.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRMS mapping IPv4 prefix.

    Example:
        >>> configure_srms_mapping_ipv4_prefix(
        ...     device=device,
        ...     mapping_id='map1',
        ...     prefix='10.0.0.0/24',
        ...     sid=16000,
        ...     range_val=100,
        ... )
    """
    ni = network_instance
    log.info(
        "Configuring SRMS mapping %s IPv4 prefix %s on %s "
        "(network-instance: %s)", mapping_id, prefix, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'segment-routing srms mapping {mapping_id}',
        f'ipv4 prefix {prefix}',
        f'sid {sid}',
        f'range {range_val}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRMS mapping {mapping_id} IPv4 prefix "
            f"{prefix} on {device.name}. Error:\n{e}"
        )


def unconfigure_srms_mapping_ipv4_prefix(device, mapping_id, prefix,
                                         network_instance='default'):
    """Remove an IPv4 prefix from an SRMS mapping.

    Args:
        device (obj): Device object.
        mapping_id (str): Mapping identifier.
        prefix (str): IPv4 prefix to remove (e.g., '10.0.0.0/24').
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRMS mapping IPv4 prefix.

    Example:
        >>> unconfigure_srms_mapping_ipv4_prefix(
        ...     device=device,
        ...     mapping_id='map1',
        ...     prefix='10.0.0.0/24',
        ... )
    """
    ni = network_instance
    log.info(
        "Removing SRMS mapping %s IPv4 prefix %s on %s "
        "(network-instance: %s)", mapping_id, prefix, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'segment-routing srms mapping {mapping_id}',
        f'no ipv4 prefix {prefix}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRMS mapping {mapping_id} IPv4 prefix "
            f"{prefix} on {device.name}. Error:\n{e}"
        )


def configure_srms_mapping_ipv6_prefix(device, mapping_id, prefix, sid,
                                       range_val,
                                       network_instance='default'):
    """Configure an IPv6 prefix for an SRMS mapping.

    Args:
        device (obj): Device object.
        mapping_id (str): Mapping identifier.
        prefix (str): IPv6 prefix (e.g., '2001:db8::/32').
        sid (int): Segment Identifier value.
        range_val (int): Number of SIDs in the range.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRMS mapping IPv6 prefix.

    Example:
        >>> configure_srms_mapping_ipv6_prefix(
        ...     device=device,
        ...     mapping_id='map1',
        ...     prefix='2001:db8::/32',
        ...     sid=17000,
        ...     range_val=100,
        ... )
    """
    ni = network_instance
    log.info(
        "Configuring SRMS mapping %s IPv6 prefix %s on %s "
        "(network-instance: %s)", mapping_id, prefix, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'segment-routing srms mapping {mapping_id}',
        f'ipv6 prefix {prefix}',
        f'sid {sid}',
        f'range {range_val}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRMS mapping {mapping_id} IPv6 prefix "
            f"{prefix} on {device.name}. Error:\n{e}"
        )


def unconfigure_srms_mapping_ipv6_prefix(device, mapping_id, prefix,
                                         network_instance='default'):
    """Remove an IPv6 prefix from an SRMS mapping.

    Args:
        device (obj): Device object.
        mapping_id (str): Mapping identifier.
        prefix (str): IPv6 prefix to remove (e.g., '2001:db8::/32').
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRMS mapping IPv6 prefix.

    Example:
        >>> unconfigure_srms_mapping_ipv6_prefix(
        ...     device=device,
        ...     mapping_id='map1',
        ...     prefix='2001:db8::/32',
        ... )
    """
    ni = network_instance
    log.info(
        "Removing SRMS mapping %s IPv6 prefix %s on %s "
        "(network-instance: %s)", mapping_id, prefix, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'segment-routing srms mapping {mapping_id}',
        f'no ipv6 prefix {prefix}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRMS mapping {mapping_id} IPv6 prefix "
            f"{prefix} on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# SRv6 Encapsulation — ip-ttl-propagation
# ---------------------------------------------------------------------------

def configure_srv6_encap_ip_ttl_propagation(device, enabled=True,
                                            network_instance='default'):
    """Configure SRv6 encapsulation ip-ttl-propagation.

    When enabled, the hop-limit/TTL value of the inner packet is copied
    into the hop-limit field of the encapsulating IPv6 header.
    ip-ttl-propagation takes precedence over hop-limit — enabling it
    removes any existing hop-limit configuration.

    Args:
        device (obj): Device object.
        enabled (bool, optional): Enable or disable ip-ttl-propagation.
            Defaults to True.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRv6 encapsulation
            ip-ttl-propagation.

    Example:
        >>> configure_srv6_encap_ip_ttl_propagation(device=device)
    """
    ni = network_instance
    value = "true" if enabled else "false"
    log.info(
        "Configuring SRv6 encapsulation ip-ttl-propagation %s on %s "
        "(network-instance: %s)", value, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'srv6 encapsulation ip-ttl-propagation {value}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRv6 encapsulation ip-ttl-propagation "
            f"{value} on {device.name}. Error:\n{e}"
        )


def unconfigure_srv6_encap_ip_ttl_propagation(device,
                                              network_instance='default'):
    """Remove SRv6 encapsulation ip-ttl-propagation configuration.

    Args:
        device (obj): Device object.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRv6 encapsulation
            ip-ttl-propagation.

    Example:
        >>> unconfigure_srv6_encap_ip_ttl_propagation(device=device)
    """
    ni = network_instance
    log.info(
        "Removing SRv6 encapsulation ip-ttl-propagation on %s "
        "(network-instance: %s)", device.name, ni
    )

    config = [
        f'network-instance {ni}',
        'no srv6 encapsulation ip-ttl-propagation',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRv6 encapsulation ip-ttl-propagation on "
            f"{device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# SRv6 Encapsulation — hop-limit
# ---------------------------------------------------------------------------

def configure_srv6_encap_hop_limit(device, hop_limit,
                                   network_instance='default'):
    """Configure SRv6 encapsulation hop-limit.

    Sets the hop-limit field of the encapsulating IPv6 header.
    ip-ttl-propagation must be false (or unconfigured) before setting
    hop-limit.

    Args:
        device (obj): Device object.
        hop_limit (int): Hop-limit value (1-255).
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SRv6 encapsulation
            hop-limit.

    Example:
        >>> configure_srv6_encap_hop_limit(device=device, hop_limit=15)
    """
    ni = network_instance
    log.info(
        "Configuring SRv6 encapsulation hop-limit %s on %s "
        "(network-instance: %s)", hop_limit, device.name, ni
    )

    config = [
        f'network-instance {ni}',
        f'srv6 encapsulation hop-limit {hop_limit}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SRv6 encapsulation hop-limit "
            f"{hop_limit} on {device.name}. Error:\n{e}"
        )


def unconfigure_srv6_encap_hop_limit(device, network_instance='default'):
    """Remove SRv6 encapsulation hop-limit configuration.

    Args:
        device (obj): Device object.
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove SRv6 encapsulation hop-limit.

    Example:
        >>> unconfigure_srv6_encap_hop_limit(device=device)
    """
    ni = network_instance
    log.info(
        "Removing SRv6 encapsulation hop-limit on %s "
        "(network-instance: %s)", device.name, ni
    )

    config = [
        f'network-instance {ni}',
        'no srv6 encapsulation hop-limit',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SRv6 encapsulation hop-limit on "
            f"{device.name}. Error:\n{e}"
        )
