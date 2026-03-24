"""Common configure functions for BGP on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _build_bgp_config_context(network_instance='default', protocol_instance='default'):
    """Helper function to build BGP configuration context path.

    Args:
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        str: Configuration context path for BGP

    Example:
        >>> _build_bgp_config_context('default', 'default')
        'network-instance default protocol BGP default'
    """
    return f'network-instance {network_instance} protocol BGP {protocol_instance}'


def _build_neighbor_context(neighbor, network_instance='default', protocol_instance='default'):
    """Helper function to build BGP neighbor configuration context path.

    Args:
        neighbor (str): Neighbor address
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        str: Configuration context path for BGP neighbor

    Example:
        >>> _build_neighbor_context('10.0.0.1', 'default', 'default')
        'network-instance default protocol BGP default neighbor 10.0.0.1'
    """
    return f'{_build_bgp_config_context(network_instance, protocol_instance)} neighbor {neighbor}'


def _build_peer_group_context(peer_group, network_instance='default', protocol_instance='default'):
    """Helper function to build BGP peer-group configuration context path.

    Args:
        peer_group (str): Peer-group name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        str: Configuration context path for BGP peer-group

    Example:
        >>> _build_peer_group_context('SPINE', 'default', 'default')
        'network-instance default protocol BGP default peer-group SPINE'
    """
    return f'{_build_bgp_config_context(network_instance, protocol_instance)} peer-group {peer_group}'


# ===========================================================================
# Global Configure APIs
# ===========================================================================

def configure_bgp_instance(device, network_instance='default', protocol_instance='default'):
    """Create BGP protocol instance.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to create BGP instance
    """
    log.info(
        f"Creating BGP instance on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    config = [
        _build_bgp_config_context(network_instance, protocol_instance),
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not create BGP instance on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_instance(device, network_instance='default', protocol_instance='default'):
    """Remove entire BGP protocol instance.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP instance
    """
    log.info(
        f"Removing BGP instance from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    config = [
        f'no {_build_bgp_config_context(network_instance, protocol_instance)}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP instance from {device.name}. Error:\n{e}"
        )


def configure_bgp_as_number(device, as_number, network_instance='default',
                             protocol_instance='default'):
    """Configure BGP autonomous system number.

    Args:
        device (obj): Device object
        as_number (int): BGP AS number (e.g., 65001)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP AS number
    """
    log.info(f"Configuring BGP AS {as_number} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global as {as_number}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP AS {as_number} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_as_number(device, network_instance='default',
                               protocol_instance='default'):
    """Remove BGP autonomous system number.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP AS number
    """
    log.info(f"Removing BGP AS number from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'no global as',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP AS number from {device.name}. Error:\n{e}"
        )


def configure_bgp_router_id(device, router_id, network_instance='default',
                              protocol_instance='default'):
    """Configure BGP router-id.

    Args:
        device (obj): Device object
        router_id (str): Router-id (e.g., '1.0.0.0')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP router-id
    """
    log.info(f"Configuring BGP router-id {router_id} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global router-id {router_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP router-id {router_id} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_router_id(device, network_instance='default',
                                protocol_instance='default'):
    """Remove BGP router-id.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP router-id
    """
    log.info(f"Removing BGP router-id from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'no global router-id',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP router-id from {device.name}. Error:\n{e}"
        )


def configure_bgp_global_afi_safi(device, afi_safi, network_instance='default',
                                   protocol_instance='default'):
    """Configure BGP global AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST', 'L2VPN_EVPN')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP global AFI-SAFI
    """
    log.info(f"Configuring BGP global AFI-SAFI {afi_safi} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP global AFI-SAFI {afi_safi} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_global_afi_safi(device, afi_safi, network_instance='default',
                                     protocol_instance='default'):
    """Remove BGP global AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST', 'L2VPN_EVPN')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP global AFI-SAFI
    """
    log.info(f"Removing BGP global AFI-SAFI {afi_safi} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'no global afi-safi {afi_safi}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP global AFI-SAFI {afi_safi} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_maximum_paths(device, afi_safi, maximum_paths,
                                 network_instance='default',
                                 protocol_instance='default'):
    """Configure BGP maximum paths (IBGP ECMP) for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        maximum_paths (int): Maximum number of IBGP paths
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP maximum paths
    """
    log.info(
        f"Configuring BGP maximum-paths {maximum_paths} for {afi_safi} on {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'use-maximum-paths ibgp maximum-paths {maximum_paths}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP maximum-paths for {afi_safi} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_maximum_paths(device, afi_safi, network_instance='default',
                                    protocol_instance='default'):
    """Remove BGP maximum paths for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP maximum paths
    """
    log.info(f"Removing BGP maximum-paths for {afi_safi} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        'no use-maximum-paths ibgp maximum-paths',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP maximum-paths for {afi_safi} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_network(device, afi_safi, prefix, network_instance='default',
                            protocol_instance='default'):
    """Configure BGP network advertisement for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        prefix (str): Network prefix to advertise (e.g., '10.0.0.0/24')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP network
    """
    log.info(f"Configuring BGP network {prefix} for {afi_safi} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'network {prefix}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP network {prefix} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_network(device, afi_safi, prefix, network_instance='default',
                              protocol_instance='default'):
    """Remove BGP network advertisement for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        prefix (str): Network prefix to remove (e.g., '10.0.0.0/24')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP network
    """
    log.info(f"Removing BGP network {prefix} for {afi_safi} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'no network {prefix}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP network {prefix} from {device.name}. Error:\n{e}"
        )


def configure_bgp_aggregate_address(device, afi_safi, prefix,
                                      summary_only=None,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Configure BGP aggregate address for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        prefix (str): Aggregate prefix (e.g., '10.0.0.0/8')
        summary_only (bool, optional): Enable summary-only mode. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP aggregate address
    """
    log.info(f"Configuring BGP aggregate-address {prefix} for {afi_safi} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'aggregate-address {prefix}',
    ]

    if summary_only is not None:
        val = 'true' if summary_only else 'false'
        config.append(f'summary-only {val}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP aggregate-address {prefix} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_aggregate_address(device, afi_safi, prefix,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Remove BGP aggregate address for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        prefix (str): Aggregate prefix to remove (e.g., '10.0.0.0/8')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP aggregate address
    """
    log.info(f"Removing BGP aggregate-address {prefix} for {afi_safi} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'no aggregate-address {prefix}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP aggregate-address {prefix} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_adj_rib_out_post(device, enabled=True, network_instance='default',
                                     protocol_instance='default'):
    """Configure BGP adj-rib-out-post.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable adj-rib-out-post. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP adj-rib-out-post
    """
    val = 'true' if enabled else 'false'
    log.info(f"Configuring BGP adj-rib-out-post {val} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global adj-rib-out-post {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP adj-rib-out-post on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_adj_rib_out_post(device, network_instance='default',
                                       protocol_instance='default'):
    """Remove BGP adj-rib-out-post configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP adj-rib-out-post
    """
    log.info(f"Removing BGP adj-rib-out-post from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'no global adj-rib-out-post',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP adj-rib-out-post from {device.name}. Error:\n{e}"
        )


def configure_bgp_label_allocation_mode(device, mode, network_instance='default',
                                          protocol_instance='default'):
    """Configure BGP label allocation mode.

    Args:
        device (obj): Device object
        mode (str): Label allocation mode (e.g., 'INSTANCE_LABEL')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP label allocation mode
    """
    log.info(f"Configuring BGP label-allocation-mode {mode} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global label-allocation-mode {mode}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP label-allocation-mode on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_label_allocation_mode(device, network_instance='default',
                                            protocol_instance='default'):
    """Remove BGP label allocation mode.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP label allocation mode
    """
    log.info(f"Removing BGP label-allocation-mode from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'no global label-allocation-mode',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP label-allocation-mode from {device.name}. Error:\n{e}"
        )


def configure_bgp_segment_routing(device, enabled=True, network_instance='default',
                                    protocol_instance='default'):
    """Configure BGP segment routing.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable segment routing. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP segment routing
    """
    val = 'true' if enabled else 'false'
    log.info(f"Configuring BGP segment-routing enabled {val} on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global segment-routing enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP segment-routing on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_segment_routing(device, network_instance='default',
                                      protocol_instance='default'):
    """Remove BGP segment routing configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP segment routing
    """
    log.info(f"Removing BGP segment-routing from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'no global segment-routing enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP segment-routing from {device.name}. Error:\n{e}"
        )


# ===========================================================================
# Neighbor Configure APIs
# ===========================================================================

def configure_bgp_neighbor(device, neighbor, peer_as, network_instance='default',
                            protocol_instance='default'):
    """Configure a BGP neighbor with peer AS.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address (e.g., '10.0.0.1')
        peer_as (int): Peer AS number
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor
    """
    log.info(f"Configuring BGP neighbor {neighbor} peer-as {peer_as} on {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'peer-as {peer_as}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor(device, neighbor, network_instance='default',
                               protocol_instance='default'):
    """Remove a BGP neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address (e.g., '10.0.0.1')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor
    """
    log.info(f"Removing BGP neighbor {neighbor} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'no neighbor {neighbor}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} from {device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_description(device, neighbor, description,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure BGP neighbor description.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        description (str): Description string
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor description
    """
    log.info(f"Configuring BGP neighbor {neighbor} description on {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'description "{description}"',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} description on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_description(device, neighbor,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Remove BGP neighbor description.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor description
    """
    log.info(f"Removing BGP neighbor {neighbor} description from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        'no description',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} description from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_shutdown(device, neighbor, shutdown=True,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Configure BGP neighbor shutdown state.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        shutdown (bool, optional): Shutdown state. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor shutdown
    """
    val = 'true' if shutdown else 'false'
    log.info(f"Configuring BGP neighbor {neighbor} shutdown {val} on {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'shutdown {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} shutdown on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_shutdown(device, neighbor,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Remove BGP neighbor shutdown configuration (re-enable).

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor shutdown
    """
    log.info(f"Removing BGP neighbor {neighbor} shutdown from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        'no shutdown',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} shutdown from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_bfd(device, neighbor, enabled=True, profile=None,
                                 network_instance='default',
                                 protocol_instance='default'):
    """Configure BGP neighbor BFD.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        enabled (bool, optional): Enable BFD. Defaults to True.
        profile (str, optional): BFD profile name. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor BFD
    """
    val = 'true' if enabled else 'false'
    log.info(f"Configuring BGP neighbor {neighbor} BFD enabled {val} on {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context]
    config.append(f'bfd enable {val}')

    if profile is not None:
        config.append(f'bfd profile {profile}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} BFD on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_bfd(device, neighbor, network_instance='default',
                                   protocol_instance='default'):
    """Remove BGP neighbor BFD configuration.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor BFD
    """
    log.info(f"Removing BGP neighbor {neighbor} BFD from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        'no bfd enable',
        'no bfd profile',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} BFD from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_afi_safi(device, neighbor, afi_safi,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Configure BGP neighbor AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor AFI-SAFI
    """
    log.info(f"Configuring BGP neighbor {neighbor} AFI-SAFI {afi_safi} on {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} AFI-SAFI {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_afi_safi(device, neighbor, afi_safi,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Remove BGP neighbor AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor AFI-SAFI
    """
    log.info(f"Removing BGP neighbor {neighbor} AFI-SAFI {afi_safi} from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'no afi-safi {afi_safi}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} AFI-SAFI {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_transport(device, neighbor, local_address,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure BGP neighbor transport local-address.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        local_address (str): Local address for BGP transport
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor transport
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} transport local-address "
        f"{local_address} on {device.name}"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'transport local-address {local_address}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} transport on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_transport(device, neighbor,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Remove BGP neighbor transport local-address.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor transport
    """
    log.info(f"Removing BGP neighbor {neighbor} transport from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        'no transport local-address',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} transport from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_import_policy(device, neighbor, afi_safi, policies,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure BGP neighbor import policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        policies (list or str): Policy name(s) to apply as import
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor import policy
    """
    log.info(f"Configuring BGP neighbor {neighbor} import-policy on {device.name}")

    if isinstance(policies, (list, tuple)):
        pol_str = ' '.join(str(p) for p in policies)
    else:
        pol_str = str(policies)

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        f'apply-policy import-policy [ {pol_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} import-policy on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_import_policy(device, neighbor, afi_safi,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove BGP neighbor import policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor import policy
    """
    log.info(f"Removing BGP neighbor {neighbor} import-policy from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        'no apply-policy import-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} import-policy from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_export_policy(device, neighbor, afi_safi, policies,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure BGP neighbor export policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        policies (list or str): Policy name(s) to apply as export
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor export policy
    """
    log.info(f"Configuring BGP neighbor {neighbor} export-policy on {device.name}")

    if isinstance(policies, (list, tuple)):
        pol_str = ' '.join(str(p) for p in policies)
    else:
        pol_str = str(policies)

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        f'apply-policy export-policy [ {pol_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} export-policy on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_export_policy(device, neighbor, afi_safi,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove BGP neighbor export policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor export policy
    """
    log.info(f"Removing BGP neighbor {neighbor} export-policy from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        'no apply-policy export-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} export-policy from "
            f"{device.name}. Error:\n{e}"
        )


# ===========================================================================
# Peer-Group Configure APIs
# ===========================================================================

def configure_bgp_peer_group(device, peer_group, peer_as=None,
                               network_instance='default',
                               protocol_instance='default'):
    """Configure a BGP peer-group.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        peer_as (int, optional): Peer AS for the group. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP peer-group
    """
    log.info(f"Configuring BGP peer-group {peer_group} on {device.name}")

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [pg_context]

    if peer_as is not None:
        config.append(f'peer-as {peer_as}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP peer-group {peer_group} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_peer_group(device, peer_group, network_instance='default',
                                 protocol_instance='default'):
    """Remove a BGP peer-group.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP peer-group
    """
    log.info(f"Removing BGP peer-group {peer_group} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'no peer-group {peer_group}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP peer-group {peer_group} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_peer_group_bfd(device, peer_group, enabled=True, profile=None,
                                   network_instance='default',
                                   protocol_instance='default'):
    """Configure BGP peer-group BFD.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        enabled (bool, optional): Enable BFD. Defaults to True.
        profile (str, optional): BFD profile name. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP peer-group BFD
    """
    val = 'true' if enabled else 'false'
    log.info(f"Configuring BGP peer-group {peer_group} BFD enabled {val} on {device.name}")

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [pg_context]
    config.append(f'bfd enable {val}')

    if profile is not None:
        config.append(f'bfd profile {profile}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP peer-group {peer_group} BFD on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_peer_group_bfd(device, peer_group, network_instance='default',
                                     protocol_instance='default'):
    """Remove BGP peer-group BFD configuration.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP peer-group BFD
    """
    log.info(f"Removing BGP peer-group {peer_group} BFD from {device.name}")

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        'no bfd enable',
        'no bfd profile',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP peer-group {peer_group} BFD from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_peer_group_afi_safi(device, peer_group, afi_safi,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure BGP peer-group AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP peer-group AFI-SAFI
    """
    log.info(
        f"Configuring BGP peer-group {peer_group} AFI-SAFI {afi_safi} on {device.name}"
    )

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'afi-safi {afi_safi}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP peer-group {peer_group} AFI-SAFI {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_peer_group_afi_safi(device, peer_group, afi_safi,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove BGP peer-group AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP peer-group AFI-SAFI
    """
    log.info(
        f"Removing BGP peer-group {peer_group} AFI-SAFI {afi_safi} from {device.name}"
    )

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'no afi-safi {afi_safi}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP peer-group {peer_group} AFI-SAFI {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_peer_group(device, neighbor, peer_group,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Assign a BGP neighbor to a peer-group.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        peer_group (str): Peer-group name to assign
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to assign BGP neighbor to peer-group
    """
    log.info(
        f"Assigning BGP neighbor {neighbor} to peer-group {peer_group} on {device.name}"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'peer-group {peer_group}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not assign BGP neighbor {neighbor} to peer-group {peer_group} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_peer_group(device, neighbor,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove BGP neighbor peer-group assignment.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor peer-group
    """
    log.info(f"Removing BGP neighbor {neighbor} peer-group from {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        'no peer-group',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} peer-group from "
            f"{device.name}. Error:\n{e}"
        )


# ===========================================================================
# Global AFI-SAFI Feature APIs
# ===========================================================================


def configure_bgp_add_paths_calculate(device, afi_safi, calculate,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure BGP add-paths calculate mode for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        calculate (str): Calculate mode (e.g., 'MULTIPATHS', 'ALL')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP add-paths calculate

    Example:
        >>> configure_bgp_add_paths_calculate(device, 'IPV4_UNICAST', 'MULTIPATHS')
    """
    log.info(
        f"Configuring BGP add-paths calculate {calculate} for {afi_safi} on {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'add-paths calculate {calculate}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP add-paths calculate for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_add_paths_calculate(device, afi_safi,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove BGP add-paths calculate mode for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP add-paths calculate
    """
    log.info(f"Removing BGP add-paths calculate for {afi_safi} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        'no add-paths calculate',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP add-paths calculate for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_null_label(device, afi_safi, label_mode,
                              network_instance='default',
                              protocol_instance='default'):
    """Configure BGP null-label mode for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV6_LABELED_UNICAST')
        label_mode (str): Null-label mode (e.g., 'EXPLICIT')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP null-label

    Example:
        >>> configure_bgp_null_label(device, 'IPV6_LABELED_UNICAST', 'EXPLICIT')
    """
    log.info(
        f"Configuring BGP null-label {label_mode} for {afi_safi} on {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'null-label {label_mode}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP null-label for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_null_label(device, afi_safi,
                                network_instance='default',
                                protocol_instance='default'):
    """Remove BGP null-label mode for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV6_LABELED_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP null-label
    """
    log.info(f"Removing BGP null-label for {afi_safi} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        'no null-label',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP null-label for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_rtfilter(device, afi_safi, enabled=True,
                            network_instance='default',
                            protocol_instance='default'):
    """Configure BGP rtfilter for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'L3VPN_IPV4_UNICAST')
        enabled (bool, optional): Enable rtfilter. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP rtfilter

    Example:
        >>> configure_bgp_rtfilter(device, 'L3VPN_IPV4_UNICAST')
    """
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring BGP rtfilter enabled {val} for {afi_safi} on {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'rtfilter enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP rtfilter for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_rtfilter(device, afi_safi,
                              network_instance='default',
                              protocol_instance='default'):
    """Remove BGP rtfilter for an AFI-SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'L3VPN_IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP rtfilter
    """
    log.info(f"Removing BGP rtfilter for {afi_safi} from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        'no rtfilter',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP rtfilter for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


# ===========================================================================
# Global Route-Selection and Compatibility APIs
# ===========================================================================


def configure_bgp_ignore_next_hop_igp_metric(device, enabled=True,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Configure BGP ignore-next-hop-igp-metric.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable ignore-next-hop-igp-metric. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP ignore-next-hop-igp-metric

    Example:
        >>> configure_bgp_ignore_next_hop_igp_metric(device)
    """
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring BGP ignore-next-hop-igp-metric {val} on {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global route-selection-options ignore-next-hop-igp-metric {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP ignore-next-hop-igp-metric on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_ignore_next_hop_igp_metric(device,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Remove BGP ignore-next-hop-igp-metric.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP ignore-next-hop-igp-metric
    """
    log.info(f"Removing BGP ignore-next-hop-igp-metric from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'global no route-selection-options ignore-next-hop-igp-metric',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP ignore-next-hop-igp-metric from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_drop_upon_invalid_sr_policy(device, enabled=True,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure BGP drop-upon-invalid-sr-policy.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable drop-upon-invalid-sr-policy. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP drop-upon-invalid-sr-policy

    Example:
        >>> configure_bgp_drop_upon_invalid_sr_policy(device)
    """
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring BGP drop-upon-invalid-sr-policy {val} on {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global drop-upon-invalid-sr-policy {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP drop-upon-invalid-sr-policy on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_drop_upon_invalid_sr_policy(device,
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Remove BGP drop-upon-invalid-sr-policy.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP drop-upon-invalid-sr-policy
    """
    log.info(f"Removing BGP drop-upon-invalid-sr-policy from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'global no drop-upon-invalid-sr-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP drop-upon-invalid-sr-policy from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_compatibility_l2_attr_local(device, enabled=True,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure BGP compatibility l2-attr-local.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable l2-attr-local. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP compatibility l2-attr-local

    Example:
        >>> configure_bgp_compatibility_l2_attr_local(device)
    """
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring BGP compatibility l2-attr-local {val} on {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global compatibility l2-attr-local {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP compatibility l2-attr-local on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_compatibility_l2_attr_local(device,
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Remove BGP compatibility l2-attr-local.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP compatibility l2-attr-local
    """
    log.info(f"Removing BGP compatibility l2-attr-local from {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'global no compatibility l2-attr-local',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP compatibility l2-attr-local from "
            f"{device.name}. Error:\n{e}"
        )


# ===========================================================================
# Neighbor / Peer-Group Add-Paths APIs
# ===========================================================================


def configure_bgp_neighbor_add_paths(device, neighbor, afi_safi,
                                      send=None, receive=None,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Configure BGP neighbor add-paths send/receive for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address (IPv4 or IPv6)
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_LABELED_UNICAST')
        send (str or bool, optional): Send mode — 'BACKUP', 'ALL', True/False. Defaults to None.
        receive (bool, optional): Enable add-paths receive. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor add-paths

    Example:
        >>> configure_bgp_neighbor_add_paths(device, '3.0.0.0', 'IPV4_LABELED_UNICAST',
        ...                                   send='BACKUP', receive=True)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} add-paths for {afi_safi} on {device.name}"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
    ]

    if send is not None:
        if isinstance(send, bool):
            val = 'true' if send else 'false'
        else:
            val = str(send)
        config.append(f'add-paths send {val}')

    if receive is not None:
        val = 'true' if receive else 'false'
        config.append(f'add-paths receive {val}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} add-paths for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_add_paths(device, neighbor, afi_safi,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Remove BGP neighbor add-paths for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address (IPv4 or IPv6)
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_LABELED_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor add-paths
    """
    log.info(
        f"Removing BGP neighbor {neighbor} add-paths for {afi_safi} from {device.name}"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        'no add-paths',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} add-paths for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_peer_group_add_paths(device, peer_group, afi_safi,
                                         send=None, receive=None,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure BGP peer-group add-paths send/receive for an AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_LABELED_UNICAST')
        send (str or bool, optional): Send mode — 'BACKUP', 'ALL', True/False. Defaults to None.
        receive (bool, optional): Enable add-paths receive. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP peer-group add-paths

    Example:
        >>> configure_bgp_peer_group_add_paths(device, 'RR-Peer-Group',
        ...     'L3VPN_IPV4_UNICAST', send='ALL', receive=True)
    """
    log.info(
        f"Configuring BGP peer-group {peer_group} add-paths for {afi_safi} on {device.name}"
    )

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'afi-safi {afi_safi}',
    ]

    if send is not None:
        if isinstance(send, bool):
            val = 'true' if send else 'false'
        else:
            val = str(send)
        config.append(f'add-paths send {val}')

    if receive is not None:
        val = 'true' if receive else 'false'
        config.append(f'add-paths receive {val}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP peer-group {peer_group} add-paths for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_peer_group_add_paths(device, peer_group, afi_safi,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Remove BGP peer-group add-paths for an AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_LABELED_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP peer-group add-paths
    """
    log.info(
        f"Removing BGP peer-group {peer_group} add-paths for {afi_safi} from {device.name}"
    )

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'afi-safi {afi_safi}',
        'no add-paths',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP peer-group {peer_group} add-paths for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


# ===========================================================================
# Peer-Group Policy APIs
# ===========================================================================


def configure_bgp_peer_group_import_policy(device, peer_group, afi_safi, policies,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure BGP peer-group import policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        policies (list or str): Import policy name(s)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP peer-group import policy

    Example:
        >>> configure_bgp_peer_group_import_policy(device, 'access_v4_peer_grp',
        ...     'IPV4_UNICAST', ['accept_all'])
    """
    log.info(
        f"Configuring BGP peer-group {peer_group} import-policy for {afi_safi} on {device.name}"
    )

    if isinstance(policies, (list, tuple)):
        pol_str = ' '.join(str(p) for p in policies)
    else:
        pol_str = str(policies)

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'afi-safi {afi_safi}',
        f'apply-policy import-policy [ {pol_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP peer-group {peer_group} import-policy for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_peer_group_import_policy(device, peer_group, afi_safi,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Remove BGP peer-group import policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP peer-group import policy
    """
    log.info(
        f"Removing BGP peer-group {peer_group} import-policy for {afi_safi} from {device.name}"
    )

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'afi-safi {afi_safi}',
        'no apply-policy import-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP peer-group {peer_group} import-policy for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_peer_group_export_policy(device, peer_group, afi_safi, policies,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure BGP peer-group export policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        policies (list or str): Export policy name(s)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP peer-group export policy

    Example:
        >>> configure_bgp_peer_group_export_policy(device, 'RR-Peer-Group',
        ...     'IPV4_UNICAST', ['ALLOW-ALL'])
    """
    log.info(
        f"Configuring BGP peer-group {peer_group} export-policy for {afi_safi} on {device.name}"
    )

    if isinstance(policies, (list, tuple)):
        pol_str = ' '.join(str(p) for p in policies)
    else:
        pol_str = str(policies)

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'afi-safi {afi_safi}',
        f'apply-policy export-policy [ {pol_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP peer-group {peer_group} export-policy for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_peer_group_export_policy(device, peer_group, afi_safi,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Remove BGP peer-group export policy for an AFI-SAFI.

    Args:
        device (obj): Device object
        peer_group (str): Peer-group name
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP peer-group export policy
    """
    log.info(
        f"Removing BGP peer-group {peer_group} export-policy for {afi_safi} from {device.name}"
    )

    pg_context = _build_peer_group_context(peer_group, network_instance, protocol_instance)
    config = [
        pg_context,
        f'afi-safi {afi_safi}',
        'no apply-policy export-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP peer-group {peer_group} export-policy for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )
