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


# ===========================================================================
# BGP VRF Configure APIs (route-distinguisher, route-target, rt-afi-safi)
# ===========================================================================

def configure_bgp_route_distinguisher(device, rd, network_instance='default',
                                        protocol_instance='default'):
    """Configure BGP route-distinguisher for a network instance.

    Args:
        device (obj): Device object
        rd (str): Route distinguisher (e.g., '1.0.0.0:2001')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP route-distinguisher

    Example:
        >>> configure_bgp_route_distinguisher(device, '1.0.0.0:2001',
        ...     network_instance='ECMP-L3VPN-01')
    """
    log.info(
        f"Configuring BGP route-distinguisher {rd} on {device.name} "
        f"(network-instance: {network_instance})"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global route-distinguisher {rd}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP route-distinguisher {rd} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_route_distinguisher(device, network_instance='default',
                                          protocol_instance='default'):
    """Remove BGP route-distinguisher from a network instance.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP route-distinguisher

    Example:
        >>> unconfigure_bgp_route_distinguisher(device,
        ...     network_instance='ECMP-L3VPN-01')
    """
    log.info(
        f"Removing BGP route-distinguisher from {device.name} "
        f"(network-instance: {network_instance})"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'no global route-distinguisher',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP route-distinguisher from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_route_target(device, rt, rt_type='both',
                                 network_instance='default',
                                 protocol_instance='default'):
    """Configure BGP route-target on a network instance (L2VPN direct).

    Used for L2VPN/EVPN network instances where route-targets are
    configured directly under the BGP protocol instance.

    Args:
        device (obj): Device object
        rt (str): Route target value (e.g., '2001:2001')
        rt_type (str, optional): Route target type — 'both', 'import',
            or 'export'. Defaults to 'both'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP route-target

    Example:
        >>> configure_bgp_route_target(device, '2001:2001', rt_type='both',
        ...     network_instance='Leaf1-Leaf2-EPLAN-1')
    """
    log.info(
        f"Configuring BGP route-target {rt} {rt_type} on {device.name} "
        f"(network-instance: {network_instance})"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'route-target {rt} {rt_type}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP route-target {rt} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_route_target(device, rt, rt_type='both',
                                   network_instance='default',
                                   protocol_instance='default'):
    """Remove BGP route-target from a network instance.

    Args:
        device (obj): Device object
        rt (str): Route target value (e.g., '2001:2001')
        rt_type (str, optional): Route target type — 'both', 'import',
            or 'export'. Defaults to 'both'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP route-target

    Example:
        >>> unconfigure_bgp_route_target(device, '2001:2001',
        ...     network_instance='Leaf1-Leaf2-EPLAN-1')
    """
    log.info(
        f"Removing BGP route-target {rt} {rt_type} from {device.name} "
        f"(network-instance: {network_instance})"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'no route-target {rt} {rt_type}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP route-target {rt} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_rt_afi_safi_route_target(device, afi_safi, rt,
                                             rt_type='both',
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure BGP route-target under an rt-afi-safi (L3VPN).

    Used for L3VPN network instances where route-targets are configured
    under ``rt-afi-safi <AFI_SAFI>`` sub-context.

    Args:
        device (obj): Device object
        afi_safi (str): AFI/SAFI name (e.g., 'L3VPN_IPV4_UNICAST',
            'L3VPN_IPV6_UNICAST')
        rt (str): Route target value (e.g., '201:201')
        rt_type (str, optional): Route target type — 'both', 'import',
            or 'export'. Defaults to 'both'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP rt-afi-safi route-target

    Example:
        >>> configure_bgp_rt_afi_safi_route_target(device,
        ...     'L3VPN_IPV4_UNICAST', '201:201', rt_type='both',
        ...     network_instance='ECMP-L3VPN-01')
    """
    log.info(
        f"Configuring BGP rt-afi-safi {afi_safi} route-target {rt} {rt_type} "
        f"on {device.name} (network-instance: {network_instance})"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'rt-afi-safi {afi_safi}',
        f'route-target {rt} {rt_type}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP rt-afi-safi {afi_safi} route-target {rt} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_rt_afi_safi_route_target(device, afi_safi, rt,
                                               rt_type='both',
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove BGP route-target from an rt-afi-safi (L3VPN).

    Args:
        device (obj): Device object
        afi_safi (str): AFI/SAFI name (e.g., 'L3VPN_IPV4_UNICAST')
        rt (str): Route target value (e.g., '201:201')
        rt_type (str, optional): Route target type. Defaults to 'both'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP rt-afi-safi route-target

    Example:
        >>> unconfigure_bgp_rt_afi_safi_route_target(device,
        ...     'L3VPN_IPV4_UNICAST', '201:201',
        ...     network_instance='ECMP-L3VPN-01')
    """
    log.info(
        f"Removing BGP rt-afi-safi {afi_safi} route-target {rt} {rt_type} "
        f"from {device.name} (network-instance: {network_instance})"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'rt-afi-safi {afi_safi}',
        f'no route-target {rt} {rt_type}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP rt-afi-safi {afi_safi} route-target {rt} "
            f"from {device.name}. Error:\n{e}"
        )


# =====================================================================
# SRv6 / L3VPN-SRv6 configuration
# =====================================================================

def configure_bgp_srv6_locator(device, locator_name,
                                network_instance='default',
                                protocol_instance='default'):
    """Configure BGP SRv6 locator reference.

    Args:
        device: Device object.
        locator_name: SRv6 locator name.
        network_instance: Network instance name.
        protocol_instance: BGP protocol instance.

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        f"Configuring BGP SRv6 locator {locator_name} on {device.name}"
    )
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global srv6 locator {locator_name}',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP SRv6 locator on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_srv6_locator(device, network_instance='default',
                                   protocol_instance='default'):
    """Remove BGP SRv6 locator reference."""
    log.info(f"Removing BGP SRv6 locator from {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, 'no global srv6 locator', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP SRv6 locator from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_sid_allocation_mode(device, mode,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure BGP SID allocation mode for SRv6 VRF.

    Args:
        device: Device object.
        mode: INSTANCE_SID or PER_NEXTHOP.
        network_instance: VRF network instance name.
        protocol_instance: BGP protocol instance.

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        f"Configuring BGP SID allocation mode {mode} on {device.name} "
        f"(network-instance: {network_instance})"
    )
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, f'global sid-allocation-mode {mode}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP SID allocation mode on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_sid_allocation_mode(device, network_instance='default',
                                          protocol_instance='default'):
    """Remove BGP SID allocation mode."""
    log.info(f"Removing BGP SID allocation mode from {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, 'no global sid-allocation-mode', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP SID allocation mode from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_peer_group_extended_nexthop(device, peer_group,
                                                afi_safi, enabled=True,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure extended-nexthop on a BGP peer-group AFI-SAFI.

    Required for L3VPN_IPV4_UNICAST over IPv6 peers (RFC 5549).

    Args:
        device: Device object.
        peer_group: Peer group name.
        afi_safi: AFI-SAFI name (e.g., L3VPN_IPV4_UNICAST).
        enabled: Enable extended-nexthop (default True).
        network_instance: Network instance name.
        protocol_instance: BGP protocol instance.

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(
        f"Configuring extended-nexthop on peer-group {peer_group} "
        f"AFI-SAFI {afi_safi} on {device.name}"
    )
    enabled_str = 'true' if enabled else 'false'
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'peer-group {peer_group}',
        f'afi-safi {afi_safi}',
        f'extended-nexthop enable {enabled_str}',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure extended-nexthop on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_peer_group_extended_nexthop(device, peer_group,
                                                   afi_safi,
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Remove extended-nexthop from a BGP peer-group AFI-SAFI."""
    log.info(
        f"Removing extended-nexthop from peer-group {peer_group} on {device.name}"
    )
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'peer-group {peer_group}',
        f'afi-safi {afi_safi}',
        'no extended-nexthop',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove extended-nexthop from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# BGP Best Path Selection
# =====================================================================

def configure_bgp_multipath_as_path_relax(device, enabled=True,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure BGP multipath as-path-relax."""
    log.info(f"Configuring BGP multipath as-path-relax on {device.name}")
    flag = 'true' if enabled else 'false'
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, f'global route-selection-options multipath as-path-relax {flag}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP multipath as-path-relax failed on {device.name}: {e}")


def configure_bgp_med_missing_as_worst(device, enabled=True,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure BGP med-missing-as-worst."""
    log.info(f"Configuring BGP med-missing-as-worst on {device.name}")
    flag = 'true' if enabled else 'false'
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, f'global route-selection-options med-missing-as-worst {flag}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP med-missing-as-worst failed on {device.name}: {e}")


def configure_bgp_multipath_evpn_etree_ead_relax(device, enabled=True,
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Configure BGP multipath-evpn-etree-ead-relax."""
    log.info(f"Configuring BGP multipath-evpn-etree-ead-relax on {device.name}")
    flag = 'true' if enabled else 'false'
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, f'global route-selection-options multipath-evpn-etree-ead-relax {flag}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP multipath-evpn-etree-ead-relax failed on {device.name}: {e}")


# =====================================================================
# BGP eRPL (External Routing Policy Language)
# =====================================================================

def configure_bgp_erpl_server(device, server_name, address, port,
                               preference=None,
                               network_instance='default',
                               protocol_instance='default'):
    """Configure BGP eRPL server.

    Args:
        device: Device object.
        server_name: eRPL server name.
        address: Server IP address.
        port: Server port number.
        preference: Server preference value.
    """
    log.info(f"Configuring BGP eRPL server {server_name} on {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'erpl server {server_name}',
        f'address {address}',
        f'port {port}',
    ]
    if preference is not None:
        config.append(f'preference {preference}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP eRPL server failed on {device.name}: {e}")


def unconfigure_bgp_erpl_server(device, server_name,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Remove BGP eRPL server."""
    log.info(f"Removing BGP eRPL server {server_name} from {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, f'no erpl server {server_name}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP eRPL server removal failed on {device.name}: {e}")


def configure_bgp_erpl_connection_wait_time(device, seconds,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Configure BGP eRPL connection wait time."""
    log.info(f"Configuring BGP eRPL connection-wait-time {seconds}s on {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context, f'erpl connection-wait-time {seconds}', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP eRPL connection-wait-time failed on {device.name}: {e}")


def configure_bgp_neighbor_apply_erpl(device, neighbor, afi_safi,
                                        import_policy,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure eRPL import policy on a BGP neighbor AFI-SAFI.

    Args:
        device: Device object.
        neighbor: Neighbor address.
        afi_safi: AFI-SAFI name.
        import_policy: eRPL policy name (server-side).
    """
    log.info(f"Configuring eRPL import-policy on neighbor {neighbor} on {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'neighbor {neighbor}',
        f'afi-safi {afi_safi}',
        f'apply-erpl import-policy {import_policy}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP eRPL import-policy failed on {device.name}: {e}")


def unconfigure_bgp_neighbor_apply_erpl(device, neighbor, afi_safi,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove eRPL import policy from a BGP neighbor AFI-SAFI."""
    log.info(f"Removing eRPL import-policy from neighbor {neighbor} on {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'neighbor {neighbor}',
        f'afi-safi {afi_safi}',
        'no apply-erpl import-policy',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP eRPL removal failed on {device.name}: {e}")


# =====================================================================
# BGP PIC (Prefix Independent Convergence)
# =====================================================================

def configure_bgp_install_backup(device, afi_safi, enabled=True,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Configure add-paths install-backup for BGP PIC.

    Args:
        device: Device object.
        afi_safi: AFI-SAFI name.
        enabled: Enable backup path installation (default True).
    """
    log.info(f"Configuring BGP install-backup for {afi_safi} on {device.name}")
    flag = 'true' if enabled else 'false'
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'add-paths install-backup {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP install-backup failed on {device.name}: {e}")


def unconfigure_bgp_install_backup(device, afi_safi,
                                    network_instance='default',
                                    protocol_instance='default'):
    """Remove add-paths install-backup."""
    log.info(f"Removing BGP install-backup for {afi_safi} on {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        'no add-paths install-backup',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP install-backup removal failed on {device.name}: {e}")


def configure_bgp_advertise_best_external(device, afi_safi, enabled=True,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Configure advertise-best-external for BGP PIC."""
    log.info(f"Configuring BGP advertise-best-external for {afi_safi} on {device.name}")
    flag = 'true' if enabled else 'false'
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'advertise-best-external {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP advertise-best-external failed on {device.name}: {e}")


def unconfigure_bgp_advertise_best_external(device, afi_safi,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Remove advertise-best-external."""
    log.info(f"Removing BGP advertise-best-external for {afi_safi} on {device.name}")
    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        'no advertise-best-external',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"BGP advertise-best-external removal failed on {device.name}: {e}")


def configure_bgp_neighbor_timers(device, neighbor,
                                    keepalive_interval=None,
                                    hold_time=None,
                                    minimum_advertisement_interval=None,
                                    network_instance='default',
                                    protocol_instance='default'):
    """Configure BGP neighbor timers (keepalive, hold-time, MAI).

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        keepalive_interval (int, optional): Keepalive interval in seconds.
        hold_time (int, optional): Hold-time in seconds.
        minimum_advertisement_interval (int, optional): Minimum advertisement
            interval in seconds.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor timers
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} timers on {device.name} "
        f"(keepalive={keepalive_interval}, hold-time={hold_time}, "
        f"mai={minimum_advertisement_interval})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context]

    # arcOS supports keepalive-interval and hold-time on a single line.
    # MAI is a separate timers sub-command.
    if keepalive_interval is not None or hold_time is not None:
        line = 'timers'
        if keepalive_interval is not None:
            line += f' keepalive-interval {keepalive_interval}'
        if hold_time is not None:
            line += f' hold-time {hold_time}'
        config.append(line)

    if minimum_advertisement_interval is not None:
        config.append(
            f'timers minimum-advertisement-interval '
            f'{minimum_advertisement_interval}'
        )

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} timers on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_timers(device, neighbor,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Remove BGP neighbor timer configuration (reset to default).

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor timer configuration
    """
    log.info(f"Removing BGP neighbor {neighbor} timers on {device.name}")

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        'no timers',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} timers on {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_graceful_restart(device,
                                     enabled=None,
                                     helper_only=None,
                                     restart_time=None,
                                     stale_routes_time=None,
                                     network_instance='default',
                                     protocol_instance='default'):
    """Configure BGP global graceful-restart capability.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable/disable graceful-restart capability.
        helper_only (bool, optional): Run in helper-only mode.
        restart_time (int, optional): Restart time in seconds (default 120).
        stale_routes_time (int, optional): Stale-routes time in seconds
            (default 300).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP graceful-restart
    """
    log.info(
        f"Configuring BGP graceful-restart on {device.name} "
        f"(enabled={enabled}, helper-only={helper_only}, "
        f"restart-time={restart_time}, stale-routes-time={stale_routes_time})"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [bgp_context]

    if enabled is not None:
        flag = 'true' if enabled else 'false'
        config.append(f'global graceful-restart enabled {flag}')

    if helper_only is not None:
        flag = 'true' if helper_only else 'false'
        config.append(f'global graceful-restart helper-only {flag}')

    if restart_time is not None:
        config.append(f'global graceful-restart restart-time {restart_time}')

    if stale_routes_time is not None:
        config.append(
            f'global graceful-restart stale-routes-time {stale_routes_time}'
        )

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP graceful-restart on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_graceful_restart(device,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Remove BGP global graceful-restart configuration (reset to default).

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP graceful-restart configuration
    """
    log.info(f"Removing BGP graceful-restart configuration on {device.name}")

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        'no global graceful-restart',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP graceful-restart on {device.name}. "
            f"Error:\n{e}"
        )


def _afi_safi_short_token(afi_safi):
    """Convert OpenConfig AFI-SAFI name to arcOS sub-token.

    For prefix-limit and similar per-AF sub-blocks, arcOS uses a lowercased
    hyphenated form (e.g. ``IPV4_UNICAST`` -> ``ipv4-unicast``).

    Args:
        afi_safi (str): OpenConfig AFI-SAFI name (e.g., 'IPV4_UNICAST').

    Returns:
        str: arcOS short token (e.g., 'ipv4-unicast').
    """
    return str(afi_safi).lower().replace('_', '-')


def configure_bgp_neighbor_max_prefix(device, neighbor, afi_safi, max_prefixes,
                                        warning_threshold_pct=None,
                                        prevent_teardown=None,
                                        restart_timer=None,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure BGP neighbor maximum-prefix-limit for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST', 'IPV6_UNICAST')
        max_prefixes (int): Maximum number of prefixes to accept.
        warning_threshold_pct (int, optional): Threshold percent (1-100) at
            which a syslog warning is emitted before reaching max-prefixes.
        prevent_teardown (bool, optional): If True, log instead of tearing
            down the session when max-prefixes is exceeded.
        restart_timer (int, optional): Seconds after which the session is
            re-established after teardown. Has no effect if prevent_teardown
            is True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP neighbor max-prefix-limit
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} {afi_safi} prefix-limit on "
        f"{device.name} (max={max_prefixes}, warn-pct={warning_threshold_pct}, "
        f"prevent-teardown={prevent_teardown}, restart-timer={restart_timer})"
    )

    af_short = _afi_safi_short_token(afi_safi)
    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        f'{af_short} prefix-limit max-prefixes {max_prefixes}',
    ]

    if warning_threshold_pct is not None:
        config.append(
            f'{af_short} prefix-limit warning-threshold-pct '
            f'{warning_threshold_pct}'
        )

    if prevent_teardown is not None:
        flag = 'true' if prevent_teardown else 'false'
        config.append(f'{af_short} prefix-limit prevent-teardown {flag}')

    if restart_timer is not None:
        config.append(f'{af_short} prefix-limit restart-timer {restart_timer}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} {afi_safi} "
            f"prefix-limit on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_max_prefix(device, neighbor, afi_safi,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove BGP neighbor maximum-prefix-limit configuration for an AFI-SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST', 'IPV6_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP neighbor max-prefix-limit
    """
    log.info(
        f"Removing BGP neighbor {neighbor} {afi_safi} prefix-limit on "
        f"{device.name}"
    )

    af_short = _afi_safi_short_token(afi_safi)
    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi}',
        f'no {af_short} prefix-limit',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} {afi_safi} "
            f"prefix-limit on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-01 — session, transport & security
# (arcos_pyats_sanity/docs/config-coverage/02-bgp-policy-redist.md)
#
# Every CLI line traces to Command_Line_Interface/Border_Gateway_Protocol.adoc;
# the cited line is in each docstring. Leaf names were additionally confirmed
# against `neighbor <ip> ?` on rtr1 2026-08-17, which corrected three audit rows:
# `ttl-security` is really the direct leaf `ttl-security-hops`; "fast-deactivation"
# is really `disable-fast-deactivation` (inverted sense); and inbound
# soft-reconfiguration lives under the neighbor's AFI/SAFI, not the neighbor.
#
# Every list is flat — no submode is entered, so nothing emits `exit`.
# ---------------------------------------------------------------------------

#: Accepted values for ``configure_bgp_neighbor_remove_private_as(mode=...)``.
#: Device-confirmed enum (rtr1, `neighbor <ip> remove-private-as ?`).
BGP_REMOVE_PRIVATE_AS_MODES = ('PRIVATE_AS_REMOVE_ALL', 'PRIVATE_AS_REPLACE_ALL')


def configure_bgp_neighbor_ebgp_local_as(device, neighbor, local_as,
                                         no_prepend=None, replace_as=None,
                                         dual_as=None,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure the eBGP local-AS override for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1508-1511

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        local_as (int): Local AS number advertised to this neighbor.
        no_prepend (bool, optional): Suppress prepending the local AS. Defaults to None (unset).
        replace_as (bool, optional): Replace the real AS with the local AS. Defaults to None.
        dual_as (bool, optional): Accept the peer using either AS. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the eBGP local-AS

    Example:
        >>> configure_bgp_neighbor_ebgp_local_as(
        ...     device, neighbor='220.1.11.1', local_as=58067, replace_as=True)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} ebgp-local-as {local_as} on "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'ebgp-local-as local-as {local_as}']
    if no_prepend is not None:
        config.append(f'ebgp-local-as no-prepend {"true" if no_prepend else "false"}')
    if replace_as is not None:
        config.append(f'ebgp-local-as replace-as {"true" if replace_as else "false"}')
    if dual_as is not None:
        config.append(f'ebgp-local-as dual-as {"true" if dual_as else "false"}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} ebgp-local-as {local_as} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_ebgp_local_as(device, neighbor,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Remove the eBGP local-AS configuration from a neighbor.

    Removes the whole ``ebgp-local-as`` container, including any no-prepend /
    replace-as / dual-as sub-leaves set by the configure counterpart.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the eBGP local-AS

    Example:
        >>> unconfigure_bgp_neighbor_ebgp_local_as(device, neighbor='220.1.11.1')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} ebgp-local-as from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no ebgp-local-as', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} ebgp-local-as on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_remove_private_as(device, neighbor, mode,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure removal of private AS numbers towards a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1521

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        mode (str): One of :data:`BGP_REMOVE_PRIVATE_AS_MODES` —
            ``'PRIVATE_AS_REMOVE_ALL'`` or ``'PRIVATE_AS_REPLACE_ALL'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``mode`` is not one of the two accepted values
        SubCommandFailure: Failed to configure remove-private-as

    Example:
        >>> configure_bgp_neighbor_remove_private_as(
        ...     device, neighbor='10.1.1.2', mode='PRIVATE_AS_REMOVE_ALL')
    """
    if mode not in BGP_REMOVE_PRIVATE_AS_MODES:
        raise ValueError(
            f"Invalid remove-private-as mode '{mode}'. Must be one of: "
            f"{', '.join(BGP_REMOVE_PRIVATE_AS_MODES)}"
        )

    log.info(
        f"Configuring BGP neighbor {neighbor} remove-private-as {mode} on "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'remove-private-as {mode}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} remove-private-as "
            f"{mode} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_remove_private_as(device, neighbor,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove the remove-private-as configuration from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove remove-private-as

    Example:
        >>> unconfigure_bgp_neighbor_remove_private_as(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} remove-private-as from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no remove-private-as', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} remove-private-as on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_as_path_options(device, neighbor, allow_own_as=None,
                                           replace_peer_as=None,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure AS-path handling options for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1545,1554

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        allow_own_as (int, optional): Times the local AS may appear in a received
            AS-path before the route is rejected. Defaults to None (unset).
        replace_peer_as (bool, optional): Replace the peer AS in outbound AS-paths.
            Defaults to None (unset).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If neither option is supplied
        SubCommandFailure: Failed to configure as-path-options

    Example:
        >>> configure_bgp_neighbor_as_path_options(
        ...     device, neighbor='220.1.11.1', allow_own_as=3)
    """
    if allow_own_as is None and replace_peer_as is None:
        raise ValueError(
            "configure_bgp_neighbor_as_path_options requires at least one of "
            "'allow_own_as' or 'replace_peer_as'"
        )

    log.info(
        f"Configuring BGP neighbor {neighbor} as-path-options on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context]
    if allow_own_as is not None:
        config.append(f'as-path-options allow-own-as {allow_own_as}')
    if replace_peer_as is not None:
        config.append(f'as-path-options replace-peer-as {"true" if replace_peer_as else "false"}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} as-path-options on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_as_path_options(device, neighbor,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove AS-path options from a neighbor.

    Removes the whole ``as-path-options`` container, covering both allow-own-as
    and replace-peer-as.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove as-path-options

    Example:
        >>> unconfigure_bgp_neighbor_as_path_options(device, neighbor='220.1.11.1')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} as-path-options from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no as-path-options', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} as-path-options on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_ebgp_multihop(device, neighbor, multihop_ttl,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure the eBGP multihop TTL for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1564

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        multihop_ttl (int): TTL for the eBGP session. Device default is 1, i.e.
            directly-connected peers only.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the eBGP multihop TTL for a neighbor

    Example:
        >>> configure_bgp_neighbor_ebgp_multihop(
        ...     device, neighbor='220.1.11.1', multihop_ttl=5)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} ebgp-multihop on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'ebgp-multihop multihop-ttl {multihop_ttl}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} ebgp-multihop on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_ebgp_multihop(device, neighbor,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Remove the eBGP multihop TTL from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the eBGP multihop TTL for a neighbor

    Example:
        >>> unconfigure_bgp_neighbor_ebgp_multihop(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} ebgp-multihop from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no ebgp-multihop', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} ebgp-multihop on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_ttl_security_hops(device, neighbor, hops,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure the GTSM ttl-security hop count for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1575

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        hops (int): Maximum number of TTL hops to the neighbor.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the GTSM ttl-security hop count for a neighbor

    Example:
        >>> configure_bgp_neighbor_ttl_security_hops(
        ...     device, neighbor='220.1.11.1', hops=1)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} ttl-security-hops on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'ttl-security-hops {hops}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} ttl-security-hops on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_ttl_security_hops(device, neighbor,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove the GTSM ttl-security hop count from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the GTSM ttl-security hop count for a neighbor

    Example:
        >>> unconfigure_bgp_neighbor_ttl_security_hops(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} ttl-security-hops from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no ttl-security-hops', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} ttl-security-hops on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_auth_password(device, neighbor, password,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure the MD5 authentication password for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1586

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        password (str): Authentication password. Max 80 characters.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the MD5 authentication password for a neighbor

    Note:
        arcOS stores this ENCRYPTED — `show running-config` never displays the
        plaintext (adoc:1593). Verification must assert the leaf's presence, not
        its value.

    Example:
        >>> configure_bgp_neighbor_auth_password(
        ...     device, neighbor='220.1.11.1', password='arrcus')
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} auth-password on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'auth-password {password}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} auth-password on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_auth_password(device, neighbor,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Remove the MD5 authentication password from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the MD5 authentication password for a neighbor

    Example:
        >>> unconfigure_bgp_neighbor_auth_password(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} auth-password from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no auth-password', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} auth-password on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_dscp(device, neighbor, dscp,
                                network_instance='default',
                                protocol_instance='default'):
    """Configure the DSCP value for a neighbor's BGP packets.

    adoc: Border_Gateway_Protocol.adoc:1602

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        dscp (int): DSCP value, 0..63.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``dscp`` is not an integer in 0..63
        SubCommandFailure: Failed to configure the DSCP value for a neighbor's BGP packets

    Example:
        >>> configure_bgp_neighbor_dscp(
        ...     device, neighbor='10.1.1.2', dscp=56)
    """
    if not isinstance(dscp, int) or isinstance(dscp, bool) or not 0 <= dscp <= 63:
        raise ValueError(
            f"Invalid DSCP value '{dscp}'. Must be an integer in 0..63."
        )

    log.info(
        f"Configuring BGP neighbor {neighbor} dscp on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'dscp {dscp}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} dscp on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_dscp(device, neighbor,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Remove the DSCP value for a neighbor's BGP packets from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the DSCP value for a neighbor's BGP packets

    Example:
        >>> unconfigure_bgp_neighbor_dscp(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} dscp from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no dscp', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} dscp on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_transport_tcp_mss(device, neighbor, tcp_mss,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure the TCP MSS for a neighbor's transport session.

    adoc: Border_Gateway_Protocol.adoc:583

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        tcp_mss (int): TCP maximum segment size.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the TCP MSS for a neighbor's transport session

    Example:
        >>> configure_bgp_neighbor_transport_tcp_mss(
        ...     device, neighbor='2.2.2.2', tcp_mss=1000)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} transport tcp-mss on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'transport tcp-mss {tcp_mss}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} transport tcp-mss on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_transport_tcp_mss(device, neighbor,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove the TCP MSS for a neighbor's transport session from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the TCP MSS for a neighbor's transport session

    Example:
        >>> unconfigure_bgp_neighbor_transport_tcp_mss(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} transport tcp-mss from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no transport tcp-mss', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} transport tcp-mss on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_transport_passive_mode(device, neighbor, enabled=True,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Configure passive-mode transport for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1373

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        enabled (bool, optional): When True the local speaker does not initiate the
            TCP connection; the peer must. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure passive-mode transport for a neighbor

    Example:
        >>> configure_bgp_neighbor_transport_passive_mode(
        ...     device, neighbor='220.1.11.1', enabled=True)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} transport passive-mode on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'transport passive-mode {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} transport passive-mode on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_transport_passive_mode(device, neighbor,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Remove passive-mode transport from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove passive-mode transport for a neighbor

    Example:
        >>> unconfigure_bgp_neighbor_transport_passive_mode(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} transport passive-mode from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no transport passive-mode', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} transport passive-mode on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_enforce_first_as(device, neighbor, enabled=True,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Configure enforce-first-AS checking for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1139

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        enabled (bool, optional): Require the peer's AS to be first in the received
            AS-path. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure enforce-first-AS checking for a neighbor

    Example:
        >>> configure_bgp_neighbor_enforce_first_as(
        ...     device, neighbor='192.1.1.1', enabled=False)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} enforce-first-as on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'enforce-first-as {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} enforce-first-as on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_enforce_first_as(device, neighbor,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Remove enforce-first-AS checking from a neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove enforce-first-AS checking for a neighbor

    Example:
        >>> unconfigure_bgp_neighbor_enforce_first_as(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} enforce-first-as from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no enforce-first-as', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} enforce-first-as on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_disable_fast_deactivation(device, neighbor, disabled=True,
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Configure BGP fast session deactivation for a neighbor.

    adoc: Border_Gateway_Protocol.adoc:1379

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        disabled (bool, optional): True DISABLES fast deactivation, so the session
            survives a local interface going down until the hold timer expires.
            Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP fast session deactivation for a neighbor

    Note:
        This leaf carries INVERTED sense. Fast deactivation is ON by default on
        arcOS; this command turns it off. ``disabled=True`` therefore means "do
        not deactivate fast". The config-coverage audit listed this knob as
        `fast-deactivation`; the real leaf is `disable-fast-deactivation`
        (confirmed on rtr1).

    Example:
        >>> configure_bgp_neighbor_disable_fast_deactivation(
        ...     device, neighbor='10.1.1.2', disabled=True)
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} disable-fast-deactivation on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'disable-fast-deactivation {"true" if disabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} disable-fast-deactivation on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_disable_fast_deactivation(device, neighbor,
                                                       network_instance='default',
                                                       protocol_instance='default'):
    """Re-enable BGP fast session deactivation for a neighbor.

    Emits ``no disable-fast-deactivation``, which removes the *disable* and
    therefore RESTORES arcOS's default fast teardown - the session will again
    drop immediately when its local interface goes down, rather than waiting
    for the hold timer.

    Note:
        This leaf carries INVERTED sense; see
        :func:`configure_bgp_neighbor_disable_fast_deactivation`. "Unconfigure"
        here means restoring fast deactivation, not removing it.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP fast session deactivation for a neighbor

    Example:
        >>> unconfigure_bgp_neighbor_disable_fast_deactivation(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} disable-fast-deactivation from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, 'no disable-fast-deactivation', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} disable-fast-deactivation on "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_inbound_soft_reconfiguration(device, neighbor, afi_safi,
                                                        enabled=True,
                                                        network_instance='default',
                                                        protocol_instance='default'):
    """Enable or disable inbound soft-reconfiguration for a neighbor AFI/SAFI.

    adoc: Border_Gateway_Protocol.adoc:1698-1704

    Emitted as ONE line rather than entering the ``afi-safi`` submode, matching
    this file's flat convention (cf. ``transport local-address``) and avoiding any
    window in which a following leaf could land at neighbor scope.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'`` or ``'IPV6_UNICAST'``.
        enabled (bool, optional): Retain pre-policy routes received from the
            neighbor. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure inbound soft-reconfiguration

    Note:
        Enabling triggers an automatic route refresh. DISABLING bounces the
        session — it goes down for cleanup before returning to Established
        (adoc:1695). Not a non-disruptive toggle.

    Note:
        PREREQUISITE (commit-time, not parse-time): the BGP *global* AF must
        already exist or the commit aborts with::

            Aborted: '... afi-safi IPV4_UNICAST afi-safi-name'
            (value "oc-bgp-types:IPV4_UNICAST"): BGP global AF must be
            configured first.

        Call :func:`configure_bgp_global_afi_safi` for the same ``afi_safi``
        first. Confirmed on rtr1 2026-08-17 — this line parses fine and fails
        only at commit, so a caller gets no warning until the commit.

    Example:
        >>> configure_bgp_neighbor_inbound_soft_reconfiguration(
        ...     device, neighbor='220.1.12.1', afi_safi='IPV4_UNICAST')
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} afi-safi {afi_safi} "
        f"inbound-soft-reconfiguration on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi} inbound-soft-reconfiguration {"true" if enabled else "false"}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} afi-safi {afi_safi} "
            f"inbound-soft-reconfiguration on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_inbound_soft_reconfiguration(device, neighbor, afi_safi,
                                                          network_instance='default',
                                                          protocol_instance='default'):
    """Remove inbound soft-reconfiguration from a neighbor AFI/SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove inbound soft-reconfiguration

    Note:
        Removing this bounces the session, exactly as disabling it does — see the
        configure counterpart.

    Example:
        >>> unconfigure_bgp_neighbor_inbound_soft_reconfiguration(
        ...     device, neighbor='220.1.12.1', afi_safi='IPV4_UNICAST')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} afi-safi {afi_safi} "
        f"inbound-soft-reconfiguration from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'no afi-safi {afi_safi} inbound-soft-reconfiguration',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} afi-safi {afi_safi} "
            f"inbound-soft-reconfiguration on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-02 — route-reflection, dynamic peering & AF knobs
# (arcos_pyats_sanity/docs/config-coverage/02-bgp-policy-redist.md)
#
# Scopes were confirmed against `?` completions on rtr1 2026-08-17, correcting
# three audit rows:
#   * `dynamic-neighbor-prefix` sits at PROTOCOL level, not under `global`.
#   * `add-paths eligible-prefix-policy` sits under GLOBAL afi-safi, not the
#     neighbor's afi-safi (the neighbor's add-paths has only send/receive).
#   * `retain-route-target-all` is valid only under GLOBAL **VPN** AFI/SAFIs
#     (L3VPN_IPV4_UNICAST / L3VPN_IPV6_UNICAST / L2VPN_EVPN) and is a bare
#     presence leaf with no value.
#
# All lists are flat — no submode is entered, so nothing emits `exit`.
# ---------------------------------------------------------------------------


def configure_bgp_neighbor_route_reflector_client(device, neighbor, enabled=True,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Configure a neighbor as a route-reflector client.

    adoc: Border_Gateway_Protocol.adoc:940,1092

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        enabled (bool, optional): Treat the peer as an RR client. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure a neighbor as a route-reflector client

    Example:
        >>> configure_bgp_neighbor_route_reflector_client(
        ...     device, neighbor='192.1.1.2', enabled=True)
    """
    log.info(
        f"Configuring BGP neighbor route reflector client on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'route-reflector route-reflector-client {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor route reflector client on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_route_reflector_client(device, neighbor, network_instance='default',
                                                    protocol_instance='default'):
    """Remove a neighbor as a route-reflector client.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove a neighbor as a route-reflector client

    Example:
        >>> unconfigure_bgp_neighbor_route_reflector_client(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor route reflector client from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, 'no route-reflector route-reflector-client', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor route reflector client from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_route_server_client(device, neighbor, enabled=True,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Configure a neighbor as a route-server client.

    adoc: Border_Gateway_Protocol.adoc:1128

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        enabled (bool, optional): Treat the peer as a route-server client. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure a neighbor as a route-server client

    Example:
        >>> configure_bgp_neighbor_route_server_client(
        ...     device, neighbor='192.1.1.2', enabled=True)
    """
    log.info(
        f"Configuring BGP neighbor route server client on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'route-server route-server-client {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor route server client on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_route_server_client(device, neighbor, network_instance='default',
                                                 protocol_instance='default'):
    """Remove a neighbor as a route-server client.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove a neighbor as a route-server client

    Example:
        >>> unconfigure_bgp_neighbor_route_server_client(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor route server client from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, 'no route-server route-server-client', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor route server client from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_peer_as_range(device, neighbor, ranges,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure the accepted peer-AS range for a dynamic neighbor.

    adoc: Border_Gateway_Protocol.adoc:531-532

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        ranges (str): AS range or single AS, e.g. ``'65000..70000'`` or ``'71000'``.
            One range per call — the leaf is a list, and adoc:531-532 adds a
            second range with a second command. Call this repeatedly to build up
            more than one; a single call does not replace previously-set ranges.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the accepted peer-AS range for a dynamic neighbor

    Example:
        >>> configure_bgp_neighbor_peer_as_range(
        ...     device, neighbor='220.1.11.1', ranges='65000..70000')
    """
    log.info(
        f"Configuring BGP neighbor peer as range on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'peer-as-range inline ranges {ranges}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor peer as range on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_peer_as_range(device, neighbor, network_instance='default',
                                           protocol_instance='default'):
    """Remove the accepted peer-AS range for a dynamic neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the accepted peer-AS range for a dynamic neighbor

    Example:
        >>> unconfigure_bgp_neighbor_peer_as_range(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor peer as range from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, 'no peer-as-range', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor peer as range from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_cluster_id(device, cluster_id,
                             network_instance='default',
                             protocol_instance='default'):
    """Configure the route-reflector cluster-id.

    adoc: Border_Gateway_Protocol.adoc:1107

    Args:
        device (obj): Device object
        cluster_id (str): Cluster identifier in dotted-quad form, e.g. ``'10.10.1.1'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the route-reflector cluster-id

    Example:
        >>> configure_bgp_cluster_id(
        ...     device, cluster_id='10.10.1.1')
    """
    log.info(
        f"Configuring BGP cluster id on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global cluster-id {cluster_id}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP cluster id on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_cluster_id(device, network_instance='default',
                               protocol_instance='default'):
    """Remove the route-reflector cluster-id.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the route-reflector cluster-id

    Example:
        >>> unconfigure_bgp_cluster_id(device)
    """
    log.info(
        f"Removing BGP cluster id from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global cluster-id', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP cluster id from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_add_paths_eligible_prefix_policy(device, afi_safi, policy,
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Configure the add-paths eligible-prefix policy for a global AFI/SAFI.

    adoc: Border_Gateway_Protocol.adoc:n/a (device-confirmed)

    Args:
        device (obj): Device object
        afi_safi (str): Global AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        policy (str): Routing-policy name selecting add-paths-eligible prefixes.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the add-paths eligible-prefix policy for a global AFI/SAFI

    Example:
        >>> configure_bgp_add_paths_eligible_prefix_policy(
        ...     device, afi_safi='IPV4_UNICAST', policy='ADDPATH_POL')
    """
    log.info(
        f"Configuring BGP add paths eligible prefix policy on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global afi-safi {afi_safi} add-paths eligible-prefix-policy {policy}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP add paths eligible prefix policy on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_add_paths_eligible_prefix_policy(device, afi_safi, network_instance='default',
                                                     protocol_instance='default'):
    """Remove the add-paths eligible-prefix policy for a global AFI/SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): Global AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the add-paths eligible-prefix policy for a global AFI/SAFI

    Example:
        >>> unconfigure_bgp_add_paths_eligible_prefix_policy(device)
    """
    log.info(
        f"Removing BGP add paths eligible prefix policy from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no global afi-safi {afi_safi} add-paths eligible-prefix-policy', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP add paths eligible prefix policy from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_default_information_originate(device, afi_safi, enabled=True,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure default-information originate for a global AFI/SAFI.

    adoc: Border_Gateway_Protocol.adoc:958

    Args:
        device (obj): Device object
        afi_safi (str): Global AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        enabled (bool, optional): Originate a default route. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure default-information originate for a global AFI/SAFI

    Example:
        >>> configure_bgp_default_information_originate(
        ...     device, afi_safi='IPV4_UNICAST', enabled=True)
    """
    log.info(
        f"Configuring BGP default information originate on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global afi-safi {afi_safi} default-information originate enabled {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP default information originate on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_default_information_originate(device, afi_safi, network_instance='default',
                                                  protocol_instance='default'):
    """Remove default-information originate for a global AFI/SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): Global AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove default-information originate for a global AFI/SAFI

    Example:
        >>> unconfigure_bgp_default_information_originate(device)
    """
    log.info(
        f"Removing BGP default information originate from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no global afi-safi {afi_safi} default-information originate', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP default information originate from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_network_rib_validation(device, afi_safi, prefix, enabled=True,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure RIB validation for an originated network prefix.

    adoc: Border_Gateway_Protocol.adoc:1661

    Args:
        device (obj): Device object
        afi_safi (str): Global AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        prefix (str): The originated network prefix, e.g. ``'100.1.1.0/24'``.
        enabled (bool, optional): Require the prefix to be present in the RIB before
            it is advertised. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure RIB validation for an originated network prefix

    Example:
        >>> configure_bgp_network_rib_validation(
        ...     device, afi_safi='IPV4_UNICAST', prefix='100.1.1.0/24')
    """
    log.info(
        f"Configuring BGP network rib validation on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global afi-safi {afi_safi} network {prefix} rib-validation {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP network rib validation on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_network_rib_validation(device, afi_safi, prefix, network_instance='default',
                                           protocol_instance='default'):
    """Remove RIB validation for an originated network prefix.

    Args:
        device (obj): Device object
        afi_safi (str): Global AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        prefix (str): The originated network prefix, e.g. ``'100.1.1.0/24'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove RIB validation for an originated network prefix

    Example:
        >>> unconfigure_bgp_network_rib_validation(device)
    """
    log.info(
        f"Removing BGP network rib validation from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no global afi-safi {afi_safi} network {prefix} rib-validation', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP network rib validation from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_aigp(device, neighbor, afi_safi, enabled=True,
                                network_instance='default',
                                protocol_instance='default'):
    """Configure the AIGP metric for a neighbor AFI/SAFI.

    adoc: Border_Gateway_Protocol.adoc:1852

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        enabled (bool, optional): Enable AIGP metric handling. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the AIGP metric for a neighbor AFI/SAFI

    Example:
        >>> configure_bgp_neighbor_aigp(
        ...     device, neighbor='10.1.1.2', afi_safi='IPV4_UNICAST')
    """
    log.info(
        f"Configuring BGP neighbor aigp on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'afi-safi {afi_safi} aigp enable {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor aigp on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_aigp(device, neighbor, afi_safi, network_instance='default',
                                  protocol_instance='default'):
    """Remove the AIGP metric for a neighbor AFI/SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the AIGP metric for a neighbor AFI/SAFI

    Example:
        >>> unconfigure_bgp_neighbor_aigp(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor aigp from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'no afi-safi {afi_safi} aigp enable', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor aigp from {device.name}. "
            f"Error:\n{e}"
        )


#: Global AFI/SAFIs under which ``retain-route-target-all`` is valid.
#: adoc:853 — "under global VPN AFI/SAFIs such as L3VPN_IPV4_UNICAST,
#: L3VPN_IPV6_UNICAST, L2VPN_EVPN, etc, in the `default` network-instance".
BGP_VPN_AFI_SAFIS = (
    'L3VPN_IPV4_UNICAST',
    'L3VPN_IPV6_UNICAST',
    'L2VPN_EVPN',
)


def configure_bgp_dynamic_neighbor_prefix(device, prefix, peer_group=None,
                                          neighbor_limit=None,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Configure a BGP dynamic-neighbor (listen) range.

    adoc: Border_Gateway_Protocol.adoc:554-556, 1328

    CLI emitted (all one context, no submode)::

        network-instance {ni} protocol BGP {pi}
          dynamic-neighbor-prefix {prefix}
          dynamic-neighbor-prefix {prefix} peer-group {peer_group}
          dynamic-neighbor-prefix {prefix} neighbor-limit {neighbor_limit}

    Note:
        This leaf sits at PROTOCOL level, a sibling of ``global`` — not under it.
        Confirmed on rtr1 2026-08-17; the config-coverage audit implied global scope.

    Note:
        Dynamic neighbours only accept INCOMING connections — the remote speaker
        must initiate. A dynamic peer therefore cannot also be in passive-mode
        (adoc:1361).

    Args:
        device (obj): Device object
        prefix (str): Listen range, e.g. ``'220.1.0.0/16'``.
        peer_group (str, optional): Peer-group dynamic neighbours are placed in.
            Defaults to None (leave unset).
        neighbor_limit (int, optional): Maximum dynamic neighbours from this range.
            Defaults to None (leave unset).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the dynamic-neighbor prefix

    Example:
        >>> configure_bgp_dynamic_neighbor_prefix(
        ...     device, prefix='220.1.0.0/16', peer_group='p1', neighbor_limit=32)
    """
    log.info(
        f"Configuring BGP dynamic-neighbor-prefix {prefix} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'dynamic-neighbor-prefix {prefix}']
    if peer_group is not None:
        config.append(f'dynamic-neighbor-prefix {prefix} peer-group {peer_group}')
    if neighbor_limit is not None:
        config.append(f'dynamic-neighbor-prefix {prefix} neighbor-limit {neighbor_limit}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP dynamic-neighbor-prefix {prefix} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_dynamic_neighbor_prefix(device, prefix,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Remove a BGP dynamic-neighbor (listen) range.

    Removes the whole range including its peer-group and neighbor-limit sub-leaves.

    Args:
        device (obj): Device object
        prefix (str): Listen range, e.g. ``'220.1.0.0/16'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the dynamic-neighbor prefix

    Example:
        >>> unconfigure_bgp_dynamic_neighbor_prefix(device, prefix='220.1.0.0/16')
    """
    log.info(
        f"Removing BGP dynamic-neighbor-prefix {prefix} from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no dynamic-neighbor-prefix {prefix}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP dynamic-neighbor-prefix {prefix} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_retain_route_target_all(device, afi_safi, enabled=True,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Retain VPN routes not imported by any VRF, for a global VPN AFI/SAFI.

    adoc: Border_Gateway_Protocol.adoc:851-876

    Args:
        device (obj): Device object
        afi_safi (str): A global VPN AFI/SAFI — one of :data:`BGP_VPN_AFI_SAFIS`.
        enabled (bool, optional): Retain VPN routes with all route-targets.
            Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``afi_safi`` is not a VPN AFI/SAFI
        SubCommandFailure: Failed to configure retain-route-target-all

    Note:
        Valid ONLY under global VPN AFI/SAFIs, and only in the ``default``
        network-instance (adoc:855) — both halves are now enforced. It does not appear under IPV4_UNICAST —
        confirmed on rtr1 2026-08-17, where `global afi-safi IPV4_UNICAST ?`
        does not list it.

    Note:
        The adoc (:860,867,874) shows this as a bare presence leaf with no value.
        That is WRONG for this build: `retain-route-target-all ?` offers
        `true`/`false`, and the valueless form is rejected with
        "syntax error: incomplete path". Confirmed on rtr1 2026-08-17.

    Example:
        >>> configure_bgp_retain_route_target_all(device, afi_safi='L3VPN_IPV4_UNICAST')
    """
    if afi_safi not in BGP_VPN_AFI_SAFIS:
        raise ValueError(
            f"retain-route-target-all is only valid under a global VPN AFI/SAFI. "
            f"Got '{afi_safi}'; expected one of: {', '.join(BGP_VPN_AFI_SAFIS)}"
        )
    if network_instance != 'default':
        raise ValueError(
            "retain-route-target-all is valid only in the 'default' "
            f"network-instance (adoc:855). Got '{network_instance}'."
        )

    log.info(
        f"Configuring BGP retain-route-target-all under global afi-safi {afi_safi} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        ctx,
        f'global afi-safi {afi_safi} retain-route-target-all {"true" if enabled else "false"}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP retain-route-target-all under global "
            f"afi-safi {afi_safi} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_retain_route_target_all(device, afi_safi,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Stop retaining unimported VPN routes for a global VPN AFI/SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): A global VPN AFI/SAFI — one of :data:`BGP_VPN_AFI_SAFIS`.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``afi_safi`` is not a VPN AFI/SAFI
        SubCommandFailure: Failed to remove retain-route-target-all

    Example:
        >>> unconfigure_bgp_retain_route_target_all(device, afi_safi='L2VPN_EVPN')
    """
    if afi_safi not in BGP_VPN_AFI_SAFIS:
        raise ValueError(
            f"retain-route-target-all is only valid under a global VPN AFI/SAFI. "
            f"Got '{afi_safi}'; expected one of: {', '.join(BGP_VPN_AFI_SAFIS)}"
        )
    if network_instance != 'default':
        raise ValueError(
            "retain-route-target-all is valid only in the 'default' "
            f"network-instance (adoc:855). Got '{network_instance}'."
        )

    log.info(
        f"Removing BGP retain-route-target-all under global afi-safi {afi_safi} "
        f"from {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no global afi-safi {afi_safi} retain-route-target-all', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP retain-route-target-all under global "
            f"afi-safi {afi_safi} from {device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_default_originate(device, neighbor, afi_safi,
                                             enabled=True, export_policy=None,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure default-route origination toward a neighbor AFI/SAFI.

    adoc: Border_Gateway_Protocol.adoc:1940-1977

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        enabled (bool, optional): Advertise a default route unconditionally.
            Defaults to True.
        export_policy (str or list, optional): Policy (or list of policies) gating
            the default-route advertisement. Defaults to None (unset).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure default-originate

    Note:
        PREREQUISITE (commit-time): the corresponding BGP *global* AF must exist
        first, else the commit aborts with "BGP global AF must be configured
        first" — see :func:`configure_bgp_global_afi_safi`.

    Example:
        >>> configure_bgp_neighbor_default_originate(
        ...     device, neighbor='10.1.1.2', afi_safi='IPV4_UNICAST')
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} afi-safi {afi_safi} default-originate "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [
        nbr_context,
        f'afi-safi {afi_safi} default-originate enabled {"true" if enabled else "false"}',
    ]
    if export_policy is not None:
        policies = ' '.join(str(x) for x in export_policy) \
            if isinstance(export_policy, (list, tuple)) \
            else export_policy
        config.append(
            f'afi-safi {afi_safi} default-originate export-policy [ {policies} ]'
        )
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} afi-safi {afi_safi} "
            f"default-originate on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_default_originate(device, neighbor, afi_safi,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove default-route origination from a neighbor AFI/SAFI.

    Removes the whole ``default-originate`` container, covering both the
    ``enabled`` leaf and any ``export-policy``.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove default-originate

    Example:
        >>> unconfigure_bgp_neighbor_default_originate(
        ...     device, neighbor='10.1.1.2', afi_safi='IPV4_UNICAST')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} afi-safi {afi_safi} default-originate "
        f"from {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    nbr_context = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [nbr_context, f'no afi-safi {afi_safi} default-originate', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} afi-safi {afi_safi} "
            f"default-originate from {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-03 — operational & AFI-specific knobs
# (arcos_pyats_sanity/docs/config-coverage/02-bgp-policy-redist.md)
#
# Scopes confirmed by `?` capture on rtr1 2026-08-17. Audit corrections:
#   * `send-default-route` is under the NEIGHBOR's afi-safi RTFILTER (adoc:2145-2151),
#     not the global one — `global afi-safi RTFILTER send-default-route` is rejected
#     with "% Invalid input detected".
#   * `graceful-shutdown` exists at BOTH global and neighbor scope, and its leaf is
#     spelled `enable`, not `enabled` like most arcOS booleans.
#   * `update-wait-data-plane` is under global afi-safi IPV4_UNICAST / IPV6_UNICAST
#     (adoc:837-842), not directly under `global`.
#
# All lists flat; nothing emits `exit`.
# ---------------------------------------------------------------------------


def configure_bgp_shutdown_protocol(device, shutdown=True,
                                    network_instance='default',
                                    protocol_instance='default'):
    """Configure administrative shutdown of the whole BGP protocol instance.

    adoc / device source: Border_Gateway_Protocol.adoc:global ? (device)

    Args:
        device (obj): Device object
        shutdown (bool, optional): Shut the protocol down. **Defaults to True** —
            calling this with no arguments takes down the entire BGP instance.
            Named ``shutdown`` rather than ``enabled`` to match
            :func:`configure_bgp_neighbor_shutdown` and because ``enabled=True``
            reads as "BGP enabled", the opposite of what it does.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure administrative shutdown of the whole BGP protocol instance

    Example:
        >>> configure_bgp_shutdown_protocol(device, shutdown=True)
    """
    log.info(
        f"Configuring BGP shutdown protocol on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global shutdown-protocol {"true" if shutdown else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP shutdown protocol on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_shutdown_protocol(device, network_instance='default',
                                      protocol_instance='default'):
    """Remove administrative shutdown of the whole BGP protocol instance.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove administrative shutdown of the whole BGP protocol instance

    Example:
        >>> unconfigure_bgp_shutdown_protocol(device)
    """
    log.info(
        f"Removing BGP shutdown protocol from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global shutdown-protocol', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP shutdown protocol from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_shutdown_all_sessions(device, shutdown=True,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure administrative shutdown of all neighbor sessions.

    adoc / device source: Border_Gateway_Protocol.adoc:global ? (device)

    Args:
        device (obj): Device object
        shutdown (bool, optional): Shut all sessions down. **Defaults to True** —
            calling this with no arguments drops every BGP session on the device.
            Named ``shutdown`` rather than ``enabled`` for the same reason as
            :func:`configure_bgp_shutdown_protocol`.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure administrative shutdown of all neighbor sessions

    Example:
        >>> configure_bgp_shutdown_all_sessions(device, shutdown=True)
    """
    log.info(
        f"Configuring BGP shutdown all sessions on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global shutdown-all-sessions {"true" if shutdown else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP shutdown all sessions on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_shutdown_all_sessions(device, network_instance='default',
                                          protocol_instance='default'):
    """Remove administrative shutdown of all neighbor sessions.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove administrative shutdown of all neighbor sessions

    Example:
        >>> unconfigure_bgp_shutdown_all_sessions(device)
    """
    log.info(
        f"Removing BGP shutdown all sessions from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global shutdown-all-sessions', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP shutdown all sessions from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_silent_drop(device, enabled=True,
                              network_instance='default',
                              protocol_instance='default'):
    """Configure silent-drop of unconfigured inbound BGP connections.

    adoc / device source: Border_Gateway_Protocol.adoc:global ? (device)

    Args:
        device (obj): Device object
        enabled (bool, optional): Silently drop. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure silent-drop of unconfigured inbound BGP connections

    Example:
        >>> configure_bgp_silent_drop(device, enabled=True)
    """
    log.info(
        f"Configuring BGP silent drop on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global silent-drop {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP silent drop on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_silent_drop(device, network_instance='default',
                                protocol_instance='default'):
    """Remove silent-drop of unconfigured inbound BGP connections.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove silent-drop of unconfigured inbound BGP connections

    Example:
        >>> unconfigure_bgp_silent_drop(device)
    """
    log.info(
        f"Removing BGP silent drop from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global silent-drop', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP silent drop from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_mandate_ebgp_policy(device, enabled=True,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Configure the requirement for an explicit eBGP policy (RFC 8212).

    adoc / device source: Border_Gateway_Protocol.adoc:global ? (device)

    Args:
        device (obj): Device object
        enabled (bool, optional): Require an explicit policy before eBGP routes
            propagate. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the requirement for an explicit eBGP policy (RFC 8212)

    Example:
        >>> configure_bgp_mandate_ebgp_policy(device, enabled=True)
    """
    log.info(
        f"Configuring BGP mandate ebgp policy on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global mandate-ebgp-policy {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP mandate ebgp policy on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_mandate_ebgp_policy(device, network_instance='default',
                                        protocol_instance='default'):
    """Remove the requirement for an explicit eBGP policy (RFC 8212).

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the requirement for an explicit eBGP policy (RFC 8212)

    Example:
        >>> unconfigure_bgp_mandate_ebgp_policy(device)
    """
    log.info(
        f"Removing BGP mandate ebgp policy from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global mandate-ebgp-policy', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP mandate ebgp policy from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_compatibility_suppress_nexthop_attribute(device, enabled=True,
                                                           network_instance='default',
                                                           protocol_instance='default'):
    """Configure suppression of the NEXT_HOP attribute in multi-protocol updates.

    adoc / device source: Border_Gateway_Protocol.adoc:global compatibility ? (device)

    Args:
        device (obj): Device object
        enabled (bool, optional): Suppress the attribute. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure suppression of the NEXT_HOP attribute in multi-protocol updates

    Example:
        >>> configure_bgp_compatibility_suppress_nexthop_attribute(device, enabled=True)
    """
    log.info(
        f"Configuring BGP compatibility suppress nexthop attribute on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global compatibility suppress-nexthop-attribute {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP compatibility suppress nexthop attribute on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_compatibility_suppress_nexthop_attribute(device, network_instance='default',
                                                             protocol_instance='default'):
    """Remove suppression of the NEXT_HOP attribute in multi-protocol updates.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove suppression of the NEXT_HOP attribute in multi-protocol updates

    Example:
        >>> unconfigure_bgp_compatibility_suppress_nexthop_attribute(device)
    """
    log.info(
        f"Removing BGP compatibility suppress nexthop attribute from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global compatibility suppress-nexthop-attribute', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP compatibility suppress nexthop attribute from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_compatibility_strict_common_afi_safi_check(device, enabled=True,
                                                             network_instance='default',
                                                             protocol_instance='default'):
    """Configure the strict common AFI/SAFI check for BGP peering.

    adoc / device source: Border_Gateway_Protocol.adoc:global compatibility ? (device)

    Args:
        device (obj): Device object
        enabled (bool, optional): Require a common AFI/SAFI. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the strict common AFI/SAFI check for BGP peering

    Example:
        >>> configure_bgp_compatibility_strict_common_afi_safi_check(device, enabled=True)
    """
    log.info(
        f"Configuring BGP compatibility strict common afi safi check on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global compatibility strict-common-afi-safi-check {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP compatibility strict common afi safi check on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_compatibility_strict_common_afi_safi_check(device, network_instance='default',
                                                               protocol_instance='default'):
    """Remove the strict common AFI/SAFI check for BGP peering.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the strict common AFI/SAFI check for BGP peering

    Example:
        >>> unconfigure_bgp_compatibility_strict_common_afi_safi_check(device)
    """
    log.info(
        f"Removing BGP compatibility strict common afi safi check from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global compatibility strict-common-afi-safi-check', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP compatibility strict common afi safi check from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_update_wait_data_plane(device, afi_safi, enabled=True,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure deferral of BGP updates until the data plane acknowledges programming.

    adoc / device source: Border_Gateway_Protocol.adoc:837-847

    Args:
        device (obj): Device object
        afi_safi (str): ``'IPV4_UNICAST'`` or ``'IPV6_UNICAST'`` — see
            :data:`BGP_UPDATE_WAIT_AFI_SAFIS` (adoc:837). Enforced.
        enabled (bool, optional): Wait for the data plane. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure deferral of BGP updates until the data plane acknowledges programming

    Example:
        >>> configure_bgp_update_wait_data_plane(device, afi_safi='IPV4_UNICAST')
    """
    if afi_safi not in BGP_UPDATE_WAIT_AFI_SAFIS:
        raise ValueError(
            f"update-wait-data-plane is only available under "
            f"{', '.join(BGP_UPDATE_WAIT_AFI_SAFIS)}. Got '{afi_safi}'."
        )

    log.info(
        f"Configuring BGP update wait data plane on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global afi-safi {afi_safi} update-wait-data-plane {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP update wait data plane on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_update_wait_data_plane(device, afi_safi, network_instance='default',
                                           protocol_instance='default'):
    """Remove deferral of BGP updates until the data plane acknowledges programming.

    Args:
        device (obj): Device object
        afi_safi (str): ``'IPV4_UNICAST'`` or ``'IPV6_UNICAST'`` — see
            :data:`BGP_UPDATE_WAIT_AFI_SAFIS` (adoc:837). Enforced.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove deferral of BGP updates until the data plane acknowledges programming

    Example:
        >>> unconfigure_bgp_update_wait_data_plane(device)
    """
    if afi_safi not in BGP_UPDATE_WAIT_AFI_SAFIS:
        raise ValueError(
            f"update-wait-data-plane is only available under "
            f"{', '.join(BGP_UPDATE_WAIT_AFI_SAFIS)}. Got '{afi_safi}'."
        )

    log.info(
        f"Removing BGP update wait data plane from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no global afi-safi {afi_safi} update-wait-data-plane', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP update wait data plane from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_rtfilter_vpn_update_delay(device, delay,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Configure the RTFILTER End-of-RIB wait before sending updates.

    adoc / device source: Border_Gateway_Protocol.adoc:RTFILTER ? (device)

    Args:
        device (obj): Device object
        delay (int): Maximum seconds to wait for the RTFILTER End-of-RIB.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the RTFILTER End-of-RIB wait before sending updates

    Example:
        >>> configure_bgp_rtfilter_vpn_update_delay(device, delay=90)
    """
    log.info(
        f"Configuring BGP rtfilter vpn update delay on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'global afi-safi RTFILTER vpn-update-delay {delay}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP rtfilter vpn update delay on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_rtfilter_vpn_update_delay(device, network_instance='default',
                                              protocol_instance='default'):
    """Remove the RTFILTER End-of-RIB wait before sending updates.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the RTFILTER End-of-RIB wait before sending updates

    Example:
        >>> unconfigure_bgp_rtfilter_vpn_update_delay(device)
    """
    log.info(
        f"Removing BGP rtfilter vpn update delay from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global afi-safi RTFILTER vpn-update-delay', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP rtfilter vpn update delay from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_egress_peer_engineering(device, neighbor, enabled=True,
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Configure BGP-LU based egress peer engineering for a neighbor.

    adoc / device source: Border_Gateway_Protocol.adoc:egress-peer-engineering ? (device)

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        enabled (bool, optional): Enable BGP-LU EPE. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP-LU based egress peer engineering for a neighbor

    Example:
        >>> configure_bgp_neighbor_egress_peer_engineering(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Configuring BGP neighbor egress peer engineering on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'egress-peer-engineering labeled-unicast enable {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor egress peer engineering on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_egress_peer_engineering(device, neighbor, network_instance='default',
                                                     protocol_instance='default'):
    """Remove BGP-LU based egress peer engineering for a neighbor.

    Note:
        Emits ``no egress-peer-engineering``, removing the WHOLE container — not
        just the ``labeled-unicast enable`` leaf its configure counterpart sets.
        Lab-verified on rtr1 2026-08-17.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP-LU based egress peer engineering for a neighbor

    Example:
        >>> unconfigure_bgp_neighbor_egress_peer_engineering(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor egress peer engineering from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, 'no egress-peer-engineering', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor egress peer engineering from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_rtfilter_send_default_route(device, neighbor, enabled=True,
                                                       network_instance='default',
                                                       protocol_instance='default'):
    """Configure sending of the default Route Target to an RR client.

    adoc / device source: Border_Gateway_Protocol.adoc:2145-2151

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        enabled (bool, optional): Send the default RT (prefix 0, length 0) to this
            client. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure sending of the default Route Target to an RR client

    Example:
        >>> configure_bgp_neighbor_rtfilter_send_default_route(device, neighbor='12.1.1.2', enabled=False)
    """
    log.info(
        f"Configuring BGP neighbor rtfilter send default route on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'afi-safi RTFILTER send-default-route {"true" if enabled else "false"}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor rtfilter send default route on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_neighbor_rtfilter_send_default_route(device, neighbor, network_instance='default',
                                                         protocol_instance='default'):
    """Remove sending of the default Route Target to an RR client.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove sending of the default Route Target to an RR client

    Example:
        >>> unconfigure_bgp_neighbor_rtfilter_send_default_route(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor rtfilter send default route from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, 'no afi-safi RTFILTER send-default-route', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor rtfilter send default route from {device.name}. "
            f"Error:\n{e}"
        )


#: Global AFI/SAFIs that carry ``update-wait-data-plane`` (adoc:837).
BGP_UPDATE_WAIT_AFI_SAFIS = ('IPV4_UNICAST', 'IPV6_UNICAST')

#: Next-hop treatment values for a neighbor AFI/SAFI.
#: Device-confirmed enum (`neighbor <ip> afi-safi <af> next-hop ?`).
BGP_NEXT_HOP_TYPES = ('SELF', 'UNCHANGED')

#: Flowspec AFI/SAFIs carrying `sample-and-drop` and `rt-redirect` (adoc:297).
BGP_FLOWSPEC_AFI_SAFIS = ('IPV4_FLOWSPEC', 'IPV6_FLOWSPEC')

#: `rt-redirect next-hop` values (adoc:314,324).
BGP_RT_REDIRECT_NEXT_HOPS = ('DEFAULT', 'BGP_NLRI')


def _graceful_shutdown_lines(prefix, enable, set_local_preference_zero, set_med_maximum):
    """Build the graceful-shutdown leaf lines shared by the global and neighbor forms.

    Note:
        The leaf is spelled ``enable``, NOT ``enabled`` — unlike most arcOS
        booleans. Confirmed on rtr1 2026-08-17.

    Raises:
        ValueError: If a sub-leaf is requested with ``enable=False``.
            ``Border_Gateway_Protocol.adoc:1182``: "graceful-shutdown must be
            enabled first to allow the other parameters to be configured." The
            batch previously emitted ``enable false`` followed by the sub-leaves,
            an ordering the adoc forbids; refusing is safer than emitting it,
            since arcOS accepts-and-ignores some malformed input.
    """
    if not enable and (set_local_preference_zero is not None
                       or set_med_maximum is not None):
        raise ValueError(
            "graceful-shutdown sub-leaves (set_local_preference_zero, "
            "set_med_maximum) require enable=True; adoc:1182 states "
            "graceful-shutdown must be enabled before the other parameters "
            "can be configured"
        )
    lines = [f'{prefix}graceful-shutdown enable {"true" if enable else "false"}']
    if set_local_preference_zero is not None:
        lines.append(
            f'{prefix}graceful-shutdown set-local-preference-zero '
            f'{"true" if set_local_preference_zero else "false"}')
    if set_med_maximum is not None:
        lines.append(
            f'{prefix}graceful-shutdown set-med-maximum '
            f'{"true" if set_med_maximum else "false"}')
    return lines


def configure_bgp_graceful_shutdown(device, enable=True,
                                    set_local_preference_zero=None,
                                    set_med_maximum=None,
                                    network_instance='default',
                                    protocol_instance='default'):
    """Configure BGP graceful shutdown (RFC 8326) for the whole instance.

    Args:
        device (obj): Device object
        enable (bool, optional): Enable graceful shutdown. Defaults to True.
        set_local_preference_zero (bool, optional): Advertise LOCAL_PREF 0 on
            affected paths. Defaults to None (leave unset).
        set_med_maximum (bool, optional): Advertise maximum MED on affected paths.
            Defaults to None (leave unset).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure graceful shutdown

    Example:
        >>> configure_bgp_graceful_shutdown(device, set_local_preference_zero=True)
    """
    log.info(
        f"Configuring BGP global graceful-shutdown on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx] + _graceful_shutdown_lines(
        'global ', enable, set_local_preference_zero, set_med_maximum) + ['!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP global graceful-shutdown on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_graceful_shutdown(device, network_instance='default',
                                      protocol_instance='default'):
    """Remove instance-wide BGP graceful shutdown.

    Note:
        Emits ``no global graceful-shutdown``, removing the WHOLE container —
        ``enable``, ``set-local-preference-zero`` and ``set-med-maximum``
        together — not only the leaves a given configure call set.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove graceful shutdown

    Example:
        >>> unconfigure_bgp_graceful_shutdown(device)
    """
    log.info(
        f"Removing BGP global graceful-shutdown from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global graceful-shutdown', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP global graceful-shutdown from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_neighbor_graceful_shutdown(device, neighbor, enable=True,
                                             set_local_preference_zero=None,
                                             set_med_maximum=None,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure BGP graceful shutdown for a single neighbor.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        enable (bool, optional): Enable graceful shutdown. Defaults to True.
        set_local_preference_zero (bool, optional): Advertise LOCAL_PREF 0.
            Defaults to None (leave unset).
        set_med_maximum (bool, optional): Advertise maximum MED. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure neighbor graceful shutdown

    Example:
        >>> configure_bgp_neighbor_graceful_shutdown(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Configuring BGP neighbor {neighbor} graceful-shutdown on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx] + _graceful_shutdown_lines(
        '', enable, set_local_preference_zero, set_med_maximum) + ['!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} graceful-shutdown on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_graceful_shutdown(device, neighbor,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove graceful shutdown from a single neighbor.

    Note:
        Emits ``no graceful-shutdown``, removing the WHOLE container, not only
        the leaves a given configure call set.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove neighbor graceful shutdown

    Example:
        >>> unconfigure_bgp_neighbor_graceful_shutdown(device, neighbor='10.1.1.2')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} graceful-shutdown from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, 'no graceful-shutdown', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} graceful-shutdown from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_neighbor_next_hop(device, neighbor, afi_safi, next_hop,
                                    network_instance='default',
                                    protocol_instance='default'):
    """Configure next-hop treatment for a neighbor AFI/SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        next_hop (str): One of :data:`BGP_NEXT_HOP_TYPES` — ``'SELF'`` or ``'UNCHANGED'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``next_hop`` is not SELF or UNCHANGED
        SubCommandFailure: Failed to configure the next-hop type

    Example:
        >>> configure_bgp_neighbor_next_hop(
        ...     device, neighbor='10.1.1.2', afi_safi='IPV4_UNICAST', next_hop='SELF')
    """
    if next_hop not in BGP_NEXT_HOP_TYPES:
        raise ValueError(
            f"Invalid next-hop type '{next_hop}'. Must be one of: "
            f"{', '.join(BGP_NEXT_HOP_TYPES)}"
        )

    log.info(
        f"Configuring BGP neighbor {neighbor} afi-safi {afi_safi} next-hop "
        f"{next_hop} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'afi-safi {afi_safi} next-hop {next_hop}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP neighbor {neighbor} afi-safi {afi_safi} "
            f"next-hop on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_neighbor_next_hop(device, neighbor, afi_safi,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Remove next-hop treatment from a neighbor AFI/SAFI.

    Args:
        device (obj): Device object
        neighbor (str): Neighbor address.
        afi_safi (str): AFI/SAFI, e.g. ``'IPV4_UNICAST'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the next-hop type

    Example:
        >>> unconfigure_bgp_neighbor_next_hop(
        ...     device, neighbor='10.1.1.2', afi_safi='IPV4_UNICAST')
    """
    log.info(
        f"Removing BGP neighbor {neighbor} afi-safi {afi_safi} next-hop from "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    ctx = _build_neighbor_context(neighbor, network_instance, protocol_instance)
    config = [ctx, f'no afi-safi {afi_safi} next-hop', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP neighbor {neighbor} afi-safi {afi_safi} "
            f"next-hop from {device.name}. Error:\n{e}"
        )


def configure_bgp_flowspec_sample_and_drop(device, afi_safi, enabled=True,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure Flowspec sample-and-drop for a Flowspec AFI/SAFI.

    adoc: Border_Gateway_Protocol.adoc:295-297

    Args:
        device (obj): Device object
        afi_safi (str): One of :data:`BGP_FLOWSPEC_AFI_SAFIS`.
        enabled (bool, optional): Sample matched traffic before dropping.
            Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``afi_safi`` is not a Flowspec AFI/SAFI
        SubCommandFailure: Failed to configure sample-and-drop

    Example:
        >>> configure_bgp_flowspec_sample_and_drop(device, afi_safi='IPV4_FLOWSPEC')
    """
    if afi_safi not in BGP_FLOWSPEC_AFI_SAFIS:
        raise ValueError(
            f"sample-and-drop is only available for Flowspec AFI/SAFIs. Got "
            f"'{afi_safi}'; expected one of: {', '.join(BGP_FLOWSPEC_AFI_SAFIS)}"
        )

    log.info(
        f"Configuring BGP flowspec sample-and-drop under global afi-safi {afi_safi} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        ctx,
        f'global afi-safi {afi_safi} sample-and-drop {"true" if enabled else "false"}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP flowspec sample-and-drop under global "
            f"afi-safi {afi_safi} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_flowspec_sample_and_drop(device, afi_safi,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove Flowspec sample-and-drop from a Flowspec AFI/SAFI.

    Args:
        device (obj): Device object
        afi_safi (str): One of :data:`BGP_FLOWSPEC_AFI_SAFIS`.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``afi_safi`` is not a Flowspec AFI/SAFI
        SubCommandFailure: Failed to remove sample-and-drop

    Example:
        >>> unconfigure_bgp_flowspec_sample_and_drop(device, afi_safi='IPV4_FLOWSPEC')
    """
    if afi_safi not in BGP_FLOWSPEC_AFI_SAFIS:
        raise ValueError(
            f"sample-and-drop is only available for Flowspec AFI/SAFIs. Got "
            f"'{afi_safi}'; expected one of: {', '.join(BGP_FLOWSPEC_AFI_SAFIS)}"
        )

    log.info(
        f"Removing BGP flowspec sample-and-drop from global afi-safi {afi_safi} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no global afi-safi {afi_safi} sample-and-drop', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP flowspec sample-and-drop from global "
            f"afi-safi {afi_safi} on {device.name}. Error:\n{e}"
        )


def configure_bgp_flowspec_rt_redirect_next_hop(device, afi_safi, next_hop,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure the Flowspec rt-redirect next-hop selection.

    adoc: Border_Gateway_Protocol.adoc:305-324

    Args:
        device (obj): Device object
        afi_safi (str): One of :data:`BGP_FLOWSPEC_AFI_SAFIS`.
        next_hop (str): One of :data:`BGP_RT_REDIRECT_NEXT_HOPS` — ``'DEFAULT'``
            or ``'BGP_NLRI'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``afi_safi`` or ``next_hop`` is invalid
        SubCommandFailure: Failed to configure rt-redirect next-hop

    Example:
        >>> configure_bgp_flowspec_rt_redirect_next_hop(
        ...     device, afi_safi='IPV4_FLOWSPEC', next_hop='DEFAULT')
    """
    if afi_safi not in BGP_FLOWSPEC_AFI_SAFIS:
        raise ValueError(
            f"rt-redirect is only available for Flowspec AFI/SAFIs. Got "
            f"'{afi_safi}'; expected one of: {', '.join(BGP_FLOWSPEC_AFI_SAFIS)}"
        )
    if next_hop not in BGP_RT_REDIRECT_NEXT_HOPS:
        raise ValueError(
            f"Invalid rt-redirect next-hop '{next_hop}'. Must be one of: "
            f"{', '.join(BGP_RT_REDIRECT_NEXT_HOPS)}"
        )

    log.info(
        f"Configuring BGP flowspec rt-redirect next-hop {next_hop} under global "
        f"afi-safi {afi_safi} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        ctx,
        f'global afi-safi {afi_safi} rt-redirect next-hop {next_hop}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP flowspec rt-redirect next-hop under global "
            f"afi-safi {afi_safi} on {device.name}. Error:\n{e}"
        )


def unconfigure_bgp_flowspec_rt_redirect_next_hop(device, afi_safi,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Remove the Flowspec rt-redirect next-hop selection.

    Args:
        device (obj): Device object
        afi_safi (str): One of :data:`BGP_FLOWSPEC_AFI_SAFIS`.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``afi_safi`` is not a Flowspec AFI/SAFI
        SubCommandFailure: Failed to remove rt-redirect next-hop

    Example:
        >>> unconfigure_bgp_flowspec_rt_redirect_next_hop(
        ...     device, afi_safi='IPV4_FLOWSPEC')
    """
    if afi_safi not in BGP_FLOWSPEC_AFI_SAFIS:
        raise ValueError(
            f"rt-redirect is only available for Flowspec AFI/SAFIs. Got "
            f"'{afi_safi}'; expected one of: {', '.join(BGP_FLOWSPEC_AFI_SAFIS)}"
        )

    log.info(
        f"Removing BGP flowspec rt-redirect next-hop from global afi-safi "
        f"{afi_safi} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no global afi-safi {afi_safi} rt-redirect', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP flowspec rt-redirect from global afi-safi "
            f"{afi_safi} on {device.name}. Error:\n{e}"
        )


def configure_bgp_telemetry(device, neighbor_stream=None, prefix_stream=None,
                            network_instance='default',
                            protocol_instance='default'):
    """Configure BGP telemetry streaming.

    Args:
        device (obj): Device object
        neighbor_stream (bool, optional): Stream neighbor information.
            Defaults to None (leave unset).
        prefix_stream (bool, optional): Stream prefix information.
            Defaults to None (leave unset).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If neither stream is specified
        SubCommandFailure: Failed to configure telemetry

    Example:
        >>> configure_bgp_telemetry(device, neighbor_stream=True, prefix_stream=True)
    """
    if neighbor_stream is None and prefix_stream is None:
        raise ValueError(
            "configure_bgp_telemetry requires at least one of 'neighbor_stream' "
            "or 'prefix_stream'"
        )

    log.info(
        f"Configuring BGP global telemetry on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx]
    if neighbor_stream is not None:
        config.append(
            f'global telemetry neighbor-stream-enabled {"true" if neighbor_stream else "false"}')
    if prefix_stream is not None:
        config.append(
            f'global telemetry prefix-stream-enabled {"true" if prefix_stream else "false"}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP global telemetry on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_telemetry(device, network_instance='default',
                              protocol_instance='default'):
    """Remove BGP telemetry streaming configuration.

    Note:
        Emits ``no global telemetry``, removing the WHOLE container — both
        ``neighbor-stream-enabled`` and ``prefix-stream-enabled`` — even if the
        caller only ever set one of them.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove telemetry

    Example:
        >>> unconfigure_bgp_telemetry(device)
    """
    log.info(
        f"Removing BGP global telemetry from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, 'no global telemetry', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP global telemetry from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_rtr_server(device, server_name, address, port, preference,
                             local_address=None,
                             network_instance='default',
                             protocol_instance='default'):
    """Configure an RPKI RTR server for origin validation.

    Args:
        device (obj): Device object
        server_name (str): RTR server name, e.g. ``'rpki-rtr'``.
        address (str): Server IP address. **Mandatory** — see the Note.
        port (int): Server TCP port. **Mandatory** — see the Note.
        preference (int): Server preference. **Mandatory** — see the Note.
        local_address (str, optional): Local transport address or interface name.
            Defaults to None (unset).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the RTR server

    Note:
        ``rtr-server`` sits at PROTOCOL level, a sibling of ``global`` — confirmed
        on rtr1 2026-08-17.

    Note:
        ``address``, ``port`` and ``preference`` are all MANDATORY at commit
        time, so they are required parameters rather than optional ones. Omitting
        any of them aborts, and the device reports them one at a time
        (verified on rtr1 2026-08-18)::

            rtr-server t1                       -> Aborted: '... t1 port' is not configured
            rtr-server t1 port 3323             -> Aborted: '... t1 preference' is not configured
            rtr-server t1 port .. preference .. -> Aborted: '... t1 address' is not configured
            all three set                       -> Commit complete.

        An earlier revision made all three optional, so
        ``configure_bgp_rtr_server(device, server_name='x')`` emitted only the
        bare key line and always aborted.

    Example:
        >>> configure_bgp_rtr_server(
        ...     device, server_name='rpki-rtr', address='10.1.1.9', port=3323,
        ...     preference=1)
    """
    log.info(
        f"Configuring BGP rtr-server {server_name} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        ctx,
        f'rtr-server {server_name}',
        f'rtr-server {server_name} address {address}',
        f'rtr-server {server_name} port {port}',
        f'rtr-server {server_name} preference {preference}',
    ]
    if local_address is not None:
        config.append(f'rtr-server {server_name} local-address {local_address}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP rtr-server {server_name} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bgp_rtr_server(device, server_name,
                               network_instance='default',
                               protocol_instance='default'):
    """Remove an RPKI RTR server.

    Args:
        device (obj): Device object
        server_name (str): RTR server name, e.g. ``'rpki-rtr'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the RTR server

    Example:
        >>> unconfigure_bgp_rtr_server(device, server_name='rpki-rtr')
    """
    log.info(
        f"Removing BGP rtr-server {server_name} from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    ctx = _build_bgp_config_context(network_instance, protocol_instance)
    config = [ctx, f'no rtr-server {server_name}', '!']

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP rtr-server {server_name} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_bgp_global_import_policy(device, afi_safi, policies,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure BGP global (instance-wide) import policy for an AFI-SAFI.

    Applies an import-policy chain at ``global afi-safi`` scope, i.e. to the
    whole BGP instance rather than a single neighbor or peer-group.

    CLI emitted::

        network-instance {ni} protocol BGP {pi}
         global afi-safi {afi_safi}
          apply-policy import-policy [ {policies} ]
        !

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        policies (list or str): Policy name(s) to apply as import
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP global import policy

    Example:
        >>> configure_bgp_global_import_policy(device, 'IPV4_UNICAST', ['X1'])

    Note:
        The BGP instance must already have both ``global as`` and
        ``global router-id``, or the commit aborts with
        ``Local-AS and Router-ID must be configured`` — this is a
        commit-time-only constraint that a parse check will not catch. See
        :func:`configure_bgp_as_number` and :func:`configure_bgp_router_id`.
        Verified on rtr1 2026-08-20.
    """
    log.info(
        f"Configuring BGP global import-policy for {afi_safi} on {device.name}"
    )

    if isinstance(policies, (list, tuple)):
        pol_str = ' '.join(str(p) for p in policies)
    else:
        pol_str = str(policies)

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'apply-policy import-policy [ {pol_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP global import-policy for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_global_import_policy(device, afi_safi,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Remove the BGP global import policy for an AFI-SAFI.

    CLI emitted::

        network-instance {ni} protocol BGP {pi}
         no global afi-safi {afi_safi} apply-policy import-policy
        !

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP global import policy

    Example:
        >>> unconfigure_bgp_global_import_policy(device, 'IPV4_UNICAST')

    Note:
        Exact inverse of :func:`configure_bgp_global_import_policy`. Removes
        only the import-policy leaf; any export-policy on the same AFI-SAFI is
        left intact. An empty ``global afi-safi`` container may remain —
        assert on the leaf, not the block.

        The whole path is emitted flat on the ``no`` line rather than entering
        the ``global afi-safi`` submode: a bare ``no <leaf>`` after a submode
        line that was accepted-and-ignored can land at the parent scope. This
        matches every post-T1 BGP unconfigure in this module. Verified on rtr1
        2026-08-20 — import removed, export and ``global as``/``router-id``
        left intact.
    """
    log.info(
        f"Removing BGP global import-policy for {afi_safi} from {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'no global afi-safi {afi_safi} apply-policy import-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP global import-policy for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_bgp_global_export_policy(device, afi_safi, policies,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure BGP global (instance-wide) export policy for an AFI-SAFI.

    Applies an export-policy chain at ``global afi-safi`` scope, i.e. to the
    whole BGP instance rather than a single neighbor or peer-group. This is
    also the attachment point for SR-Policy colour steering, where an
    export-policy adds a colour extended-community to advertised routes.

    CLI emitted::

        network-instance {ni} protocol BGP {pi}
         global afi-safi {afi_safi}
          apply-policy export-policy [ {policies} ]
        !

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        policies (list or str): Policy name(s) to apply as export
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BGP global export policy

    Example:
        >>> configure_bgp_global_export_policy(
        ...     device, 'IPV4_UNICAST', ['add-color'])

    Note:
        The BGP instance must already have both ``global as`` and
        ``global router-id``, or the commit aborts with
        ``Local-AS and Router-ID must be configured``. See
        :func:`configure_bgp_as_number` and :func:`configure_bgp_router_id`.
        Verified on rtr1 2026-08-20.
    """
    log.info(
        f"Configuring BGP global export-policy for {afi_safi} on {device.name}"
    )

    if isinstance(policies, (list, tuple)):
        pol_str = ' '.join(str(p) for p in policies)
    else:
        pol_str = str(policies)

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'global afi-safi {afi_safi}',
        f'apply-policy export-policy [ {pol_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BGP global export-policy for {afi_safi} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_bgp_global_export_policy(device, afi_safi,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Remove the BGP global export policy for an AFI-SAFI.

    CLI emitted::

        network-instance {ni} protocol BGP {pi}
         no global afi-safi {afi_safi} apply-policy export-policy
        !

    Args:
        device (obj): Device object
        afi_safi (str): AFI-SAFI name (e.g., 'IPV4_UNICAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): BGP protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BGP global export policy

    Example:
        >>> unconfigure_bgp_global_export_policy(device, 'IPV4_UNICAST')

    Note:
        Exact inverse of :func:`configure_bgp_global_export_policy`. Removes
        only the export-policy leaf; any import-policy on the same AFI-SAFI is
        left intact.

        The whole path is emitted flat on the ``no`` line rather than entering
        the ``global afi-safi`` submode, matching every post-T1 BGP unconfigure
        in this module — a bare ``no <leaf>`` after an accepted-and-ignored
        submode line can land at the parent scope. Verified on rtr1
        2026-08-20.
    """
    log.info(
        f"Removing BGP global export-policy for {afi_safi} from {device.name}"
    )

    bgp_context = _build_bgp_config_context(network_instance, protocol_instance)
    config = [
        bgp_context,
        f'no global afi-safi {afi_safi} apply-policy export-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BGP global export-policy for {afi_safi} from "
            f"{device.name}. Error:\n{e}"
        )
