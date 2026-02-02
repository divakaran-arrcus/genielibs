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
