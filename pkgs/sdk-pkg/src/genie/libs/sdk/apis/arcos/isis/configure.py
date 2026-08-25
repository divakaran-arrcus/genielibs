"""Common configure functions for ISIS on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def _build_isis_config_context(network_instance='default', protocol_instance='default'):
    """Helper function to build ISIS configuration context path.
    
    Args:
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        str: Configuration context path for ISIS
    
    Example:
        >>> _build_isis_config_context('default', 'isis1')
        'network-instance default protocol ISIS isis1'
    """
    return f'network-instance {network_instance} protocol ISIS {protocol_instance}'


def _build_interface_context(interface, network_instance='default', protocol_instance='default'):
    """Helper function to build ISIS interface configuration context path.
    
    Args:
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        str: Configuration context path for ISIS interface
    
    Example:
        >>> _build_interface_context('ethernet-1/1', 'default', 'isis1')
        'network-instance default protocol ISIS isis1 interface ethernet-1/1'
    """
    return f'{_build_isis_config_context(network_instance, protocol_instance)} interface {interface}'


def _convert_level_format(level):
    """Convert level format from lowercase with underscores to ArcOS format.
    
    Args:
        level (str): Level in format 'level_1', 'level_2', or 'level_1_2'
    
    Returns:
        str: Level in ArcOS format 'LEVEL_1', 'LEVEL_2', or 'LEVEL_1_2'
    
    Raises:
        ValueError: If level format is invalid
    
    Example:
        >>> _convert_level_format('level_1')
        'LEVEL_1'
        >>> _convert_level_format('level_1_2')
        'LEVEL_1_2'
    """
    valid_levels = {
        'level_1': 'LEVEL_1',
        'level_2': 'LEVEL_2',
        'level_1_2': 'LEVEL_1_2'
    }
    
    if level not in valid_levels:
        raise ValueError(
            f"Invalid level '{level}'. Must be one of: {', '.join(valid_levels.keys())}"
        )
    
    return valid_levels[level]


def _get_level_number(level):
    """Extract level number from level format.
    
    Args:
        level (str): Level in format 'level_1' or 'level_2'
    
    Returns:
        int: Level number (1 or 2)
    
    Raises:
        ValueError: If level format is invalid or is level_1_2
    
    Example:
        >>> _get_level_number('level_1')
        1
        >>> _get_level_number('level_2')
        2
    """
    if level == 'level_1':
        return 1
    elif level == 'level_2':
        return 2
    else:
        raise ValueError(
            f"Invalid level '{level}' for single-level operation. "
            "Must be 'level_1' or 'level_2'"
        )

def configure_isis_net_address(device, net_address, network_instance='default', 
                                protocol_instance='default'):
    """Configure ISIS network address (NET).
    
    Args:
        device (obj): Device object
        net_address (str): NET address (e.g., '49.0001.1921.6800.1001.00')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure ISIS NET address
    
    Example:
        >>> configure_isis_net_address(
        ...     device=device,
        ...     net_address='49.0001.1921.6800.1001.00',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Configuring ISIS NET address {net_address} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global net [ {net_address} ]',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS NET address {net_address} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_net_address(device, net_address, network_instance='default',
                                  protocol_instance='default'):
    """Remove ISIS network address (NET).
    
    Args:
        device (obj): Device object
        net_address (str): NET address to remove (e.g., '49.0001.1921.6800.1001.00')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove ISIS NET address
    
    Example:
        >>> unconfigure_isis_net_address(
        ...     device=device,
        ...     net_address='49.0001.1921.6800.1001.00',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Removing ISIS NET address {net_address} from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'no global net [ {net_address} ]',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS NET address {net_address} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_isis_instance(device, network_instance='default', protocol_instance='default'):
    """Create ISIS protocol instance.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to create ISIS instance
    
    Example:
        >>> configure_isis_instance(
        ...     device=device,
        ...     network_instance='default',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Creating ISIS instance on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    config = [
        _build_isis_config_context(network_instance, protocol_instance),
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not create ISIS instance on {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


def unconfigure_isis_instance(device, network_instance='default', protocol_instance='default'):
    """Remove entire ISIS protocol instance.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove ISIS instance
    
    Example:
        >>> unconfigure_isis_instance(
        ...     device=device,
        ...     network_instance='default',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Removing ISIS instance from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    config = [
        f'no {_build_isis_config_context(network_instance, protocol_instance)}'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS instance from {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


# ============================================================================
# Category 2: Interface Configuration
# ============================================================================

# ============================================================================
# 2.1 Interface ISIS Enablement
# ============================================================================


def configure_isis_interface_ipv4(device, interface, level=None, network_instance='default',
                                   protocol_instance='default'):
    """Enable ISIS IPv4 unicast on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        level (str, optional): ISIS level ('level_1', 'level_2', 'level_1_2'). Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to enable ISIS IPv4 on interface
    
    Example:
        >>> configure_isis_interface_ipv4(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     level='level_2',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Enabling ISIS IPv4 on interface {interface} on {device.name} "
        f"(level: {level}, network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        'enabled true',
        'exit'  # Exit AF submode back to interface level
    ]
    
    # Add level configuration if specified (at interface level, not in AF)
    if level:
        if level in ['level_1', 'level_1_2']:
            config.extend([
                'level 1',
                'enabled true',
                'exit'
            ])
        if level in ['level_2', 'level_1_2']:
            config.extend([
                'level 2',
                'enabled true',
                'exit'
            ])
    
    config.append('!')
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not enable ISIS IPv4 on interface {interface} on {device.name}. "
            f"Error:\n{e}"
        )


def configure_isis_interface_ipv6(device, interface, level=None, network_instance='default',
                                   protocol_instance='default'):
    """Enable ISIS IPv6 unicast on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        level (str, optional): ISIS level ('level_1', 'level_2', 'level_1_2'). Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to enable ISIS IPv6 on interface
    
    Example:
        >>> configure_isis_interface_ipv6(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     level='level_2',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Enabling ISIS IPv6 on interface {interface} on {device.name} "
        f"(level: {level}, network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        'enabled true',
        'exit'  # Exit AF submode back to interface level
    ]
    
    # Add level configuration if specified (at interface level, not in AF)
    if level:
        if level in ['level_1', 'level_1_2']:
            config.extend([
                'level 1',
                'enabled true',
                'exit'
            ])
        if level in ['level_2', 'level_1_2']:
            config.extend([
                'level 2',
                'enabled true',
                'exit'
            ])
    
    config.append('!')
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not enable ISIS IPv6 on interface {interface} on {device.name}. "
            f"Error:\n{e}"
        )


def configure_isis_interface(device, interface, ipv4=True, ipv6=False, level=None,
                              network_instance='default', protocol_instance='default'):
    """Enable ISIS on interface (both IPv4 and/or IPv6).
    
    This is a convenience wrapper that calls configure_isis_interface_ipv4 and/or
    configure_isis_interface_ipv6 based on the parameters.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        ipv4 (bool, optional): Enable IPv4. Defaults to True.
        ipv6 (bool, optional): Enable IPv6. Defaults to False.
        level (str, optional): ISIS level ('level_1', 'level_2', 'level_1_2'). Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to enable ISIS on interface
    
    Example:
        >>> # Enable both IPv4 and IPv6
        >>> configure_isis_interface(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     ipv4=True,
        ...     ipv6=True,
        ...     level='level_2',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Enabling ISIS on interface {interface} on {device.name} "
        f"(IPv4: {ipv4}, IPv6: {ipv6}, level: {level}, "
        f"network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    if ipv4:
        configure_isis_interface_ipv4(
            device, interface, level=level,
            network_instance=network_instance,
            protocol_instance=protocol_instance
        )
    
    if ipv6:
        configure_isis_interface_ipv6(
            device, interface, level=level,
            network_instance=network_instance,
            protocol_instance=protocol_instance
        )


def unconfigure_isis_interface_ipv4(device, interface, network_instance='default',
                                     protocol_instance='default'):
    """Disable ISIS IPv4 on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable ISIS IPv4 on interface
    
    Example:
        >>> unconfigure_isis_interface_ipv4(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Disabling ISIS IPv4 on interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no af IPV4 UNICAST',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable ISIS IPv4 on interface {interface} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_interface_ipv6(device, interface, network_instance='default',
                                     protocol_instance='default'):
    """Disable ISIS IPv6 on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable ISIS IPv6 on interface
    
    Example:
        >>> unconfigure_isis_interface_ipv6(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Disabling ISIS IPv6 on interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no af IPV6 UNICAST',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable ISIS IPv6 on interface {interface} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_interface(device, interface, ipv4=True, ipv6=False,
                                network_instance='default', protocol_instance='default'):
    """Disable ISIS on interface (both IPv4 and/or IPv6).
    
    This is a convenience wrapper that calls unconfigure_isis_interface_ipv4 and/or
    unconfigure_isis_interface_ipv6 based on the parameters.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        ipv4 (bool, optional): Disable IPv4. Defaults to True.
        ipv6 (bool, optional): Disable IPv6. Defaults to False.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable ISIS on interface
    
    Example:
        >>> # Disable both IPv4 and IPv6
        >>> unconfigure_isis_interface(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     ipv4=True,
        ...     ipv6=True,
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Disabling ISIS on interface {interface} on {device.name} "
        f"(IPv4: {ipv4}, IPv6: {ipv6}, "
        f"network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    if ipv4:
        unconfigure_isis_interface_ipv4(
            device, interface,
            network_instance=network_instance,
            protocol_instance=protocol_instance
        )
    
    if ipv6:
        unconfigure_isis_interface_ipv6(
            device, interface,
            network_instance=network_instance,
            protocol_instance=protocol_instance
        )


def configure_isis_interface_enabled(device, interface, enabled=True,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Enable or disable ISIS on interface (interface level, not AF level).
    
    This controls whether ISIS runs on the interface at all, independent of
    address-family configuration. This is different from AF-level enablement
    (configure_isis_interface_ipv4/ipv6), which controls specific address families.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        enabled (bool, optional): True to enable, False to disable. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure interface enabled state
    
    Example:
        >>> # Disable ISIS on interface (TC 101.5 use case)
        >>> configure_isis_interface_enabled(
        ...     device=device,
        ...     interface='swp5',
        ...     enabled=False,
        ...     protocol_instance='default'
        ... )
        
        >>> # Re-enable ISIS on interface
        >>> configure_isis_interface_enabled(
        ...     device=device,
        ...     interface='swp5',
        ...     enabled=True,
        ...     protocol_instance='default'
        ... )
    
    Note:
        Interface-level control affects ALL address families. If you only want
        to disable IPv4 or IPv6, use unconfigure_isis_interface_ipv4/ipv6 instead.
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS on interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'enabled {str(enabled).lower()}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not {'enable' if enabled else 'disable'} ISIS on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_enabled(device, interface, network_instance='default',
                                        protocol_instance='default'):
    """Reset ISIS enabled state on interface to default (enabled).
    
    This removes the explicit enabled/disabled configuration, reverting to the
    default behavior (enabled).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset enabled state
    
    Example:
        >>> unconfigure_isis_interface_enabled(
        ...     device=device,
        ...     interface='swp5',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting ISIS enabled state on interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no enabled',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset enabled state on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )

# ============================================================================
# 2.2 Interface Metrics
# ============================================================================


def configure_isis_interface_metric(device, interface, metric, level, network_instance='default',
                                     protocol_instance='default'):
    """Configure ISIS metric on interface (per-level, not per-address-family).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        metric (int): Metric value
        level (str): ISIS level ('level_1' or 'level_2')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure ISIS interface metric
        ValueError: If level is not 'level_1' or 'level_2'
    
    Example:
        >>> configure_isis_interface_metric(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     metric=10,
        ...     level='level_2',
        ...     protocol_instance='isis1'
        ... )
    
    Note:
        In ArcOS, metric is configured per-level, NOT per-address-family.
        CLI: interface <name> level <1|2> metric <value>
    """
    log.info(
        f"Configuring ISIS metric {metric} on interface {interface} level {level} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    # Get level number (1 or 2)
    level_num = _get_level_number(level)
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {level_num} metric {metric}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS metric {metric} on interface {interface} level {level} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_metric(device, interface, level, network_instance='default',
                                       protocol_instance='default'):
    """Remove ISIS metric from interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        level (str): ISIS level ('level_1' or 'level_2')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove ISIS interface metric
        ValueError: If level is not 'level_1' or 'level_2'
    
    Example:
        >>> unconfigure_isis_interface_metric(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     level='level_2',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Removing ISIS metric from interface {interface} level {level} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    # Get level number (1 or 2)
    level_num = _get_level_number(level)
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'no level {level_num} metric',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS metric from interface {interface} level {level} "
            f"on {device.name}. Error:\n{e}"
        )

# ============================================================================
# 2.3 Interface Network Type
# ============================================================================


def configure_isis_interface_network_type(device, interface, network_type, network_instance='default',
                                          protocol_instance='default'):
    """Configure ISIS network type on interface (point-to-point or broadcast).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_type (str): Network type ('POINT_TO_POINT' or 'BROADCAST')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure ISIS network type
        ValueError: If network_type is not valid
    
    Example:
        >>> configure_isis_interface_network_type(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     network_type='POINT_TO_POINT',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Configuring ISIS network type {network_type} on interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    # Validate network type
    valid_types = ['POINT_TO_POINT', 'BROADCAST']
    if network_type.upper() not in valid_types:
        raise ValueError(
            f"Invalid network type '{network_type}'. Must be one of: {', '.join(valid_types)}"
        )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'network-type {network_type.upper()}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS network type {network_type} on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_network_type(device, interface, network_instance='default',
                                            protocol_instance='default'):
    """Remove ISIS network type from interface (reset to default).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove ISIS network type
    
    Example:
        >>> unconfigure_isis_interface_network_type(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Removing ISIS network type from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no network-type',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS network type from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 4: Global Router Configuration
# ============================================================================

# ============================================================================
# 4.2 IS-Type / Level Capability
# ============================================================================


def configure_isis_level_type(device, is_type, network_instance='default',
                               protocol_instance='default'):
    """Configure IS-TYPE (level-1, level-2, level-1-2) and enable the appropriate levels.
    
    This function sets the level-capability and automatically enables the appropriate
    level(s) based on the is_type parameter:
    - level_1: enables level 1
    - level_2: enables level 2
    - level_1_2: enables both level 1 and level 2
    
    Args:
        device (obj): Device object
        is_type (str): IS-TYPE ('level_1', 'level_2', 'level_1_2')
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure ISIS level type
        ValueError: If is_type is not valid
    
    Example:
        >>> configure_isis_level_type(
        ...     device=device,
        ...     is_type='level_2',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Configuring ISIS level type {is_type} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    # Convert level format to ArcOS format
    level_capability = _convert_level_format(is_type)
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [isis_context]
    
    # Set level-capability
    config.append(f'global level-capability {level_capability}')
    
    # Enable appropriate level(s) based on is_type
    if is_type in ['level_1', 'level_1_2']:
        config.extend([
            'level 1',
            'enabled true',
            'exit'
        ])
    
    if is_type in ['level_2', 'level_1_2']:
        config.extend([
            'level 2',
            'enabled true',
            'exit'
        ])
    
    config.append('!')
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS level type {is_type} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_level_type(device, network_instance='default', protocol_instance='default'):
    """Reset to default level type (level-2) and disable levels.
    
    This function removes the level-capability configuration and disables both levels.
    After unconfiguration, you need to explicitly enable the required levels.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset ISIS level type
    
    Example:
        >>> unconfigure_isis_level_type(
        ...     device=device,
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Resetting ISIS level type to default on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global level-capability',
        'level 1',
        'enabled false',
        'exit',
        'level 2',
        'enabled false',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS level type on {device.name}. "
            f"Error:\n{e}"
        )


# ============================================================================
# 4.5 Passive Interface
# ============================================================================


def configure_isis_passive_interface(device, interface, network_instance='default',
                                      protocol_instance='default'):
    """Configure interface as passive (suppress routing updates).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure passive interface
    
    Example:
        >>> configure_isis_passive_interface(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Configuring interface {interface} as passive on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'passive true',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure interface {interface} as passive on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_passive_interface(device, interface, network_instance='default',
                                        protocol_instance='default'):
    """Remove passive configuration from interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove passive configuration
    
    Example:
        >>> unconfigure_isis_passive_interface(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Removing passive configuration from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no passive',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove passive configuration from interface {interface} on {device.name}. "
            f"Error:\n{e}"
        )


# ============================================================================
# PHASE 2 - TIER 1: Essential Production APIs
# ============================================================================

# ============================================================================
# Category 1: Interface Authentication
# ============================================================================


def configure_isis_interface_hello_authentication(device, interface, enabled=True,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Enable or disable ISIS hello authentication on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        enabled (bool, optional): Enable or disable hello authentication. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure hello authentication
    
    Example:
        >>> configure_isis_interface_hello_authentication(
        ...     device=device,
        ...     interface='swp1',
        ...     enabled=True,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS hello authentication on "
        f"interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    enabled_str = 'true' if enabled else 'false'
    config = [
        intf_context,
        f'authentication hello-authentication {enabled_str}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure hello authentication on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_hello_authentication(device, interface, network_instance='default',
                                                      protocol_instance='default'):
    """Remove hello authentication configuration (reset to default).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove hello authentication configuration
    
    Example:
        >>> unconfigure_isis_interface_hello_authentication(
        ...     device=device,
        ...     interface='swp1',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Removing hello authentication configuration from interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no authentication hello-authentication',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove hello authentication from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_auth_keychain(device, interface, keychain_name,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure keychain-based authentication on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        keychain_name (str): Keychain name (must be pre-configured)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure keychain authentication
    
    Example:
        >>> configure_isis_interface_auth_keychain(
        ...     device=device,
        ...     interface='swp1',
        ...     keychain_name='isis_keychain1',
        ...     protocol_instance='default'
        ... )
    
    Note:
        Keychain must be pre-configured globally before using this function.
    """
    log.info(
        f"Configuring keychain authentication '{keychain_name}' on interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'authentication auth-type KEYCHAIN',
        f'authentication keychain {keychain_name}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure keychain authentication on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_auth_keychain(device, interface, network_instance='default',
                                               protocol_instance='default'):
    """Remove keychain authentication configuration.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove keychain authentication
    
    Example:
        >>> unconfigure_isis_interface_auth_keychain(
        ...     device=device,
        ...     interface='swp1',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Removing keychain authentication from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no authentication auth-type',
        'no authentication keychain',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove keychain authentication from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_auth_simple_key(device, interface, password,
                                               crypto_algorithm='MD5',
                                               network_instance='default',
                                               protocol_instance='default'):
    """Configure simple key authentication with MD5 on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        password (str): Authentication password (AES encrypted string)
        crypto_algorithm (str, optional): Cryptographic algorithm. Defaults to 'MD5'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure simple key authentication
        ValueError: If crypto_algorithm is not MD5
    
    Example:
        >>> configure_isis_interface_auth_simple_key(
        ...     device=device,
        ...     interface='swp1',
        ...     password='mypassword123',
        ...     protocol_instance='default'
        ... )
    
    Note:
        Only MD5 is supported for crypto_algorithm (no cleartext).
    """
    if crypto_algorithm != 'MD5':
        raise ValueError(
            f"Invalid crypto_algorithm '{crypto_algorithm}'. Only 'MD5' is supported."
        )
    
    log.info(
        f"Configuring simple key authentication with {crypto_algorithm} on interface "
        f"{interface} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'authentication auth-type SIMPLE_KEY',
        f'authentication key crypto-algorithm {crypto_algorithm}',
        f'authentication key auth-password {password}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure simple key authentication on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_auth_simple_key(device, interface, network_instance='default',
                                                 protocol_instance='default'):
    """Remove simple key authentication configuration.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove simple key authentication
    
    Example:
        >>> unconfigure_isis_interface_auth_simple_key(
        ...     device=device,
        ...     interface='swp1',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Removing simple key authentication from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no authentication auth-type',
        'no authentication key',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove simple key authentication from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_auth_password(device, interface, password,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure or update authentication password (for existing simple key auth).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        password (str): Authentication password (AES encrypted string)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure authentication password
    
    Example:
        >>> configure_isis_interface_auth_password(
        ...     device=device,
        ...     interface='swp1',
        ...     password='newpassword456',
        ...     protocol_instance='default'
        ... )
    
    Note:
        This function assumes simple key authentication is already configured.
        Use configure_isis_interface_auth_simple_key for initial setup.
    """
    log.info(
        f"Configuring authentication password on interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'authentication key auth-password {password}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure authentication password on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_auth_password(device, interface, network_instance='default',
                                               protocol_instance='default'):
    """Remove authentication password configuration.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove authentication password
    
    Example:
        >>> unconfigure_isis_interface_auth_password(
        ...     device=device,
        ...     interface='swp1',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Removing authentication password from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no authentication key auth-password',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove authentication password from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 1b: Level-Context PDU Authentication (LSP, CSNP, PSNP)
# ============================================================================


def _level_number(level):
    """Extract numeric level (1 or 2) from level string.

    Args:
        level (str): Level in format 'level_1' or 'level_2'

    Returns:
        str: '1' or '2'

    Raises:
        ValueError: If level is not 'level_1' or 'level_2'
    """
    mapping = {'level_1': '1', 'level_2': '2'}
    if level not in mapping:
        raise ValueError(
            f"Invalid level '{level}'. Must be 'level_1' or 'level_2'"
        )
    return mapping[level]


def configure_isis_lsp_authentication(device, level, enabled=True,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Enable or disable ISIS LSP authentication at the level context.

    Args:
        device (obj): Device object
        level (str): ISIS level — 'level_1' or 'level_2'
        enabled (bool, optional): Enable or disable LSP authentication. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LSP authentication

    Example:
        >>> configure_isis_lsp_authentication(device, level='level_2', enabled=True)
    """
    lvl = _level_number(level)
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS LSP authentication "
        f"level {lvl} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    enabled_str = 'true' if enabled else 'false'
    config = [
        isis_context,
        f'level {lvl}',
        f'authentication lsp-authentication {enabled_str}',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LSP authentication level {lvl} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_lsp_authentication(device, level,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Remove ISIS LSP authentication at the level context.

    Args:
        device (obj): Device object
        level (str): ISIS level — 'level_1' or 'level_2'
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LSP authentication

    Example:
        >>> unconfigure_isis_lsp_authentication(device, level='level_2')
    """
    lvl = _level_number(level)
    log.info(
        f"Removing ISIS LSP authentication level {lvl} from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'no authentication lsp-authentication',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LSP authentication level {lvl} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_isis_csnp_authentication(device, level, enabled=True,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Enable or disable ISIS CSNP authentication at the level context.

    Args:
        device (obj): Device object
        level (str): ISIS level — 'level_1' or 'level_2'
        enabled (bool, optional): Enable or disable CSNP authentication. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure CSNP authentication

    Example:
        >>> configure_isis_csnp_authentication(device, level='level_2', enabled=True)
    """
    lvl = _level_number(level)
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS CSNP authentication "
        f"level {lvl} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    enabled_str = 'true' if enabled else 'false'
    config = [
        isis_context,
        f'level {lvl}',
        f'authentication csnp-authentication {enabled_str}',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure CSNP authentication level {lvl} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_csnp_authentication(device, level,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove ISIS CSNP authentication at the level context.

    Args:
        device (obj): Device object
        level (str): ISIS level — 'level_1' or 'level_2'
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove CSNP authentication

    Example:
        >>> unconfigure_isis_csnp_authentication(device, level='level_2')
    """
    lvl = _level_number(level)
    log.info(
        f"Removing ISIS CSNP authentication level {lvl} from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'no authentication csnp-authentication',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove CSNP authentication level {lvl} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_isis_psnp_authentication(device, level, enabled=True,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Enable or disable ISIS PSNP authentication at the level context.

    Args:
        device (obj): Device object
        level (str): ISIS level — 'level_1' or 'level_2'
        enabled (bool, optional): Enable or disable PSNP authentication. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure PSNP authentication

    Example:
        >>> configure_isis_psnp_authentication(device, level='level_2', enabled=True)
    """
    lvl = _level_number(level)
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS PSNP authentication "
        f"level {lvl} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    enabled_str = 'true' if enabled else 'false'
    config = [
        isis_context,
        f'level {lvl}',
        f'authentication psnp-authentication {enabled_str}',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure PSNP authentication level {lvl} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_psnp_authentication(device, level,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove ISIS PSNP authentication at the level context.

    Args:
        device (obj): Device object
        level (str): ISIS level — 'level_1' or 'level_2'
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove PSNP authentication

    Example:
        >>> unconfigure_isis_psnp_authentication(device, level='level_2')
    """
    lvl = _level_number(level)
    log.info(
        f"Removing ISIS PSNP authentication level {lvl} from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'no authentication psnp-authentication',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove PSNP authentication level {lvl} from {device.name}. "
            f"Error:\n{e}"
        )


# ============================================================================
# Category 2: Maximum ECMP Paths
# ============================================================================


def configure_isis_max_ecmp_paths(device, max_paths, network_instance='default',
                                   protocol_instance='default'):
    """Configure maximum ECMP paths for ISIS.
    
    Args:
        device (obj): Device object
        max_paths (int): Maximum ECMP paths (0-64)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure maximum ECMP paths
        ValueError: If max_paths is not in range 0-64
    
    Example:
        >>> configure_isis_max_ecmp_paths(
        ...     device=device,
        ...     max_paths=8,
        ...     protocol_instance='default'
        ... )
    """
    if not 0 <= max_paths <= 64:
        raise ValueError(
            f"Invalid max_paths '{max_paths}'. Must be between 0 and 64."
        )
    
    log.info(
        f"Configuring ISIS maximum ECMP paths to {max_paths} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global max-ecmp-paths {max_paths}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure maximum ECMP paths on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_max_ecmp_paths(device, network_instance='default',
                                     protocol_instance='default'):
    """Reset maximum ECMP paths to default.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset maximum ECMP paths
    
    Example:
        >>> unconfigure_isis_max_ecmp_paths(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting ISIS maximum ECMP paths to default on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global max-ecmp-paths',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset maximum ECMP paths on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 3: Timers
# ============================================================================

# ============================================================================
# 3.1 Global SPF Timers
# ============================================================================


def configure_isis_spf_intervals(device, first_interval=None, hold_interval=None,
                                  second_interval=None, mla_interval=None,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Configure SPF timer intervals (first, hold, second, mla).

    Configures one or more SPF timer intervals atomically. The four timers control
    SPF calculation behavior and convergence speed. `mla_interval` is the
    Microloop-Avoidance SPF first-interval used when MLA is active.

    Args:
        device (obj): Device object
        first_interval (int, optional): SPF first interval in milliseconds (initial delay; default 50)
        hold_interval (int, optional): SPF hold interval in milliseconds (default 5000)
        second_interval (int, optional): SPF second interval in milliseconds (default 200)
        mla_interval (int, optional): SPF first interval when MLA active, in
            milliseconds (default 25). adoc §IS-IS.adoc:689-697.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure SPF intervals
        ValueError: If no intervals are provided

    Example:
        >>> # Configure all four intervals
        >>> configure_isis_spf_intervals(
        ...     device=device,
        ...     first_interval=50,
        ...     hold_interval=200,
        ...     second_interval=5000,
        ...     mla_interval=100,
        ...     protocol_instance='default'
        ... )
        >>> # Configure only specific intervals
        >>> configure_isis_spf_intervals(
        ...     device=device,
        ...     first_interval=100,
        ...     hold_interval=500
        ... )
    """
    if (first_interval is None and hold_interval is None and
            second_interval is None and mla_interval is None):
        raise ValueError(
            "At least one SPF interval must be specified (first_interval, "
            "hold_interval, second_interval, or mla_interval)"
        )

    intervals = []
    if first_interval is not None:
        intervals.append(f"first={first_interval}ms")
    if hold_interval is not None:
        intervals.append(f"hold={hold_interval}ms")
    if second_interval is not None:
        intervals.append(f"second={second_interval}ms")
    if mla_interval is not None:
        intervals.append(f"mla={mla_interval}ms")

    log.info(
        f"Configuring ISIS SPF intervals ({', '.join(intervals)}) on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [isis_context]

    if first_interval is not None:
        config.append(f'global timers spf spf-first-interval {first_interval}')
    if hold_interval is not None:
        config.append(f'global timers spf spf-hold-interval {hold_interval}')
    if second_interval is not None:
        config.append(f'global timers spf spf-second-interval {second_interval}')
    if mla_interval is not None:
        config.append(f'global timers spf spf-mla-interval {mla_interval}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SPF intervals on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_spf_intervals(device, network_instance='default',
                                    protocol_instance='default'):
    """Reset all SPF timer intervals to default.
    
    Resets all three SPF intervals (first, hold, second) to their default values.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset SPF intervals
    
    Example:
        >>> unconfigure_isis_spf_intervals(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting all ISIS SPF intervals to default on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global timers spf spf-first-interval',
        'no global timers spf spf-hold-interval',
        'no global timers spf spf-second-interval',
        'no global timers spf spf-mla-interval',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset SPF intervals on {device.name}. Error:\n{e}"
        )


# ============================================================================
# 3.2 Global LSP Timers
# ============================================================================


def configure_isis_lsp_lifetime_interval(device, interval, network_instance='default',
                                          protocol_instance='default'):
    """Configure LSP lifetime interval.
    
    Args:
        device (obj): Device object
        interval (int): LSP lifetime interval in seconds (default 1200)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure LSP lifetime interval
    
    Example:
        >>> configure_isis_lsp_lifetime_interval(
        ...     device=device,
        ...     interval=1800,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Configuring ISIS LSP lifetime interval to {interval}s on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global timers lsp-lifetime-interval {interval}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LSP lifetime interval on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_lsp_lifetime_interval(device, network_instance='default',
                                            protocol_instance='default'):
    """Reset LSP lifetime interval to default.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset LSP lifetime interval
    
    Example:
        >>> unconfigure_isis_lsp_lifetime_interval(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting ISIS LSP lifetime interval to default on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global timers lsp-lifetime-interval',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset LSP lifetime interval on {device.name}. Error:\n{e}"
        )


def configure_isis_lsp_refresh_interval(device, interval, network_instance='default',
                                         protocol_instance='default'):
    """Configure LSP refresh interval.
    
    Args:
        device (obj): Device object
        interval (int): LSP refresh interval in seconds (default 600)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure LSP refresh interval
    
    Example:
        >>> configure_isis_lsp_refresh_interval(
        ...     device=device,
        ...     interval=900,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Configuring ISIS LSP refresh interval to {interval}s on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global timers lsp-refresh-interval {interval}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LSP refresh interval on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_lsp_refresh_interval(device, network_instance='default',
                                           protocol_instance='default'):
    """Reset LSP refresh interval to default.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset LSP refresh interval
    
    Example:
        >>> unconfigure_isis_lsp_refresh_interval(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting ISIS LSP refresh interval to default on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global timers lsp-refresh-interval',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset LSP refresh interval on {device.name}. Error:\n{e}"
        )


# ============================================================================
# 3.3 Interface Hello Timers
# ============================================================================


def configure_isis_interface_hello_interval(device, interface, interval,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure hello interval for point-to-point networks.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        interval (int): Hello interval in seconds
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure hello interval
    
    Example:
        >>> configure_isis_interface_hello_interval(
        ...     device=device,
        ...     interface='swp1',
        ...     interval=10,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Configuring ISIS hello interval to {interval}s on interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'timers hello-interval {interval}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure hello interval on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_hello_interval(device, interface, network_instance='default',
                                               protocol_instance='default'):
    """Reset hello interval to default.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset hello interval
    
    Example:
        >>> unconfigure_isis_interface_hello_interval(
        ...     device=device,
        ...     interface='swp1',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting ISIS hello interval to default on interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no timers hello-interval',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset hello interval on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_hello_multiplier(device, interface, multiplier,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Configure hello multiplier for point-to-point networks.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        multiplier (int): Hello multiplier
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure hello multiplier
    
    Example:
        >>> configure_isis_interface_hello_multiplier(
        ...     device=device,
        ...     interface='swp1',
        ...     multiplier=3,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Configuring ISIS hello multiplier to {multiplier} on interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'timers hello-multiplier {multiplier}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure hello multiplier on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_hello_multiplier(device, interface, network_instance='default',
                                                 protocol_instance='default'):
    """Reset hello multiplier to default.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to reset hello multiplier
    
    Example:
        >>> unconfigure_isis_interface_hello_multiplier(
        ...     device=device,
        ...     interface='swp1',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting ISIS hello multiplier to default on interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no timers hello-multiplier',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset hello multiplier on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# ===========================================================================
# PHASE 2 TIER 2 APIS
# ===========================================================================

# ============================================================================
# Category 4: Graceful Restart
# ============================================================================


def configure_isis_graceful_restart(device, enabled=True, network_instance='default',
                                     protocol_instance='default'):
    """Enable or disable ISIS graceful restart.
    
    Args:
        device (obj): Device object
        enabled (bool, optional): Enable or disable graceful restart. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure graceful restart
    
    Example:
        >>> configure_isis_graceful_restart(
        ...     device=device,
        ...     enabled=True,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS graceful restart on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global graceful-restart enabled {str(enabled).lower()}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure graceful restart on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_graceful_restart(device, network_instance='default',
                                       protocol_instance='default'):
    """Disable graceful restart (reset to default).
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable graceful restart
    
    Example:
        >>> unconfigure_isis_graceful_restart(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Disabling ISIS graceful restart on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global graceful-restart enabled',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable graceful restart on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 5: BFD (Interface-level only)
# ============================================================================


def configure_isis_interface_bfd(device, interface, profile=None,
                                  enabled=True,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Configure BFD on an ISIS interface (BFD TLV + optional BFD profile).

    Enables BFD negotiation in ISIS hello packets via ``bfd bfd-tlv``.
    When ``profile`` is provided, also associates the BFD profile via
    ``bfd profile``.  The BFD profile must already exist on the device
    (created via ``configure_bfd_profile``).

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g., 'swp1')
        profile (str, optional): BFD profile name. If None, only bfd-tlv
            is configured. The profile must exist on the device.
        enabled (bool, optional): Enable or disable BFD TLV. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD

    Example:
        >>> configure_isis_interface_bfd(
        ...     device=device,
        ...     interface='swp1',
        ...     profile='isis-bfd',
        ...     enabled=True,
        ... )
    """
    log.info(
        f"Configuring BFD on interface {interface} "
        f"(enabled={enabled}, profile={profile}) "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'bfd bfd-tlv {str(enabled).lower()}',
    ]
    if profile:
        config.append(f'bfd profile {profile}')
    config.append('!')
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD TLV on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_bfd(device, interface, network_instance='default',
                                     protocol_instance='default'):
    """Disable BFD TLV on interface (reset to default).
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable BFD TLV
    
    Example:
        >>> unconfigure_isis_interface_bfd(
        ...     device=device,
        ...     interface='swp1',
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Disabling BFD TLV on interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no bfd bfd-tlv',
        'no bfd profile',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable BFD TLV on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# ===========================================================================
# PHASE 2 TIER 3 APIS - SEGMENT ROUTING (SR-MPLS)
# ===========================================================================

# ============================================================================
# Category 6.1: Prefix-SID Configuration
# ============================================================================


def configure_isis_interface_ipv4_prefix_sid(device, interface, sid_type, value,
                                              algorithm='SPF', label_option=None,
                                              clear_n_flag=False,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Configure IPv4 Prefix-SID on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        sid_type (str): SID type (ABSOLUTE, INDEX)
        value (int): SID value
        algorithm (str, optional): Algorithm. Defaults to 'SPF'.
        label_option (str, optional): Label option (NO_PHP, EXPLICIT_NULL)
        clear_n_flag (bool, optional): Clear N-flag. Defaults to False.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure IPv4 Prefix-SID
    
    Example:
        >>> configure_isis_interface_ipv4_prefix_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     sid_type='INDEX',
        ...     value=100,
        ...     algorithm='SPF',
        ...     label_option='NO_PHP'
        ... )
    """
    log.info(
        f"Configuring IPv4 Prefix-SID on interface {interface} on {device.name} "
        f"(algorithm: {algorithm}, sid-type: {sid_type}, value: {value})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        f'prefix-sid {algorithm}',
        f'sid-type {sid_type}',
        f'value {value}'
    ]
    
    if label_option:
        config.append(f'label-option {label_option}')
    
    if clear_n_flag:
        config.append('clear-n-flag true')
    
    config.extend(['exit', 'exit', '!'])
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv4 Prefix-SID on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv4_prefix_sid(device, interface, algorithm='SPF',
                                                 network_instance='default',
                                                 protocol_instance='default'):
    """Remove IPv4 Prefix-SID configuration from interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        algorithm (str, optional): Algorithm. Defaults to 'SPF'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove IPv4 Prefix-SID
    
    Example:
        >>> unconfigure_isis_interface_ipv4_prefix_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     algorithm='SPF'
        ... )
    """
    log.info(
        f"Removing IPv4 Prefix-SID (algorithm: {algorithm}) from interface {interface} "
        f"on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        f'no prefix-sid {algorithm}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv4 Prefix-SID from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_ipv6_prefix_sid(device, interface, sid_type, value,
                                              algorithm='SPF', label_option=None,
                                              clear_n_flag=False,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Configure IPv6 Prefix-SID on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        sid_type (str): SID type (ABSOLUTE, INDEX)
        value (int): SID value
        algorithm (str, optional): Algorithm. Defaults to 'SPF'.
        label_option (str, optional): Label option (NO_PHP, EXPLICIT_NULL)
        clear_n_flag (bool, optional): Clear N-flag. Defaults to False.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure IPv6 Prefix-SID
    
    Example:
        >>> configure_isis_interface_ipv6_prefix_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     sid_type='INDEX',
        ...     value=200,
        ...     algorithm='SPF'
        ... )
    """
    log.info(
        f"Configuring IPv6 Prefix-SID on interface {interface} on {device.name} "
        f"(algorithm: {algorithm}, sid-type: {sid_type}, value: {value})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        f'prefix-sid {algorithm}',
        f'sid-type {sid_type}',
        f'value {value}'
    ]
    
    if label_option:
        config.append(f'label-option {label_option}')
    
    if clear_n_flag:
        config.append('clear-n-flag true')
    
    config.extend(['exit', 'exit', '!'])
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv6 Prefix-SID on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv6_prefix_sid(device, interface, algorithm='SPF',
                                                 network_instance='default',
                                                 protocol_instance='default'):
    """Remove IPv6 Prefix-SID configuration from interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        algorithm (str, optional): Algorithm. Defaults to 'SPF'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove IPv6 Prefix-SID
    
    Example:
        >>> unconfigure_isis_interface_ipv6_prefix_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     algorithm='SPF'
        ... )
    """
    log.info(
        f"Removing IPv6 Prefix-SID (algorithm: {algorithm}) from interface {interface} "
        f"on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        f'no prefix-sid {algorithm}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv6 Prefix-SID from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 6.2: Adjacency-SID Configuration
# ============================================================================


def configure_isis_interface_ipv4_adjacency_sid(device, interface, sid_type, value,
                                                 adjacency_type='POINT_TO_POINT',
                                                 network_instance='default',
                                                 protocol_instance='default'):
    """Configure IPv4 Adjacency-SID on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        sid_type (str): SID type (ABSOLUTE, INDEX)
        value (int): SID value
        adjacency_type (str, optional): Adjacency type. Defaults to 'POINT_TO_POINT'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure IPv4 Adjacency-SID
    
    Example:
        >>> configure_isis_interface_ipv4_adjacency_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     sid_type='ABSOLUTE',
        ...     value=16001,
        ...     adjacency_type='POINT_TO_POINT'
        ... )
    """
    log.info(
        f"Configuring IPv4 Adjacency-SID on interface {interface} on {device.name} "
        f"(adjacency-type: {adjacency_type}, sid-type: {sid_type}, value: {value})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        f'adjacency-sid {adjacency_type}',
        f'sid-type {sid_type}',
        f'value {value}',
        'exit',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv4 Adjacency-SID on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv4_adjacency_sid(device, interface,
                                                    adjacency_type='POINT_TO_POINT',
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Remove IPv4 Adjacency-SID configuration from interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        adjacency_type (str, optional): Adjacency type. Defaults to 'POINT_TO_POINT'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove IPv4 Adjacency-SID
    
    Example:
        >>> unconfigure_isis_interface_ipv4_adjacency_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     adjacency_type='POINT_TO_POINT'
        ... )
    """
    log.info(
        f"Removing IPv4 Adjacency-SID (adjacency-type: {adjacency_type}) from "
        f"interface {interface} on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        f'no adjacency-sid {adjacency_type}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv4 Adjacency-SID from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_ipv6_adjacency_sid(device, interface, sid_type, value,
                                                 adjacency_type='POINT_TO_POINT',
                                                 network_instance='default',
                                                 protocol_instance='default'):
    """Configure IPv6 Adjacency-SID on interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        sid_type (str): SID type (ABSOLUTE, INDEX)
        value (int): SID value
        adjacency_type (str, optional): Adjacency type. Defaults to 'POINT_TO_POINT'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure IPv6 Adjacency-SID
    
    Example:
        >>> configure_isis_interface_ipv6_adjacency_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     sid_type='ABSOLUTE',
        ...     value=16002,
        ...     adjacency_type='POINT_TO_POINT'
        ... )
    """
    log.info(
        f"Configuring IPv6 Adjacency-SID on interface {interface} on {device.name} "
        f"(adjacency-type: {adjacency_type}, sid-type: {sid_type}, value: {value})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        f'adjacency-sid {adjacency_type}',
        f'sid-type {sid_type}',
        f'value {value}',
        'exit',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv6 Adjacency-SID on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv6_adjacency_sid(device, interface,
                                                    adjacency_type='POINT_TO_POINT',
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Remove IPv6 Adjacency-SID configuration from interface.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        adjacency_type (str, optional): Adjacency type. Defaults to 'POINT_TO_POINT'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to remove IPv6 Adjacency-SID
    
    Example:
        >>> unconfigure_isis_interface_ipv6_adjacency_sid(
        ...     device=device,
        ...     interface='swp1',
        ...     adjacency_type='POINT_TO_POINT'
        ... )
    """
    log.info(
        f"Removing IPv6 Adjacency-SID (adjacency-type: {adjacency_type}) from "
        f"interface {interface} on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        f'no adjacency-sid {adjacency_type}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv6 Adjacency-SID from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 6.3: TI-LFA SR-MPLS Configuration
# ============================================================================


def configure_isis_interface_ipv4_ti_lfa_sr_mpls(device, interface, enabled=True,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Enable TI-LFA SR-MPLS fast-reroute for IPv4.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        enabled (bool, optional): Enable or disable TI-LFA SR-MPLS. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure TI-LFA SR-MPLS
    
    Example:
        >>> configure_isis_interface_ipv4_ti_lfa_sr_mpls(
        ...     device=device,
        ...     interface='swp1',
        ...     enabled=True
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} TI-LFA SR-MPLS for IPv4 on "
        f"interface {interface} on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        f'fast-reroute ti-lfa sr-mpls enabled {str(enabled).lower()}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure TI-LFA SR-MPLS for IPv4 on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv4_ti_lfa_sr_mpls(device, interface,
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Disable TI-LFA SR-MPLS fast-reroute for IPv4.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable TI-LFA SR-MPLS
    
    Example:
        >>> unconfigure_isis_interface_ipv4_ti_lfa_sr_mpls(
        ...     device=device,
        ...     interface='swp1'
        ... )
    """
    log.info(
        f"Disabling TI-LFA SR-MPLS for IPv4 on interface {interface} on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        'no fast-reroute ti-lfa sr-mpls',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable TI-LFA SR-MPLS for IPv4 on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_ipv6_ti_lfa_sr_mpls(device, interface, enabled=True,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Enable TI-LFA SR-MPLS fast-reroute for IPv6.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        enabled (bool, optional): Enable or disable TI-LFA SR-MPLS. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure TI-LFA SR-MPLS
    
    Example:
        >>> configure_isis_interface_ipv6_ti_lfa_sr_mpls(
        ...     device=device,
        ...     interface='swp1',
        ...     enabled=True
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} TI-LFA SR-MPLS for IPv6 on "
        f"interface {interface} on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        f'fast-reroute ti-lfa sr-mpls enabled {str(enabled).lower()}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure TI-LFA SR-MPLS for IPv6 on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv6_ti_lfa_sr_mpls(device, interface,
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Disable TI-LFA SR-MPLS fast-reroute for IPv6.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable TI-LFA SR-MPLS
    
    Example:
        >>> unconfigure_isis_interface_ipv6_ti_lfa_sr_mpls(
        ...     device=device,
        ...     interface='swp1'
        ... )
    """
    log.info(
        f"Disabling TI-LFA SR-MPLS for IPv6 on interface {interface} on {device.name}"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        'no fast-reroute ti-lfa sr-mpls',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable TI-LFA SR-MPLS for IPv6 on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_ipv6_ti_lfa_srv6(device, interface, enabled=True,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Enable TI-LFA SRv6 fast-reroute for IPv6.

    Sibling of :func:`configure_isis_interface_ipv6_ti_lfa_sr_mpls`. Where the
    SR-MPLS variant encodes backup paths as MPLS label stacks, this variant
    uses SRv6 SID lists (compressed uSID when the locator has micro-segment
    enabled). The two flavors can coexist on the same interface.

    Prereqs: ISIS SRv6 globally enabled, an SRv6 locator attached to the
    ISIS instance, and an encap source-address configured under
    ``network-instance <ni> srv6``.

    Args:
        device (obj): Device object
        interface (str): Interface name
        enabled (bool, optional): Enable or disable TI-LFA SRv6. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure TI-LFA SRv6

    Example:
        >>> configure_isis_interface_ipv6_ti_lfa_srv6(
        ...     device=device,
        ...     interface='swp1',
        ...     enabled=True
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} TI-LFA SRv6 for IPv6 on "
        f"interface {interface} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        f'fast-reroute ti-lfa srv6 enabled {str(enabled).lower()}',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure TI-LFA SRv6 for IPv6 on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv6_ti_lfa_srv6(device, interface,
                                                 network_instance='default',
                                                 protocol_instance='default'):
    """Disable TI-LFA SRv6 fast-reroute for IPv6.

    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to disable TI-LFA SRv6

    Example:
        >>> unconfigure_isis_interface_ipv6_ti_lfa_srv6(
        ...     device=device,
        ...     interface='swp1'
        ... )
    """
    log.info(
        f"Disabling TI-LFA SRv6 for IPv6 on interface {interface} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        'no fast-reroute ti-lfa srv6',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable TI-LFA SRv6 for IPv6 on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 6.4: Segment Routing Global Enable
# ============================================================================


def configure_isis_segment_routing(device, enabled=True, network_instance='default',
                                    protocol_instance='default'):
    """Enable or disable Segment Routing globally for ISIS.
    
    This enables SR capability advertisement in ISIS.
    
    Args:
        device (obj): Device object
        enabled (bool, optional): Enable or disable Segment Routing. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure Segment Routing
    
    Example:
        >>> configure_isis_segment_routing(
        ...     device=device,
        ...     enabled=True,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} Segment Routing on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global segment-routing enabled {str(enabled).lower()}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure Segment Routing on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_segment_routing(device, network_instance='default',
                                      protocol_instance='default'):
    """Disable Segment Routing (reset to default).
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to disable Segment Routing
    
    Example:
        >>> unconfigure_isis_segment_routing(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Disabling Segment Routing on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global segment-routing enabled',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable Segment Routing on {device.name}. Error:\n{e}"
        )


# ============================================================================
# PHASE 3: Advanced ISIS Features
# ============================================================================

# ============================================================================
# Category 1: Route Redistribution (Table Connection)
# ============================================================================

def configure_table_connection(device, source_protocol, destination_protocol,
                                address_family, source_instance='default',
                                destination_instance='default', import_policy=None,
                                network_instance='default'):
    """Configure route redistribution (table connection) from source to destination protocol.
    
    This API configures table-connection at the network-instance level to redistribute
    routes between routing protocols.
    
    Args:
        device (obj): Device object
        source_protocol (str): Source protocol - one of: STATIC, DIRECTLY_CONNECTED, BGP, 
                              ISIS, OSPF, OSPF3, ADJACENCY, SIDMGR
        destination_protocol (str): Destination protocol - one of: BGP, ISIS, OSPF, OSPF3
        address_family (str): Address family - IPV4 or IPV6
        source_instance (str, optional): Source protocol instance name. Defaults to 'default'.
        destination_instance (str, optional): Destination protocol instance name. 
                                             Defaults to 'default'.
        import_policy (list, optional): List of import policy names to apply.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure table connection
        ValueError: Invalid source_protocol, destination_protocol, or address_family
    
    Example:
        >>> # Redistribute static routes into ISIS with policy
        >>> configure_table_connection(
        ...     device=device,
        ...     source_protocol='STATIC',
        ...     destination_protocol='ISIS',
        ...     address_family='IPV4',
        ...     import_policy=['static2isis', 'set_metric']
        ... )
        
        >>> # Redistribute connected routes into ISIS
        >>> configure_table_connection(
        ...     device=device,
        ...     source_protocol='DIRECTLY_CONNECTED',
        ...     destination_protocol='ISIS',
        ...     address_family='IPV4',
        ...     import_policy=['connected2isis']
        ... )
    """
    log.info(
        f"Configuring table connection from {source_protocol} to {destination_protocol} "
        f"({address_family}) on {device.name} (network-instance: {network_instance})"
    )
    
    # Validate protocols
    valid_sources = ['STATIC', 'DIRECTLY_CONNECTED', 'BGP', 'ISIS', 'OSPF', 'OSPF3', 
                     'ADJACENCY', 'SIDMGR']
    valid_destinations = ['BGP', 'ISIS', 'OSPF', 'OSPF3']
    valid_afs = ['IPV4', 'IPV6']
    
    if source_protocol not in valid_sources:
        raise ValueError(
            f"Invalid source_protocol '{source_protocol}'. "
            f"Must be one of: {', '.join(valid_sources)}"
        )
    
    if destination_protocol not in valid_destinations:
        raise ValueError(
            f"Invalid destination_protocol '{destination_protocol}'. "
            f"Must be one of: {', '.join(valid_destinations)}"
        )
    
    if address_family not in valid_afs:
        raise ValueError(
            f"Invalid address_family '{address_family}'. Must be one of: {', '.join(valid_afs)}"
        )
    
    config = [
        f'network-instance {network_instance}',
        f'table-connection {source_protocol} {destination_protocol} {address_family}',
        f'src-dst-instance {source_instance} {destination_instance}'
    ]
    
    if import_policy:
        # Format as [ policy1 policy2 ... ]
        policy_str = ' '.join(import_policy)
        config.append(f'import-policy [ {policy_str} ]')
    
    config.extend(['exit', 'exit'])

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure table connection from {source_protocol} to "
            f"{destination_protocol} on {device.name}. Error:\n{e}"
        )


def unconfigure_table_connection(device, source_protocol, destination_protocol,
                                  address_family, source_instance='default',
                                  destination_instance='default',
                                  network_instance='default'):
    """Remove route redistribution (table connection) between protocols.
    
    Args:
        device (obj): Device object
        source_protocol (str): Source protocol
        destination_protocol (str): Destination protocol
        address_family (str): Address family - IPV4 or IPV6
        source_instance (str, optional): Source protocol instance name. Defaults to 'default'.
        destination_instance (str, optional): Destination protocol instance name. 
                                             Defaults to 'default'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to unconfigure table connection
    
    Example:
        >>> unconfigure_table_connection(
        ...     device=device,
        ...     source_protocol='STATIC',
        ...     destination_protocol='ISIS',
        ...     address_family='IPV4'
        ... )
    """
    log.info(
        f"Removing table connection from {source_protocol} to {destination_protocol} "
        f"({address_family}) on {device.name}"
    )
    
    config = [
        f'network-instance {network_instance}',
        f'no table-connection {source_protocol} {destination_protocol} {address_family} '
        f'src-dst-instance {source_instance} {destination_instance}',
        'exit',
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove table connection from {source_protocol} to "
            f"{destination_protocol} on {device.name}. Error:\n{e}"
        )


def configure_table_connection_policy(device, source_protocol, destination_protocol,
                                       address_family, import_policy,
                                       source_instance='default',
                                       destination_instance='default',
                                       network_instance='default'):
    """Update or add import policies to an existing table connection.
    
    Args:
        device (obj): Device object
        source_protocol (str): Source protocol
        destination_protocol (str): Destination protocol
        address_family (str): Address family - IPV4 or IPV6
        import_policy (list): List of import policy names to apply
        source_instance (str, optional): Source protocol instance name. Defaults to 'default'.
        destination_instance (str, optional): Destination protocol instance name. 
                                             Defaults to 'default'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure table connection policy
    
    Example:
        >>> configure_table_connection_policy(
        ...     device=device,
        ...     source_protocol='STATIC',
        ...     destination_protocol='ISIS',
        ...     address_family='IPV4',
        ...     import_policy=['new_policy1', 'new_policy2']
        ... )
    """
    log.info(
        f"Configuring import policy for table connection {source_protocol} to "
        f"{destination_protocol} on {device.name}"
    )
    
    policy_str = ' '.join(import_policy)
    config = [
        f'network-instance {network_instance}',
        f'table-connection {source_protocol} {destination_protocol} {address_family}',
        f'src-dst-instance {source_instance} {destination_instance}',
        f'import-policy [ {policy_str} ]',
        'exit',
        'exit',
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure import policy for table connection on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_table_connection_policy(device, source_protocol, destination_protocol,
                                         address_family, source_instance='default',
                                         destination_instance='default',
                                         network_instance='default'):
    """Remove import policies from a table connection.
    
    Args:
        device (obj): Device object
        source_protocol (str): Source protocol
        destination_protocol (str): Destination protocol
        address_family (str): Address family - IPV4 or IPV6
        source_instance (str, optional): Source protocol instance name. Defaults to 'default'.
        destination_instance (str, optional): Destination protocol instance name. 
                                             Defaults to 'default'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to unconfigure table connection policy
    
    Example:
        >>> unconfigure_table_connection_policy(
        ...     device=device,
        ...     source_protocol='STATIC',
        ...     destination_protocol='ISIS',
        ...     address_family='IPV4'
        ... )
    """
    log.info(
        f"Removing import policy from table connection {source_protocol} to "
        f"{destination_protocol} on {device.name}"
    )
    
    config = [
        f'network-instance {network_instance}',
        f'table-connection {source_protocol} {destination_protocol} {address_family}',
        f'src-dst-instance {source_instance} {destination_instance}',
        'no import-policy',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove import policy from table connection on {device.name}. "
            f"Error:\n{e}"
        )


# ============================================================================
# Category 2: Overload Bit Control
# ============================================================================

def configure_isis_overload_bit(device, mode, reset_trigger=None, wait_delay=None,
                                 network_instance='default', protocol_instance='default'):
    """Configure ISIS overload bit behavior.
    
    Supports permanent overload, boot-time overload with triggers, or high-metric advertisement.
    The modes are mutually exclusive - only one can be active at a time.
    
    Args:
        device (obj): Device object
        mode (str): Overload mode - one of: 'set-bit', 'set-bit-on-boot', 'advertise-high-metric'
        reset_trigger (str, optional): Reset trigger for 'set-bit-on-boot' mode - 
                                       'WAIT_DELAY' or 'WAIT_FOR_BGP'
        wait_delay (int, optional): Delay in seconds if reset_trigger is 'WAIT_DELAY'
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure overload bit
        ValueError: Invalid mode or missing required parameters
    
    Example:
        >>> # Permanent overload
        >>> configure_isis_overload_bit(
        ...     device=device,
        ...     mode='set-bit'
        ... )
        
        >>> # Overload on boot with 300 second delay
        >>> configure_isis_overload_bit(
        ...     device=device,
        ...     mode='set-bit-on-boot',
        ...     reset_trigger='WAIT_DELAY',
        ...     wait_delay=300
        ... )
        
        >>> # Overload on boot waiting for BGP
        >>> configure_isis_overload_bit(
        ...     device=device,
        ...     mode='set-bit-on-boot',
        ...     reset_trigger='WAIT_FOR_BGP'
        ... )
        
        >>> # Advertise high metric instead
        >>> configure_isis_overload_bit(
        ...     device=device,
        ...     mode='advertise-high-metric'
        ... )
    """
    log.info(
        f"Configuring ISIS overload bit (mode: {mode}) on {device.name}"
    )
    
    # Validate mode
    valid_modes = ['set-bit', 'set-bit-on-boot', 'advertise-high-metric']
    if mode not in valid_modes:
        raise ValueError(
            f"Invalid mode '{mode}'. Must be one of: {', '.join(valid_modes)}"
        )
    
    # Validate reset_trigger if provided
    if reset_trigger:
        valid_triggers = ['WAIT_DELAY', 'WAIT_FOR_BGP']
        if reset_trigger not in valid_triggers:
            raise ValueError(
                f"Invalid reset_trigger '{reset_trigger}'. "
                f"Must be one of: {', '.join(valid_triggers)}"
            )
        
        if reset_trigger == 'WAIT_DELAY' and wait_delay is None:
            raise ValueError("wait_delay is required when reset_trigger is 'WAIT_DELAY'")
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [isis_context]
    
    # First disable all overload modes (they are mutually exclusive)
    config.extend([
        'no global lsp-bit overload-bit set-bit',
        'no global lsp-bit overload-bit set-bit-on-boot',
        'no global lsp-bit overload-bit advertise-high-metric',
        'no global lsp-bit overload-bit reset-trigger'
    ])
    
    # Configure the requested mode
    if mode == 'set-bit':
        config.append('global lsp-bit overload-bit set-bit true')
    
    elif mode == 'set-bit-on-boot':
        config.append('global lsp-bit overload-bit set-bit-on-boot true')
        
        if reset_trigger:
            if reset_trigger == 'WAIT_DELAY':
                config.extend([
                    f'global lsp-bit overload-bit reset-trigger {reset_trigger}',
                    f'delay {wait_delay}',
                    'exit'
                ])
            else:  # WAIT_FOR_BGP
                config.append(f'global lsp-bit overload-bit reset-trigger {reset_trigger}')
    
    elif mode == 'advertise-high-metric':
        config.append('global lsp-bit overload-bit advertise-high-metric true')
    
    config.append('!')
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS overload bit on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_overload_bit(device, network_instance='default',
                                   protocol_instance='default'):
    """Disable all overload bit configurations and return to normal operation.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to unconfigure overload bit
    
    Example:
        >>> unconfigure_isis_overload_bit(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Disabling all overload bit configurations on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global lsp-bit overload-bit set-bit',
        'no global lsp-bit overload-bit set-bit-on-boot',
        'no global lsp-bit overload-bit advertise-high-metric',
        'no global lsp-bit overload-bit reset-trigger',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable overload bit on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 3: LSP MTU Configuration
# ============================================================================

def configure_isis_lsp_mtu(device, mtu, network_instance='default',
                           protocol_instance='default'):
    """Configure ISIS LSP MTU size.
    
    Args:
        device (obj): Device object
        mtu (int): LSP MTU size in bytes (typically 512-9192)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure LSP MTU
    
    Example:
        >>> configure_isis_lsp_mtu(
        ...     device=device,
        ...     mtu=1500,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Configuring ISIS LSP MTU {mtu} on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global transport lsp-mtu-size {mtu}',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS LSP MTU on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_lsp_mtu(device, network_instance='default',
                             protocol_instance='default'):
    """Reset LSP MTU to default value.
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to unconfigure LSP MTU
    
    Example:
        >>> unconfigure_isis_lsp_mtu(
        ...     device=device,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"Resetting ISIS LSP MTU to default on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global transport lsp-mtu-size',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS LSP MTU on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 4: Summary Address / Route Aggregation
# ============================================================================

def configure_isis_summary_address_ipv4(device, prefix, metric=None, level=None,
                                        tag=None, adv_unreachable=None,
                                        apply_policy=None, unreachable_component_tag=None,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure IPv4 summary address (route aggregation) in ISIS.
    
    Args:
        device (obj): Device object
        prefix (str): Summary prefix in CIDR notation (e.g., '10.0.0.0/8')
        metric (int, optional): Metric for summarized prefix
        level (str, optional): ISIS level - LEVEL_1, LEVEL_2, or LEVEL_1_2 (default: LEVEL_1_2)
        tag (int, optional): Route tag (1-4294967295)
        adv_unreachable (bool, optional): Enable UPA for components
        apply_policy (list, optional): List of policy names to apply
        unreachable_component_tag (int, optional): Tag value to limit UPA generation
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure summary address
    
    Example:
        >>> # Basic summary
        >>> configure_isis_summary_address_ipv4(
        ...     device=device,
        ...     prefix='10.0.0.0/8',
        ...     metric=100,
        ...     level='LEVEL_2'
        ... )
        
        >>> # Advanced summary with policy and UPA
        >>> configure_isis_summary_address_ipv4(
        ...     device=device,
        ...     prefix='192.168.0.0/16',
        ...     metric=50,
        ...     level='LEVEL_1_2',
        ...     tag=100,
        ...     adv_unreachable=True,
        ...     apply_policy=['summary_policy'],
        ...     unreachable_component_tag=200
        ... )
    """
    log.info(
        f"Configuring IPv4 summary address {prefix} on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'global af IPV4 UNICAST',
        f'summary-prefix {prefix}'
    ]
    
    if metric is not None:
        config.append(f'metric {metric}')
    
    if level:
        config.append(f'level {level}')
    
    if tag is not None:
        config.append(f'tag {tag}')
    
    if adv_unreachable is not None:
        adv_str = 'true' if adv_unreachable else 'false'
        config.append(f'adv-unreachable {adv_str}')
    
    if apply_policy:
        policy_str = ' '.join(apply_policy)
        config.append(f'apply-policy [ {policy_str} ]')
    
    if unreachable_component_tag is not None:
        config.append(f'unreachable-component-tag {unreachable_component_tag}')
    
    config.extend(['exit', 'exit', '!'])
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv4 summary address {prefix} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_summary_address_ipv4(device, prefix, network_instance='default',
                                          protocol_instance='default'):
    """Remove IPv4 summary address configuration.
    
    Args:
        device (obj): Device object
        prefix (str): Summary prefix to remove
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to unconfigure summary address
    
    Example:
        >>> unconfigure_isis_summary_address_ipv4(
        ...     device=device,
        ...     prefix='10.0.0.0/8'
        ... )
    """
    log.info(
        f"Removing IPv4 summary address {prefix} on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'global af IPV4 UNICAST',
        f'no summary-prefix {prefix}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv4 summary address {prefix} on {device.name}. Error:\n{e}"
        )


def configure_isis_summary_address_ipv6(device, prefix, metric=None, level=None,
                                        tag=None, adv_unreachable=None,
                                        apply_policy=None, unreachable_component_tag=None,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure IPv6 summary address (route aggregation) in ISIS.
    
    Args:
        device (obj): Device object
        prefix (str): Summary prefix in CIDR notation (e.g., '2001:db8::/32')
        metric (int, optional): Metric for summarized prefix
        level (str, optional): ISIS level - LEVEL_1, LEVEL_2, or LEVEL_1_2 (default: LEVEL_1_2)
        tag (int, optional): Route tag (1-4294967295)
        adv_unreachable (bool, optional): Enable UPA for components
        apply_policy (list, optional): List of policy names to apply
        unreachable_component_tag (int, optional): Tag value to limit UPA generation
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure IPv6 summary address
    
    Example:
        >>> configure_isis_summary_address_ipv6(
        ...     device=device,
        ...     prefix='2001:db8::/32',
        ...     metric=100,
        ...     level='LEVEL_2'
        ... )
    """
    log.info(
        f"Configuring IPv6 summary address {prefix} on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'global af IPV6 UNICAST',
        f'summary-prefix {prefix}'
    ]
    
    if metric is not None:
        config.append(f'metric {metric}')
    
    if level:
        config.append(f'level {level}')
    
    if tag is not None:
        config.append(f'tag {tag}')
    
    if adv_unreachable is not None:
        adv_str = 'true' if adv_unreachable else 'false'
        config.append(f'adv-unreachable {adv_str}')
    
    if apply_policy:
        policy_str = ' '.join(apply_policy)
        config.append(f'apply-policy [ {policy_str} ]')
    
    if unreachable_component_tag is not None:
        config.append(f'unreachable-component-tag {unreachable_component_tag}')
    
    config.extend(['exit', 'exit', '!'])
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv6 summary address {prefix} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_summary_address_ipv6(device, prefix, network_instance='default',
                                          protocol_instance='default'):
    """Remove IPv6 summary address configuration.
    
    Args:
        device (obj): Device object
        prefix (str): IPv6 summary prefix to remove
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to unconfigure IPv6 summary address
    
    Example:
        >>> unconfigure_isis_summary_address_ipv6(
        ...     device=device,
        ...     prefix='2001:db8::/32'
        ... )
    """
    log.info(
        f"Removing IPv6 summary address {prefix} on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'global af IPV6 UNICAST',
        f'no summary-prefix {prefix}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv6 summary address {prefix} on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Category 5: Multi-Topology (IPv6)
# ============================================================================

def configure_isis_ipv6_multi_topology(device, enabled=True, network_instance='default',
                                       protocol_instance='default'):
    """Enable or disable multi-topology for IPv6 address family in ISIS.
    
    Multi-topology allows separate topologies for different address families.
    This setting is only available for IPv6 (not IPv4).
    
    Args:
        device (obj): Device object
        enabled (bool, optional): Enable or disable multi-topology. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure IPv6 multi-topology
    
    Example:
        >>> # Enable IPv6 multi-topology
        >>> configure_isis_ipv6_multi_topology(
        ...     device=device,
        ...     enabled=True
        ... )
        
        >>> # Disable IPv6 multi-topology
        >>> configure_isis_ipv6_multi_topology(
        ...     device=device,
        ...     enabled=False
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} IPv6 multi-topology on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    enabled_str = 'true' if enabled else 'false'
    config = [
        isis_context,
        'global af IPV6 UNICAST',
        f'multi-topology enabled {enabled_str}',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv6 multi-topology on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_ipv6_multi_topology(device, network_instance='default',
                                         protocol_instance='default'):
    """Reset IPv6 multi-topology to default (enabled).
    
    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to unconfigure IPv6 multi-topology
    
    Example:
        >>> unconfigure_isis_ipv6_multi_topology(
        ...     device=device
        ... )
    """
    log.info(
        f"Resetting IPv6 multi-topology to default on {device.name}"
    )
    
    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'global af IPV6 UNICAST',
        'no multi-topology enabled',
        'exit',
        '!'
    ]
    
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset IPv6 multi-topology on {device.name}. Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Inter-level Propagation Policy (Route Leaking)
# ---------------------------------------------------------------------------


def configure_isis_level_import_policy(device, direction, policy_name,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure ISIS inter-level route leaking import policy.

    Applies a routing policy to control prefix propagation between ISIS
    levels. The policy must already be defined via the routing-policy
    APIs before calling this function.

    Args:
        device (obj): Device object
        direction (str): Leak direction — 'level1-to-level2' or
            'level2-to-level1'
        policy_name (str): Name of the routing-policy to apply
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If direction is invalid
        SubCommandFailure: Failed to configure import policy

    Example:
        >>> configure_isis_level_import_policy(
        ...     device=device,
        ...     direction='level2-to-level1',
        ...     policy_name='LEAK-L2-TO-L1',
        ... )
    """
    valid_directions = ('level1-to-level2', 'level2-to-level1')
    if direction not in valid_directions:
        raise ValueError(
            f"Invalid direction '{direction}'. "
            f"Must be one of: {', '.join(valid_directions)}"
        )

    log.info(
        f"Configuring ISIS {direction} import-policy {policy_name} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global inter-level-propagation-policies {direction} import-policy {policy_name}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS {direction} import-policy {policy_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_level_import_policy(device, direction,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove ISIS inter-level route leaking import policy.

    Args:
        device (obj): Device object
        direction (str): Leak direction — 'level1-to-level2' or
            'level2-to-level1'
        network_instance (str, optional): Network instance name.
            Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If direction is invalid
        SubCommandFailure: Failed to remove import policy

    Example:
        >>> unconfigure_isis_level_import_policy(
        ...     device=device,
        ...     direction='level2-to-level1',
        ... )
    """
    valid_directions = ('level1-to-level2', 'level2-to-level1')
    if direction not in valid_directions:
        raise ValueError(
            f"Invalid direction '{direction}'. "
            f"Must be one of: {', '.join(valid_directions)}"
        )

    log.info(
        f"Removing ISIS {direction} import-policy from {device.name} "
        f"(network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global no inter-level-propagation-policies {direction} import-policy',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS {direction} import-policy "
            f"from {device.name}. Error:\n{e}"
        )


def restart_isis_instance(device, network_instance='default', protocol_instance='default'):
    """Restart the ISIS protocol instance.

    Executes ``restart isis {network_instance} {protocol_instance}`` and
    automatically confirms the restart dialog prompt with "yes".

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to restart ISIS instance

    Example:
        >>> restart_isis_instance(device)
        >>> restart_isis_instance(device, network_instance='default', protocol_instance='default')
    """

    log.info(
        f"Restarting ISIS instance {protocol_instance} in network-instance "
        f"{network_instance} on {device.name}"
    )

    cmd = f"restart isis {network_instance} {protocol_instance}"

    try:
        from unicon.eal.dialogs import Dialog, Statement

        confirm_dialog = Dialog([
            Statement(
                pattern=r'.*[Rr]estart.*\[',
                action='sendline(yes)',
                loop_continue=True,
                continue_timer=False,
            )
        ])
        device.execute(cmd, reply=confirm_dialog)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not restart ISIS instance {protocol_instance} "
            f"on {device.name}. Error:\n{e}"
        )


# ===========================================================================
# Flex-Algo Configure APIs
# ===========================================================================

def configure_isis_flexible_algorithm(device, algo_id, metric_type=None,
                                       advertise_definition=None,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure an ISIS flexible-algorithm definition.

    Args:
        device (obj): Device object
        algo_id (int): Flexible-algorithm ID (128-255)
        metric_type (str, optional): Metric type ('IGP_METRIC', 'TE_METRIC',
            'LINK_DELAY'). Defaults to None.
        advertise_definition (bool, optional): Advertise definition in LSPs.
            Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS flexible-algorithm

    Example:
        >>> configure_isis_flexible_algorithm(device, 128, metric_type='TE_METRIC')
    """
    log.info(
        f"Configuring ISIS flexible-algorithm {algo_id} on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global flexible-algorithm {algo_id}',
    ]

    if metric_type is not None:
        config.append(f'metric-type {metric_type}')

    if advertise_definition is not None:
        val = 'true' if advertise_definition else 'false'
        config.append(f'advertise-definition enabled {val}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS flexible-algorithm {algo_id} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_flexible_algorithm(device, algo_id,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove an ISIS flexible-algorithm definition.

    Args:
        device (obj): Device object
        algo_id (int): Flexible-algorithm ID (128-255)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS flexible-algorithm

    Example:
        >>> unconfigure_isis_flexible_algorithm(device, 128)
    """
    log.info(
        f"Removing ISIS flexible-algorithm {algo_id} from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'no global flexible-algorithm {algo_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS flexible-algorithm {algo_id} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_flex_algo_admin_groups(device, interface, admin_groups,
                                                      network_instance='default',
                                                      protocol_instance='default'):
    """Configure flex-algo admin-groups on an ISIS interface.

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g., 'swp1')
        admin_groups (list): List of admin-group names (e.g., ['green', 'red'])
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure flex-algo admin-groups

    Example:
        >>> configure_isis_interface_flex_algo_admin_groups(
        ...     device, 'swp1', ['green', 'red']
        ... )
    """
    log.info(
        f"Configuring ISIS flex-algo admin-groups on {interface} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    groups_str = ' '.join(str(g) for g in admin_groups)
    config = [
        intf_context,
        f'flexible-algorithm admin-groups [ {groups_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS flex-algo admin-groups on {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_flex_algo_admin_groups(device, interface,
                                                        network_instance='default',
                                                        protocol_instance='default'):
    """Remove flex-algo admin-groups from an ISIS interface.

    Args:
        device (obj): Device object
        interface (str): Interface name
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove flex-algo admin-groups

    Example:
        >>> unconfigure_isis_interface_flex_algo_admin_groups(device, 'swp1')
    """
    log.info(
        f"Removing ISIS flex-algo admin-groups from {interface} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no flexible-algorithm admin-groups',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS flex-algo admin-groups from {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_flex_algo_metric(device, interface, level,
                                                te_metric=None, delay_metric=None,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure flex-algo TE/delay metric on an ISIS interface at a specific level.

    CLI emitted::

        <interface context>
         level {level} flexible-algorithm te-metric {te_metric}
         level {level} flexible-algorithm delay-metric {delay_metric}
        !

    Args:
        device (obj): Device object
        interface (str): Interface name
        level (int): ISIS level (1 or 2)
        te_metric (int, optional): TE metric value. Defaults to None.
        delay_metric (int, optional): Delay metric value. Defaults to None.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: Neither te_metric nor delay_metric was supplied
        SubCommandFailure: Failed to configure flex-algo metric

    Example:
        >>> configure_isis_interface_flex_algo_metric(
        ...     device, 'swp1', 2, te_metric=100
        ... )

    Note:
        **This metric is per-interface-level and algorithm-agnostic — there is no
        algo_id parameter, because the CLI has no per-algorithm interface metric.**
        ``level N flexible-algorithm ?`` offers exactly ``te-metric`` and
        ``delay-metric``; operational state reports a single
        ``flexible-algorithm`` object directly under the level, with no algorithm
        key. An earlier revision took an ``algo_id`` and emitted
        ``level N flexible-algorithm {algo_id}``, which the device rejects with
        ``syntax error: unknown argument``. That made the whole call a **silent
        no-op** — nothing configured, nothing raised — because a rejected line
        stages nothing and the resulting ``% No modifications to commit`` is not
        treated as a failure. Do not reintroduce an algo argument here.

        ``algo_id`` remains correct on the *global* flex-algo functions
        (:func:`configure_isis_flexible_algorithm` and friends), which really are
        keyed by algorithm.

        Verified on rtr1 2026-08-25: both metrics read back in running-config and
        in operational state (``levels.<n>.flexible_algorithm``).
    """
    if te_metric is None and delay_metric is None:
        raise ValueError(
            "configure_isis_interface_flex_algo_metric requires te_metric and/or "
            "delay_metric; a bare 'flexible-algorithm' line is rejected by the device"
        )

    log.info(
        f"Configuring ISIS flex-algo metric on {interface} level {level} "
        f"on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [intf_context]

    if te_metric is not None:
        config.append(f'level {level} flexible-algorithm te-metric {te_metric}')

    if delay_metric is not None:
        config.append(f'level {level} flexible-algorithm delay-metric {delay_metric}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS flex-algo metric on {interface} level {level} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_flex_algo_metric(device, interface, level,
                                                  te_metric=False, delay_metric=False,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Remove flex-algo TE/delay metric from an ISIS interface at a specific level.

    Called with neither flag it removes **both** metrics, per the convention that
    an unconfigure with no values clears the whole thing.

    CLI emitted::

        <interface context>
         no level {level} flexible-algorithm te-metric
         no level {level} flexible-algorithm delay-metric
        !

    Args:
        device (obj): Device object
        interface (str): Interface name
        level (int): ISIS level (1 or 2)
        te_metric (bool): Remove the TE metric. Defaults to False.
        delay_metric (bool): Remove the delay metric. Defaults to False.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove flex-algo metric

    Example:
        >>> # remove both
        >>> unconfigure_isis_interface_flex_algo_metric(device, 'swp1', 2)
        >>> # remove only the TE metric
        >>> unconfigure_isis_interface_flex_algo_metric(
        ...     device, 'swp1', 2, te_metric=True)

    Note:
        Exact inverse of :func:`configure_isis_interface_flex_algo_metric`, and
        takes no ``algo_id`` for the same reason — see that function's note. The
        previous revision emitted ``no level N flexible-algorithm {algo_id}``,
        which was a silent no-op. Emitted one flat ``no`` line per metric rather
        than removing the ``flexible-algorithm`` container, so neither metric can
        be taken out by a removal aimed at the other.

        Verified on rtr1 2026-08-25 by read-back in both directions.
    """
    # No flags means "clear the whole thing".
    if not te_metric and not delay_metric:
        te_metric = delay_metric = True

    log.info(
        f"Removing ISIS flex-algo metric from {interface} level {level} "
        f"on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [intf_context]

    if te_metric:
        config.append(f'no level {level} flexible-algorithm te-metric')

    if delay_metric:
        config.append(f'no level {level} flexible-algorithm delay-metric')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS flex-algo metric from {interface} level {level} "
            f"on {device.name}. Error:\n{e}"
        )


# ===========================================================================
# Traffic Engineering Configure APIs
# ===========================================================================

def configure_isis_traffic_engineering_router_id(device, router_id, af='ipv4',
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Configure ISIS traffic-engineering router-id.

    Args:
        device (obj): Device object
        router_id (str): Router-id address (e.g., '1.1.1.1')
        af (str, optional): Address family ('ipv4' or 'ipv6'). Defaults to 'ipv4'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS TE router-id

    Example:
        >>> configure_isis_traffic_engineering_router_id(device, '1.1.1.1')
    """
    log.info(
        f"Configuring ISIS TE {af} router-id {router_id} on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global traffic-engineering {af}-router-id {router_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS TE router-id on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_traffic_engineering_router_id(device, af='ipv4',
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Remove ISIS traffic-engineering router-id.

    Args:
        device (obj): Device object
        af (str, optional): Address family ('ipv4' or 'ipv6'). Defaults to 'ipv4'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS TE router-id

    Example:
        >>> unconfigure_isis_traffic_engineering_router_id(device)
    """
    log.info(f"Removing ISIS TE {af} router-id from {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'no global traffic-engineering {af}-router-id',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS TE router-id from {device.name}. Error:\n{e}"
        )


def configure_isis_level_traffic_engineering(device, level, enabled=True,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Configure per-level ISIS traffic-engineering enabled state.

    Args:
        device (obj): Device object
        level (int): ISIS level (1 or 2)
        enabled (bool, optional): Enable TE. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS level TE

    Example:
        >>> configure_isis_level_traffic_engineering(device, 2, enabled=True)
    """
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring ISIS level {level} traffic-engineering enabled {val} "
        f"on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {level} traffic-engineering enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS level {level} TE on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_level_traffic_engineering(device, level,
                                                 network_instance='default',
                                                 protocol_instance='default'):
    """Remove per-level ISIS traffic-engineering configuration.

    Args:
        device (obj): Device object
        level (int): ISIS level (1 or 2)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS level TE

    Example:
        >>> unconfigure_isis_level_traffic_engineering(device, 2)
    """
    log.info(
        f"Removing ISIS level {level} traffic-engineering from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'no level {level} traffic-engineering enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS level {level} TE from {device.name}. "
            f"Error:\n{e}"
        )


# ===========================================================================
# Flex-Algo Extended Configure APIs
# ===========================================================================

def configure_isis_flexible_algorithm_priority(device, algo_id, priority,
                                                 network_instance='default',
                                                 protocol_instance='default'):
    """Configure priority for an ISIS flexible-algorithm definition.

    Args:
        device (obj): Device object
        algo_id (int): Flexible-algorithm ID (128-255)
        priority (int): Priority value (higher wins FAD election)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure flex-algo priority

    Example:
        >>> configure_isis_flexible_algorithm_priority(device, 128, 100)
    """
    log.info(
        f"Configuring ISIS flex-algo {algo_id} priority {priority} on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global flexible-algorithm {algo_id}',
        f'priority {priority}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS flex-algo {algo_id} priority on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_flexible_algorithm_priority(device, algo_id,
                                                   network_instance='default',
                                                   protocol_instance='default'):
    """Remove priority from an ISIS flexible-algorithm definition.

    Args:
        device (obj): Device object
        algo_id (int): Flexible-algorithm ID (128-255)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove flex-algo priority

    Example:
        >>> unconfigure_isis_flexible_algorithm_priority(device, 128)
    """
    log.info(
        f"Removing ISIS flex-algo {algo_id} priority from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global flexible-algorithm {algo_id}',
        'no priority',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS flex-algo {algo_id} priority from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_flexible_algorithm_admin_groups(device, algo_id, constraint_type,
                                                     groups,
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Configure admin-group constraints for an ISIS flexible-algorithm.

    Args:
        device (obj): Device object
        algo_id (int): Flexible-algorithm ID (128-255)
        constraint_type (str): Constraint type: 'include-any', 'exclude-any',
            or 'include-all'
        groups (list): List of admin-group names (e.g., ['red', 'green'])
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure flex-algo admin-group constraint

    Example:
        >>> configure_isis_flexible_algorithm_admin_groups(
        ...     device, 128, 'include-any', ['red', 'green']
        ... )
    """
    groups_str = ' '.join(str(g) for g in groups)
    log.info(
        f"Configuring ISIS flex-algo {algo_id} admin-groups {constraint_type} "
        f"[ {groups_str} ] on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global flexible-algorithm {algo_id}',
        f'admin-groups {constraint_type} [ {groups_str} ]',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS flex-algo {algo_id} admin-groups on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_flexible_algorithm_admin_groups(device, algo_id, constraint_type,
                                                       network_instance='default',
                                                       protocol_instance='default'):
    """Remove admin-group constraints from an ISIS flexible-algorithm.

    Args:
        device (obj): Device object
        algo_id (int): Flexible-algorithm ID (128-255)
        constraint_type (str): Constraint type: 'include-any', 'exclude-any',
            or 'include-all'
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove flex-algo admin-group constraint

    Example:
        >>> unconfigure_isis_flexible_algorithm_admin_groups(device, 128, 'include-any')
    """
    log.info(
        f"Removing ISIS flex-algo {algo_id} admin-groups {constraint_type} "
        f"from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global flexible-algorithm {algo_id}',
        f'no admin-groups {constraint_type}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS flex-algo {algo_id} admin-groups from "
            f"{device.name}. Error:\n{e}"
        )


# ===========================================================================
# Dynamic Delay Measurement Configure APIs
# ===========================================================================

def configure_isis_dynamic_delay_measurement(device, probe_interval=None,
                                               advertisement_interval=None,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Configure ISIS dynamic delay measurement parameters.

    Args:
        device (obj): Device object
        probe_interval (int, optional): TWAMP probe interval in seconds.
        advertisement_interval (int, optional): Advertisement interval in seconds.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure dynamic delay measurement

    Example:
        >>> configure_isis_dynamic_delay_measurement(device, probe_interval=20,
        ...     advertisement_interval=60)
    """
    log.info(
        f"Configuring ISIS dynamic-delay-measurement on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [isis_context]

    if probe_interval is not None:
        config.append(
            f'global dynamic-delay-measurement probe-interval {probe_interval}'
        )

    if advertisement_interval is not None:
        config.append(
            f'global dynamic-delay-measurement advertisement-interval '
            f'{advertisement_interval}'
        )

    if len(config) == 1:
        log.warning("No dynamic-delay-measurement parameters provided")
        return

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS dynamic-delay-measurement on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_dynamic_delay_measurement(device, network_instance='default',
                                                 protocol_instance='default'):
    """Remove ISIS dynamic delay measurement configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove dynamic delay measurement

    Example:
        >>> unconfigure_isis_dynamic_delay_measurement(device)
    """
    log.info(
        f"Removing ISIS dynamic-delay-measurement from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global dynamic-delay-measurement probe-interval',
        'no global dynamic-delay-measurement advertisement-interval',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS dynamic-delay-measurement from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_flex_algo_delay_metric_dynamic(device, interface, level,
                                                              network_instance='default',
                                                              protocol_instance='default'):
    """Configure dynamic delay metric for flex-algo on an ISIS interface level.

    Sets the delay-metric to DYNAMIC (uses TWAMP measurements).

    Args:
        device (obj): Device object
        interface (str): Interface name
        level (int): ISIS level (1 or 2)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure dynamic delay metric

    Example:
        >>> configure_isis_interface_flex_algo_delay_metric_dynamic(device, 'swp1', 2)
    """
    log.info(
        f"Configuring ISIS flex-algo delay-metric DYNAMIC on {interface} "
        f"level {level} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {level} flexible-algorithm delay-metric DYNAMIC',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS dynamic delay metric on {interface} "
            f"level {level} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_flex_algo_delay_metric_dynamic(device, interface, level,
                                                                network_instance='default',
                                                                protocol_instance='default'):
    """Remove dynamic delay metric for flex-algo from an ISIS interface level.

    Args:
        device (obj): Device object
        interface (str): Interface name
        level (int): ISIS level (1 or 2)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove dynamic delay metric

    Example:
        >>> unconfigure_isis_interface_flex_algo_delay_metric_dynamic(device, 'swp1', 2)
    """
    log.info(
        f"Removing ISIS flex-algo delay-metric from {interface} level {level} "
        f"on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'no level {level} flexible-algorithm delay-metric',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS dynamic delay metric from {interface} "
            f"level {level} on {device.name}. Error:\n{e}"
        )


# ===========================================================================
# SRMS (Segment Routing Mapping Server) Configure APIs
# ===========================================================================

def configure_isis_srms_mapping(device, mapping_name, network_instance='default',
                                  protocol_instance='default'):
    """Configure ISIS SRMS mapping name.

    Args:
        device (obj): Device object
        mapping_name (str): SRMS mapping name to advertise
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS SRMS mapping

    Example:
        >>> configure_isis_srms_mapping(device, 'srms1')
    """
    log.info(f"Configuring ISIS SRMS mapping '{mapping_name}' on {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global segment-routing srms mapping {mapping_name}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS SRMS mapping on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_srms_mapping(device, network_instance='default',
                                    protocol_instance='default'):
    """Remove ISIS SRMS mapping configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS SRMS mapping

    Example:
        >>> unconfigure_isis_srms_mapping(device)
    """
    log.info(f"Removing ISIS SRMS mapping from {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global segment-routing srms mapping',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS SRMS mapping from {device.name}. Error:\n{e}"
        )


def configure_isis_srms_receive(device, enabled=True, network_instance='default',
                                  protocol_instance='default'):
    """Configure ISIS SRMS receive-enabled state.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable SRMS receive. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS SRMS receive

    Example:
        >>> configure_isis_srms_receive(device, enabled=True)
    """
    val = 'true' if enabled else 'false'
    log.info(f"Configuring ISIS SRMS receive-enabled {val} on {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global segment-routing srms receive-enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS SRMS receive on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_srms_receive(device, network_instance='default',
                                    protocol_instance='default'):
    """Remove ISIS SRMS receive-enabled configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS SRMS receive

    Example:
        >>> unconfigure_isis_srms_receive(device)
    """
    log.info(f"Removing ISIS SRMS receive-enabled from {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global segment-routing srms receive-enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS SRMS receive from {device.name}. Error:\n{e}"
        )


def configure_isis_srms_advertise(device, enabled=True, network_instance='default',
                                    protocol_instance='default'):
    """Configure ISIS SRMS advertise-enabled state.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable SRMS advertise. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS SRMS advertise

    Example:
        >>> configure_isis_srms_advertise(device, enabled=True)
    """
    val = 'true' if enabled else 'false'
    log.info(f"Configuring ISIS SRMS advertise-enabled {val} on {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global segment-routing srms advertise-enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS SRMS advertise on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_srms_advertise(device, network_instance='default',
                                      protocol_instance='default'):
    """Remove ISIS SRMS advertise-enabled configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS SRMS advertise

    Example:
        >>> unconfigure_isis_srms_advertise(device)
    """
    log.info(f"Removing ISIS SRMS advertise-enabled from {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global segment-routing srms advertise-enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS SRMS advertise from {device.name}. Error:\n{e}"
        )


# ===========================================================================
# Auto-Cost and MPLS LDP Sync Configure APIs
# ===========================================================================

def configure_isis_auto_cost_reference_bandwidth(device, bandwidth,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Configure ISIS auto-cost reference bandwidth.

    Args:
        device (obj): Device object
        bandwidth (int): Reference bandwidth in Mbps
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS auto-cost reference bandwidth

    Example:
        >>> configure_isis_auto_cost_reference_bandwidth(device, 100000)
    """
    log.info(
        f"Configuring ISIS auto-cost reference-bandwidth {bandwidth} on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global auto-cost reference-bandwidth {bandwidth}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS auto-cost reference-bandwidth on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_auto_cost_reference_bandwidth(device,
                                                      network_instance='default',
                                                      protocol_instance='default'):
    """Remove ISIS auto-cost reference bandwidth configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS auto-cost reference bandwidth

    Example:
        >>> unconfigure_isis_auto_cost_reference_bandwidth(device)
    """
    log.info(f"Removing ISIS auto-cost reference-bandwidth from {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global auto-cost reference-bandwidth',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS auto-cost reference-bandwidth from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_mpls_ldp_sync(device, enabled=True, network_instance='default',
                                   protocol_instance='default'):
    """Configure ISIS global MPLS IGP-LDP synchronization.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable MPLS LDP sync. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS MPLS LDP sync

    Example:
        >>> configure_isis_mpls_ldp_sync(device, enabled=True)
    """
    val = 'true' if enabled else 'false'
    log.info(f"Configuring ISIS MPLS igp-ldp-sync enabled {val} on {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global mpls igp-ldp-sync enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS MPLS LDP sync on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_mpls_ldp_sync(device, network_instance='default',
                                     protocol_instance='default'):
    """Remove ISIS global MPLS IGP-LDP synchronization configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS MPLS LDP sync

    Example:
        >>> unconfigure_isis_mpls_ldp_sync(device)
    """
    log.info(f"Removing ISIS MPLS igp-ldp-sync from {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global mpls igp-ldp-sync enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS MPLS LDP sync from {device.name}. Error:\n{e}"
        )


# ===========================================================================
# Global Hello Authentication Configure APIs
# ===========================================================================

def configure_isis_global_hello_auth(device, auth_type, keychain=None,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure ISIS global hello-authentication.

    Args:
        device (obj): Device object
        auth_type (str): Authentication type ('SIMPLE_KEY' or 'KEYCHAIN')
        keychain (str, optional): Keychain name (required when auth_type is 'KEYCHAIN').
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS global hello auth

    Example:
        >>> configure_isis_global_hello_auth(device, 'KEYCHAIN', keychain='isis-key')
    """
    log.info(
        f"Configuring ISIS global hello-authentication auth-type {auth_type} "
        f"on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [isis_context]

    if keychain is not None:
        config.append(f'global hello-authentication keychain {keychain}')

    config.append(f'global hello-authentication auth-type {auth_type}')

    if auth_type == 'SIMPLE_KEY':
        config.append('global hello-authentication key crypto-algorithm MD5')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS global hello auth on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_isis_global_hello_auth(device, network_instance='default',
                                         protocol_instance='default'):
    """Remove ISIS global hello-authentication configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS global hello auth

    Example:
        >>> unconfigure_isis_global_hello_auth(device)
    """
    log.info(f"Removing ISIS global hello-authentication from {device.name}")

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global hello-authentication auth-type',
        'no global hello-authentication keychain',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS global hello auth from {device.name}. "
            f"Error:\n{e}"
        )


# ===========================================================================
# Microloop Avoidance (MLA) Configure APIs
# ===========================================================================

def configure_isis_micro_loop_avoidance_sr_mpls(device, af='IPV4', enabled=True,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Configure ISIS micro-loop avoidance for SR-MPLS per address family.

    Enables SR-MPLS based microloop avoidance which temporarily steers traffic
    via SR tunnels to prevent transient loops during convergence.

    Args:
        device (obj): Device object
        af (str, optional): Address family — 'IPV4' or 'IPV6'. Defaults to 'IPV4'.
        enabled (bool, optional): Enable or disable MLA SR-MPLS. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS micro-loop avoidance SR-MPLS

    Example:
        >>> configure_isis_micro_loop_avoidance_sr_mpls(device, af='IPV4')
        >>> configure_isis_micro_loop_avoidance_sr_mpls(device, af='IPV6')
    """
    af_upper = af.upper()
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring ISIS micro-loop-avoidance sr-mpls-enabled {val} "
        f"for AF {af_upper} on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global af {af_upper} UNICAST micro-loop-avoidance sr-mpls-enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS micro-loop-avoidance sr-mpls for "
            f"AF {af_upper} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_micro_loop_avoidance_sr_mpls(device, af='IPV4',
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Remove ISIS micro-loop avoidance SR-MPLS configuration per address family.

    Args:
        device (obj): Device object
        af (str, optional): Address family — 'IPV4' or 'IPV6'. Defaults to 'IPV4'.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS micro-loop avoidance SR-MPLS

    Example:
        >>> unconfigure_isis_micro_loop_avoidance_sr_mpls(device, af='IPV4')
    """
    af_upper = af.upper()
    log.info(
        f"Removing ISIS micro-loop-avoidance sr-mpls-enabled for "
        f"AF {af_upper} from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global af {af_upper} UNICAST no micro-loop-avoidance sr-mpls-enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS micro-loop-avoidance sr-mpls for "
            f"AF {af_upper} from {device.name}. Error:\n{e}"
        )


def configure_isis_micro_loop_avoidance_srv6(device, enabled=True,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Configure ISIS micro-loop avoidance for SRv6.

    Enables SRv6-based microloop avoidance which temporarily steers traffic
    via SRv6 tunnels to prevent transient loops during convergence.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable or disable MLA SRv6. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS micro-loop avoidance SRv6

    Example:
        >>> configure_isis_micro_loop_avoidance_srv6(device)
    """
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring ISIS micro-loop-avoidance srv6-enabled {val} on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global micro-loop-avoidance srv6-enabled {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS micro-loop-avoidance srv6 on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_micro_loop_avoidance_srv6(device, network_instance='default',
                                                  protocol_instance='default'):
    """Remove ISIS micro-loop avoidance SRv6 configuration.

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS micro-loop avoidance SRv6

    Example:
        >>> unconfigure_isis_micro_loop_avoidance_srv6(device)
    """
    log.info(
        f"Removing ISIS micro-loop-avoidance srv6-enabled from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global micro-loop-avoidance srv6-enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS micro-loop-avoidance srv6 from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_micro_loop_avoidance_rib_update_delay(device, delay_ms,
                                                            network_instance='default',
                                                            protocol_instance='default'):
    """Configure ISIS micro-loop avoidance RIB update delay.

    The RIB update delay controls how long microloop avoidance paths are
    retained before being replaced with the normal post-convergence nexthop.
    Default is 5000ms. Range: 1-60000ms.

    Args:
        device (obj): Device object
        delay_ms (int): RIB update delay in milliseconds (1-60000)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS MLA RIB update delay

    Example:
        >>> configure_isis_micro_loop_avoidance_rib_update_delay(device, 4500)
    """
    log.info(
        f"Configuring ISIS micro-loop-avoidance rib-update-delay {delay_ms}ms "
        f"on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global micro-loop-avoidance rib-update-delay {delay_ms}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS micro-loop-avoidance rib-update-delay on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_micro_loop_avoidance_rib_update_delay(device,
                                                              network_instance='default',
                                                              protocol_instance='default'):
    """Remove ISIS micro-loop avoidance RIB update delay (revert to default 5000ms).

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove ISIS MLA RIB update delay

    Example:
        >>> unconfigure_isis_micro_loop_avoidance_rib_update_delay(device)
    """
    log.info(
        f"Removing ISIS micro-loop-avoidance rib-update-delay from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global micro-loop-avoidance rib-update-delay',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS micro-loop-avoidance rib-update-delay from "
            f"{device.name}. Error:\n{e}"
        )


# ============================================================================
# Batch B — Timer Knobs (Round 2)
# ============================================================================
# Six new timer-related APIs proposed in
# orchestrator/proposals/approved/isis_api_batch_b_timers.md
# Modeled on the existing configure_isis_lsp_lifetime_interval and
# configure_isis_interface_hello_interval functions.
# adoc references: IS-IS.adoc §645 (lsp-gen), §1807 (csnp), §1900 (lsp-pacing),
# §2215 (interface-level hello-interval), §2240 (interface-level multiplier).
# ============================================================================


def configure_isis_lsp_first_wait_interval(device, interval_ms,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Configure ISIS LSP-generation first-wait interval.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          global timers lsp-generation lsp-first-wait-interval {interval_ms}

    Args:
        device (obj): Device object.
        interval_ms (int): LSP-first-wait delay in milliseconds.
            Range 0..600000. Default in arcOS is 15 ms.
        network_instance (str, optional): Network instance. Defaults 'default'.
        protocol_instance (str, optional): ISIS protocol instance. Defaults 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_isis_lsp_first_wait_interval(device, 100)
    """
    log.info(
        f"Configuring ISIS LSP first-wait-interval to {interval_ms}ms on "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global timers lsp-generation lsp-first-wait-interval {interval_ms}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS LSP first-wait-interval on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_lsp_first_wait_interval(device, network_instance='default',
                                              protocol_instance='default'):
    """Reset ISIS LSP-generation first-wait interval to default (15 ms).

    Args:
        device (obj): Device object.
        network_instance (str, optional): Network instance. Defaults 'default'.
        protocol_instance (str, optional): ISIS protocol instance. Defaults 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
    """
    log.info(
        f"Resetting ISIS LSP first-wait-interval to default on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global timers lsp-generation lsp-first-wait-interval',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS LSP first-wait-interval on "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_csnp_interval(device, interface, interval_sec,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Configure ISIS interface CSNP transmit interval.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          interface {interface} timers csnp-interval {interval_sec}

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp1').
        interval_sec (int): CSNP transmit interval in seconds. Default 30.
        network_instance (str, optional): Defaults 'default'.
        protocol_instance (str, optional): Defaults 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_isis_interface_csnp_interval(device, 'swp1', 60)
    """
    log.info(
        f"Configuring ISIS CSNP interval to {interval_sec}s on interface "
        f"{interface} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'timers csnp-interval {interval_sec}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS CSNP interval on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_csnp_interval(device, interface,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Reset ISIS interface CSNP transmit interval to default (30 s)."""
    log.info(
        f"Resetting ISIS CSNP interval to default on interface {interface} "
        f"on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no timers csnp-interval',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS CSNP interval on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_lsp_pacing_interval(device, interface, interval_ms,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Configure ISIS interface LSP pacing interval.

    Controls the spacing between consecutive LSP transmissions on an interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          interface {interface} timers lsp-pacing-interval {interval_ms}

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        interval_ms (int): LSP pacing interval in milliseconds. Default 33.
        network_instance (str, optional): Defaults 'default'.
        protocol_instance (str, optional): Defaults 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_isis_interface_lsp_pacing_interval(device, 'swp1', 50)
    """
    log.info(
        f"Configuring ISIS LSP pacing interval to {interval_ms}ms on interface "
        f"{interface} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'timers lsp-pacing-interval {interval_ms}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS LSP pacing interval on interface "
            f"{interface} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_lsp_pacing_interval(device, interface,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Reset ISIS interface LSP pacing interval to default (33 ms)."""
    log.info(
        f"Resetting ISIS LSP pacing interval to default on interface "
        f"{interface} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no timers lsp-pacing-interval',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS LSP pacing interval on interface "
            f"{interface} on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_level_hello_interval(device, interface, level,
                                                    interval_sec,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Configure ISIS interface-level hello interval (per-level override).

    LAN-only per arcOS adoc — overrides the interface-scope hello-interval
    for a specific level on broadcast interfaces.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          interface {interface} level {level_num} timers hello-interval {interval_sec}

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): 'level_1' or 'level_2' (maps to CLI '1' / '2').
        interval_sec (int): Hello interval in seconds. Default 10.
        network_instance (str, optional): Defaults 'default'.
        protocol_instance (str, optional): Defaults 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If level is not 'level_1' or 'level_2'.

    Example:
        >>> configure_isis_interface_level_hello_interval(
        ...     device, 'swp1', 'level_2', 5)
    """
    log.info(
        f"Configuring ISIS level {level} hello-interval to {interval_sec}s on "
        f"interface {interface} on {device.name}"
    )

    level_num = _get_level_number(level)

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {level_num} timers hello-interval {interval_sec}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS level {level} hello-interval on "
            f"interface {interface} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_hello_interval(device, interface, level,
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Reset ISIS interface-level hello interval to default (10 s)."""
    log.info(
        f"Resetting ISIS level {level} hello-interval to default on "
        f"interface {interface} on {device.name}"
    )

    level_num = _get_level_number(level)

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'no level {level_num} timers hello-interval',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS level {level} hello-interval on "
            f"interface {interface} on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_level_hello_multiplier(device, interface, level,
                                                     multiplier,
                                                     network_instance='default',
                                                     protocol_instance='default'):
    """Configure ISIS interface-level hello multiplier (per-level override).

    LAN-only. Sets the hold-time multiplier for hello packets at the
    specified level: hold-time = hello-interval × multiplier.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          interface {interface} level {level_num} timers hello-multiplier {multiplier}

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): 'level_1' or 'level_2'.
        multiplier (int): Hello multiplier. Default 3.
        network_instance (str, optional): Defaults 'default'.
        protocol_instance (str, optional): Defaults 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If level is not 'level_1' or 'level_2'.

    Example:
        >>> configure_isis_interface_level_hello_multiplier(
        ...     device, 'swp1', 'level_2', 5)
    """
    log.info(
        f"Configuring ISIS level {level} hello-multiplier to {multiplier} on "
        f"interface {interface} on {device.name}"
    )

    level_num = _get_level_number(level)

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {level_num} timers hello-multiplier {multiplier}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS level {level} hello-multiplier on "
            f"interface {interface} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_hello_multiplier(device, interface, level,
                                                      network_instance='default',
                                                      protocol_instance='default'):
    """Reset ISIS interface-level hello multiplier to default (3)."""
    log.info(
        f"Resetting ISIS level {level} hello-multiplier to default on "
        f"interface {interface} on {device.name}"
    )

    level_num = _get_level_number(level)

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'no level {level_num} timers hello-multiplier',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS level {level} hello-multiplier on "
            f"interface {interface} on {device.name}. Error:\n{e}"
        )


# ============================================================================
# Batch D — Default-Information Originate (Round 2)
# ============================================================================
# Proposed and approved via:
#   orchestrator/proposals/approved/isis_api_batch_d_redistribution.md
# adoc reference: IS-IS.adoc §981-1072.
# ============================================================================


def configure_isis_default_information_originate(device, afi, enabled=None,
                                                  always=None,
                                                  export_policy=None,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Configure ISIS default-information originate per address family.

    By default, IS-IS does not originate the default route. This API
    enables per-AF default-route advertisement with three sub-knobs.

    Behavior per adoc §981-1072:
    - `enabled=True` alone   → conditional origination (default exists in
                               RIB AND was not added by this IS-IS instance).
    - `enabled=True` + `always=True`        → unconditional origination.
    - `enabled=True` + `export_policy='X'`  → policy-controlled origination
                                              (policy must `accept-route`).
    - `enabled=False`        → no origination (the other knobs become moot;
                               their lines are still emitted if specified,
                               but a log.warning notes the override).

    At least one of `enabled` / `always` / `export_policy` must be specified.

    CLI emitted:
        network-instance {ni} protocol ISIS {pi}
          global af {afi} UNICAST default-information originate enabled {bool}
          global af {afi} UNICAST default-information originate always {bool}
          global af {afi} UNICAST default-information originate export-policy {name}

    Args:
        device (obj): Device object.
        afi (str): Address family — 'IPV4' or 'IPV6'.
        enabled (bool, optional): Master enable/disable for default origination.
        always (bool, optional): Always-advertise toggle.
        export_policy (str, optional): Routing-policy name for conditional
            origination.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If no sub-knob is specified, or if `afi` is invalid.

    Examples:
        >>> # Unconditional IPv4 default
        >>> configure_isis_default_information_originate(
        ...     device, 'IPV4', enabled=True, always=True)
        >>> # Conditional IPv6 default via policy
        >>> configure_isis_default_information_originate(
        ...     device, 'IPV6', enabled=True, export_policy='def-info-origin')
    """
    if afi not in ('IPV4', 'IPV6'):
        raise ValueError(
            f"Invalid afi '{afi}'. Must be 'IPV4' or 'IPV6'."
        )

    if enabled is None and always is None and export_policy is None:
        raise ValueError(
            "At least one of enabled / always / export_policy must be specified."
        )

    if enabled is False and (always is not None or export_policy is not None):
        log.warning(
            f"default-information originate enabled=False on {device.name} "
            f"{afi} — `always` / `export_policy` settings have no effect "
            f"per adoc §1067."
        )

    parts = []
    if enabled is not None:
        parts.append(f"enabled={str(enabled).lower()}")
    if always is not None:
        parts.append(f"always={str(always).lower()}")
    if export_policy is not None:
        parts.append(f"export-policy={export_policy}")

    log.info(
        f"Configuring ISIS default-information originate ({', '.join(parts)}) "
        f"on {device.name} {afi} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [isis_context]

    if enabled is not None:
        config.append(
            f'global af {afi} UNICAST default-information originate enabled '
            f'{str(enabled).lower()}'
        )
    if always is not None:
        config.append(
            f'global af {afi} UNICAST default-information originate always '
            f'{str(always).lower()}'
        )
    if export_policy is not None:
        config.append(
            f'global af {afi} UNICAST default-information originate '
            f'export-policy {export_policy}'
        )

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS default-information originate "
            f"on {device.name} {afi}. Error:\n{e}"
        )


def unconfigure_isis_default_information_originate(device, afi,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Reset ISIS default-information originate for an AF.

    Emits `no` lines for all three sub-knobs to ensure clean removal.

    Args:
        device (obj): Device object.
        afi (str): 'IPV4' or 'IPV6'.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If `afi` is invalid.
    """
    if afi not in ('IPV4', 'IPV6'):
        raise ValueError(
            f"Invalid afi '{afi}'. Must be 'IPV4' or 'IPV6'."
        )

    log.info(
        f"Resetting ISIS default-information originate on {device.name} {afi}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global af {afi} UNICAST no default-information originate enabled',
        f'global af {afi} UNICAST no default-information originate always',
        f'global af {afi} UNICAST no default-information originate export-policy',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not reset ISIS default-information originate "
            f"on {device.name} {afi}. Error:\n{e}"
        )


# ============================================================================
# Batch E — Per-Level SR Labeled Preference
# ============================================================================
#
# Lab-validated 2026-05-22 on rtr1:
#   * Default value 114 (matches IS-IS.adoc §1198 table)
#   * Effective range 1..255. CLI silently ignores `preference 0` (state
#     unchanged) and silently caps 256+ to 255. API enforces 1..255
#     client-side and raises ValueError otherwise.
#   * Unconfigure MUST enter the level submode — the flat form
#     `network-instance ... no level <N> labeled-preference` is a silent no-op
#     on this build.
# ============================================================================


def configure_isis_level_labeled_preference(device, level, preference,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Configure ISIS per-level labeled-preference for SR LSPs.

    Sets the route-preference (administrative distance) that the RIB assigns
    to ISIS-SR-MPLS labeled paths at the specified level. arcOS default is
    114 (lower than LDP's default 20, so LDP wins by default). Lowering this
    value (e.g., to 10) makes ISIS-SR paths preferred over LDP — the typical
    LDP -> SR migration knob.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          labeled-preference {preference}
          exit

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        preference (int): Administrative distance for ISIS-SR labeled paths.
            Range 1..255 (lab-validated). arcOS default 114.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is not 'level_1' or 'level_2', or if
            ``preference`` is outside 1..255.

    Example:
        >>> # Make ISIS-SR L2 paths preferred over LDP (force migration)
        >>> configure_isis_level_labeled_preference(
        ...     device, level='level_2', preference=10)
    """
    lvl = _level_number(level)

    if not isinstance(preference, int) or isinstance(preference, bool):
        raise ValueError(
            f"Invalid preference '{preference}'. Must be an integer 1..255."
        )
    if preference < 1 or preference > 255:
        raise ValueError(
            f"Invalid preference '{preference}'. Must be in range 1..255. "
            f"Note: arcOS CLI silently ignores `labeled-preference 0` (no "
            f"state change) and silently caps values >255 (e.g., 256 becomes "
            f"255), so this API enforces the range client-side."
        )

    log.info(
        f"Configuring ISIS labeled-preference {preference} level {lvl} on "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        f'labeled-preference {preference}',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS labeled-preference {preference} "
            f"level {lvl} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_level_labeled_preference(device, level,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Reset ISIS per-level labeled-preference to default (114).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          no labeled-preference
          exit

    Note: The level-submode form is required. The flat form
    ``no level <N> labeled-preference`` is silently accepted by commit but
    does not remove the configuration on this arcOS build (verified
    2026-05-22).

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is not 'level_1' or 'level_2'.

    Example:
        >>> unconfigure_isis_level_labeled_preference(device, level='level_2')
    """
    lvl = _level_number(level)

    log.info(
        f"Removing ISIS labeled-preference level {lvl} from {device.name} "
        f"(network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'no labeled-preference',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS labeled-preference level {lvl} from "
            f"{device.name}. Error:\n{e}"
        )


# ============================================================================
# Batch C — Attached-bit (global) + DIS priority (per-level interface)
# ============================================================================
#
# Source gaps:
#   * KNOB §13 (LSP Bit / Overload): attached-bit ignore-bit + suppress-bit
#   * COVERAGE_GAPS #10: per-level interface priority (DIS election)
#
# Lab-validated 2026-05-22 on rtr1:
#   * attached-bit unconfigure MUST use prefix-`no` form
#     (`no global lsp-bit attached-bit <subkey>`). The inline form
#     `global lsp-bit attached-bit no <subkey>` is silently accepted by commit
#     but does NOT remove the config on this build.
#   * interface level priority: configure+unconfigure work with the standard
#     level-submode form. CLI rejects 128 explicitly (good — config-mode error
#     visible to caller), but silently caps 200 to 127 (cap-at-127 then no-op).
#     The API enforces 0..127 client-side to be safe.
# ============================================================================


def configure_isis_attached_bit_ignore(device, enabled=True,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure ISIS attached-bit ignore behaviour (global).

    When enabled (True), an L1-only router IGNORES the attached-bit set by
    L1/L2 routers in their L1 LSPs — i.e., does not install a default route
    via the nearest L1/L2 router from the attached-bit. Default arcOS value
    is false (honor the bit, install default route).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         global lsp-bit attached-bit ignore-bit {true|false}
         !

    Args:
        device (obj): Device object.
        enabled (bool, optional): True to ignore the attached-bit, False to
            honor it. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        TypeError: If ``enabled`` is not a bool.

    Example:
        >>> configure_isis_attached_bit_ignore(device, enabled=True)
    """
    if not isinstance(enabled, bool):
        raise TypeError(
            f"enabled must be a bool, got {type(enabled).__name__}: {enabled!r}"
        )

    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring ISIS attached-bit ignore-bit {val} on {device.name} "
        f"(network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global lsp-bit attached-bit ignore-bit {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS attached-bit ignore-bit {val} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_attached_bit_ignore(device,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Reset ISIS attached-bit ignore-bit to default (false).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         no global lsp-bit attached-bit ignore-bit
         !

    Lab-validated 2026-05-22: this prefix-`no` form is required. The
    inline form ``global lsp-bit attached-bit no ignore-bit`` is silently
    accepted by commit but does NOT remove the configuration on this
    arcOS build.

    Args:
        device (obj): Device object.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.

    Example:
        >>> unconfigure_isis_attached_bit_ignore(device)
    """
    log.info(
        f"Removing ISIS attached-bit ignore-bit from {device.name} "
        f"(network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global lsp-bit attached-bit ignore-bit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS attached-bit ignore-bit from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_attached_bit_suppress(device, enabled=True,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Configure ISIS attached-bit suppress behaviour (global).

    When enabled (True), an L1/L2 router SUPPRESSES (does not set) the
    attached-bit in its own L1 LSP fragment zero. Default arcOS value is
    false (set the bit when this router has L2 connectivity).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         global lsp-bit attached-bit suppress-bit {true|false}
         !

    Args:
        device (obj): Device object.
        enabled (bool, optional): True to suppress the bit, False to set it
            normally. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        TypeError: If ``enabled`` is not a bool.

    Example:
        >>> configure_isis_attached_bit_suppress(device, enabled=True)
    """
    if not isinstance(enabled, bool):
        raise TypeError(
            f"enabled must be a bool, got {type(enabled).__name__}: {enabled!r}"
        )

    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring ISIS attached-bit suppress-bit {val} on {device.name} "
        f"(network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global lsp-bit attached-bit suppress-bit {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS attached-bit suppress-bit {val} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_attached_bit_suppress(device,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Reset ISIS attached-bit suppress-bit to default (false).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         no global lsp-bit attached-bit suppress-bit
         !

    Lab-validated 2026-05-22: this prefix-`no` form is required. The
    inline form ``global lsp-bit attached-bit no suppress-bit`` is silently
    accepted by commit but does NOT remove the configuration on this
    arcOS build.

    Args:
        device (obj): Device object.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.

    Example:
        >>> unconfigure_isis_attached_bit_suppress(device)
    """
    log.info(
        f"Removing ISIS attached-bit suppress-bit from {device.name} "
        f"(network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global lsp-bit attached-bit suppress-bit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS attached-bit suppress-bit from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_level_priority(device, interface, level, priority,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Configure ISIS interface per-level DIS-election priority.

    Sets the priority used in DIS (Designated Intermediate System) election
    on broadcast/LAN interfaces. Higher priority wins; tie-broken by MAC.
    arcOS default is 63. Range 0..127. Has no effect on P2P interfaces.

    CLI emitted (level-submode form)::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {level_num}
           priority {priority}
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp1', 'ethernet-1/1').
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        priority (int): DIS-election priority. Range 0..127. Default 63.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is not 'level_1' or 'level_2', or if
            ``priority`` is outside 0..127.

    Example:
        >>> configure_isis_interface_level_priority(
        ...     device, interface='swp1', level='level_1', priority=100)
    """
    lvl = _get_level_number(level)

    if not isinstance(priority, int) or isinstance(priority, bool):
        raise ValueError(
            f"Invalid priority '{priority}'. Must be an integer 0..127."
        )
    if priority < 0 or priority > 127:
        raise ValueError(
            f"Invalid priority '{priority}'. Must be in range 0..127."
        )

    log.info(
        f"Configuring ISIS interface {interface} level {lvl} priority "
        f"{priority} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        f'priority {priority}',
        'exit',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS interface {interface} level {lvl} "
            f"priority {priority} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_priority(device, interface, level,
                                              network_instance='default',
                                              protocol_instance='default'):
    """Reset ISIS interface per-level DIS-election priority to default (63).

    CLI emitted (level-submode form)::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {level_num}
           no priority
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Network instance name. Defaults to
            'default'.
        protocol_instance (str, optional): ISIS protocol instance name.
            Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is not 'level_1' or 'level_2'.

    Example:
        >>> unconfigure_isis_interface_level_priority(
        ...     device, interface='swp1', level='level_1')
    """
    lvl = _get_level_number(level)

    log.info(
        f"Removing ISIS interface {interface} level {lvl} priority from "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        'no priority',
        'exit',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS interface {interface} level {lvl} "
            f"priority from {device.name}. Error:\n{e}"
        )


# ============================================================================
# Batch A — Level + Interface-Level (LAN Hello) Authentication
# ============================================================================
#
# Source gaps:
#   * KNOB §5  (Level container auth): keychain / simple-key / password
#   * KNOB §7  (Interface-level LAN hello auth): keychain / simple-key /
#              password / master toggle
#
# Pattern: mirrors existing P2P interface auth APIs
# (configure_isis_interface_auth_*). All use the level-submode form per
# Batch E lesson; unconfigure paths will be lab-validated and adjusted.
#
# Adoc references:
#   * Level container auth: IS-IS.adoc L1262-L1322
#   * Interface-level LAN hello auth: IS-IS.adoc L2011-L2127
# ============================================================================


# ----- Group 1: Level container auth (3 functions, 6 APIs) -----------------


def configure_isis_level_auth_keychain(device, level, keychain_name,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure ISIS level-container keychain (RFC5310) authentication.

    Sets the auth-type to KEYCHAIN and binds a keychain at level scope. The
    auth material is consumed by LSP / CSNP / PSNP PDU authentication
    toggles (configure_isis_lsp_authentication, _csnp_authentication,
    _psnp_authentication).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          authentication auth-type KEYCHAIN
          authentication keychain {keychain_name}
          exit
         !

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        keychain_name (str): Name of an already-defined keychain on the device.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is not 'level_1' or 'level_2'.

    Example:
        >>> configure_isis_level_auth_keychain(
        ...     device, level='level_2', keychain_name='mykeychain1')
    """
    lvl = _get_level_number(level)
    log.info(
        f"Configuring ISIS level {lvl} keychain auth ({keychain_name}) "
        f"on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'authentication auth-type KEYCHAIN',
        f'authentication keychain {keychain_name}',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS level {lvl} keychain auth on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_level_auth_keychain(device, level,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove ISIS level-container keychain authentication.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          no authentication keychain
          no authentication auth-type
          exit
         !

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Removing ISIS level {lvl} keychain auth from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'no authentication keychain',
        'no authentication auth-type',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS level {lvl} keychain auth from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_level_auth_simple_key(device, level, password,
                                          crypto_algorithm='MD5',
                                          network_instance='default',
                                          protocol_instance='default'):
    """Configure ISIS level-container simple-key (RFC5304) authentication.

    Bundles ``auth-type SIMPLE_KEY`` + ``key crypto-algorithm MD5`` + the
    password. Only MD5 is supported by arcOS for SIMPLE_KEY mode.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          authentication auth-type SIMPLE_KEY
          authentication key crypto-algorithm MD5
          authentication key auth-password {password}
          exit
         !

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        password (str): Authentication password. arcOS will AES-encrypt this
            in running-config output.
        crypto_algorithm (str, optional): Cryptographic algorithm. Only
            'MD5' is supported. Defaults to 'MD5'.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is invalid or ``crypto_algorithm`` is not 'MD5'.

    Example:
        >>> configure_isis_level_auth_simple_key(
        ...     device, level='level_1', password='MyLvl1Passwd')
    """
    if crypto_algorithm != 'MD5':
        raise ValueError(
            f"Invalid crypto_algorithm '{crypto_algorithm}'. Only 'MD5' is "
            f"supported for SIMPLE_KEY mode."
        )
    lvl = _get_level_number(level)
    log.info(
        f"Configuring ISIS level {lvl} simple-key auth ({crypto_algorithm}) "
        f"on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'authentication auth-type SIMPLE_KEY',
        f'authentication key crypto-algorithm {crypto_algorithm}',
        f'authentication key auth-password {password}',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS level {lvl} simple-key auth on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_level_auth_simple_key(device, level,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Remove ISIS level-container simple-key authentication.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          no authentication key
          no authentication auth-type
          exit
         !

    The ``no authentication key`` form is documented at adoc L1322 and
    removes the whole key block (crypto-algorithm + auth-password).

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Removing ISIS level {lvl} simple-key auth from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'no authentication key',
        'no authentication auth-type',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS level {lvl} simple-key auth from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_level_auth_password(device, level, password,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Update the authentication password at ISIS level scope (key block).

    Use this when the auth-type and crypto-algorithm are already set (via
    configure_isis_level_auth_simple_key) and only the password needs to
    change. Does NOT alter auth-type or crypto-algorithm.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          authentication key auth-password {password}
          exit
         !

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        password (str): New authentication password.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Updating ISIS level {lvl} auth password on {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        f'authentication key auth-password {password}',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not update ISIS level {lvl} auth password on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_level_auth_password(device, level,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove only the auth-password at ISIS level scope (preserves crypto-algorithm).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         level {N}
          no authentication key auth-password
          exit
         !

    Args:
        device (obj): Device object.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Removing ISIS level {lvl} auth password from {device.name}"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'level {lvl}',
        'no authentication key auth-password',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS level {lvl} auth password from "
            f"{device.name}. Error:\n{e}"
        )


# ----- Group 2: Interface-level (LAN hello) auth (4 functions, 8 APIs) ----


def configure_isis_interface_level_hello_authentication(device, interface, level,
                                                        enabled=True,
                                                        network_instance='default',
                                                        protocol_instance='default'):
    """Enable or disable per-interface per-level LAN hello authentication.

    Master toggle for LAN/broadcast hello-PDU authentication on a specific
    interface at a specific level. Auth material must be configured
    separately via configure_isis_interface_level_hello_auth_keychain or
    _simple_key. LAN-only (broadcast network-type).

    CLI emitted (note: ``hello-authentication hello-authentication`` is the
    actual CLI; the inner word is the leaf, the outer is the container per
    YANG augment — see adoc L2118)::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           hello-authentication hello-authentication {true|false}
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name (LAN/broadcast).
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        enabled (bool, optional): True to enable, False to disable. Defaults
            to True.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is invalid.
        TypeError: If ``enabled`` is not a bool.

    Example:
        >>> configure_isis_interface_level_hello_authentication(
        ...     device, interface='swp1', level='level_1', enabled=True)
    """
    if not isinstance(enabled, bool):
        raise TypeError(
            f"enabled must be a bool, got {type(enabled).__name__}: {enabled!r}"
        )
    lvl = _get_level_number(level)
    val = 'true' if enabled else 'false'
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS LAN hello-auth on "
        f"interface {interface} level {lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        f'hello-authentication hello-authentication {val}',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS LAN hello-auth on interface "
            f"{interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_hello_authentication(device, interface, level,
                                                          network_instance='default',
                                                          protocol_instance='default'):
    """Disable per-interface per-level LAN hello authentication (master toggle).

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           no hello-authentication hello-authentication
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Removing ISIS LAN hello-auth from interface {interface} level "
        f"{lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        'no hello-authentication hello-authentication',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS LAN hello-auth from interface "
            f"{interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_level_hello_auth_keychain(device, interface, level,
                                                       keychain_name,
                                                       network_instance='default',
                                                       protocol_instance='default'):
    """Configure RFC5310 keychain auth material for LAN hello at interface-level scope.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           hello-authentication auth-type KEYCHAIN
           hello-authentication keychain {keychain_name}
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name (LAN/broadcast).
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        keychain_name (str): Name of an already-defined keychain.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Configuring ISIS LAN hello-auth keychain ({keychain_name}) on "
        f"interface {interface} level {lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        'hello-authentication auth-type KEYCHAIN',
        f'hello-authentication keychain {keychain_name}',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS LAN hello-auth keychain on interface "
            f"{interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_hello_auth_keychain(device, interface, level,
                                                         network_instance='default',
                                                         protocol_instance='default'):
    """Remove LAN hello keychain auth material at interface-level scope.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           no hello-authentication keychain
           no hello-authentication auth-type
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Removing ISIS LAN hello-auth keychain from interface {interface} "
        f"level {lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        'no hello-authentication keychain',
        'no hello-authentication auth-type',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS LAN hello-auth keychain from interface "
            f"{interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_level_hello_auth_simple_key(device, interface, level,
                                                          password,
                                                          crypto_algorithm='MD5',
                                                          network_instance='default',
                                                          protocol_instance='default'):
    """Configure RFC5304 simple-key auth material for LAN hello at interface-level scope.

    Bundles ``auth-type SIMPLE_KEY`` + ``key crypto-algorithm MD5`` + the
    password. Only MD5 is supported for SIMPLE_KEY mode.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           hello-authentication auth-type SIMPLE_KEY
           hello-authentication key crypto-algorithm MD5
           hello-authentication key auth-password {password}
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name (LAN/broadcast).
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        password (str): Authentication password. arcOS will AES-encrypt in
            running-config output.
        crypto_algorithm (str, optional): Only 'MD5' supported. Defaults to 'MD5'.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is invalid or ``crypto_algorithm`` is not 'MD5'.
    """
    if crypto_algorithm != 'MD5':
        raise ValueError(
            f"Invalid crypto_algorithm '{crypto_algorithm}'. Only 'MD5' is "
            f"supported for SIMPLE_KEY mode."
        )
    lvl = _get_level_number(level)
    log.info(
        f"Configuring ISIS LAN hello-auth simple-key ({crypto_algorithm}) "
        f"on interface {interface} level {lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        'hello-authentication auth-type SIMPLE_KEY',
        f'hello-authentication key crypto-algorithm {crypto_algorithm}',
        f'hello-authentication key auth-password {password}',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS LAN hello-auth simple-key on "
            f"interface {interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_hello_auth_simple_key(device, interface, level,
                                                            network_instance='default',
                                                            protocol_instance='default'):
    """Remove LAN hello simple-key auth material at interface-level scope.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           no hello-authentication key
           no hello-authentication auth-type
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Removing ISIS LAN hello-auth simple-key from interface {interface} "
        f"level {lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        'no hello-authentication key',
        'no hello-authentication auth-type',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS LAN hello-auth simple-key from interface "
            f"{interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_level_hello_auth_password(device, interface, level,
                                                        password,
                                                        network_instance='default',
                                                        protocol_instance='default'):
    """Update the LAN hello auth-password at interface-level scope.

    Use this when auth-type and crypto-algorithm are already configured
    (via configure_isis_interface_level_hello_auth_simple_key) and only
    the password needs to change. Does NOT alter auth-type or
    crypto-algorithm.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           hello-authentication key auth-password {password}
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        password (str): New authentication password.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Updating ISIS LAN hello-auth password on interface {interface} "
        f"level {lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        f'hello-authentication key auth-password {password}',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not update ISIS LAN hello-auth password on interface "
            f"{interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_hello_auth_password(device, interface, level,
                                                          network_instance='default',
                                                          protocol_instance='default'):
    """Remove the LAN hello auth-password at interface-level scope.

    Preserves auth-type and crypto-algorithm.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
         interface {interface}
          level {N}
           no hello-authentication key auth-password
           exit
          exit
         !

    Args:
        device (obj): Device object.
        interface (str): Interface name.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Defaults to 'default'.
        protocol_instance (str, optional): Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: If unconfigure fails.
        ValueError: If ``level`` is invalid.
    """
    lvl = _get_level_number(level)
    log.info(
        f"Removing ISIS LAN hello-auth password from interface {interface} "
        f"level {lvl} on {device.name}"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl}',
        'no hello-authentication key auth-password',
        'exit',
        'exit',
        '!'
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS LAN hello-auth password from interface "
            f"{interface} level {lvl} on {device.name}. Error:\n{e}"
        )


def _get_global_af_name(af):
    """Map an address-family string to the ArcOS global AF submode name.

    Args:
        af (str): Address family — ``'ipv4'`` or ``'ipv6'`` (case-insensitive).

    Returns:
        str: ArcOS AF submode name, ``'IPV4 UNICAST'`` or ``'IPV6 UNICAST'``.

    Raises:
        ValueError: If ``af`` is not 'ipv4' or 'ipv6'.
    """
    af_lower = af.lower()
    if af_lower == 'ipv4':
        return 'IPV4 UNICAST'
    if af_lower == 'ipv6':
        return 'IPV6 UNICAST'
    raise ValueError(
        f"Invalid address family '{af}'. Expected 'ipv4' or 'ipv6'."
    )


def configure_isis_address_family(device, af, enabled=True, network_instance='default',
                                  protocol_instance='default'):
    """Enable or disable an ISIS global (instance-level) address family.

    Emits the instance-level AF toggle matching the conf object's rendering:
    a ``global af <AF> UNICAST`` submode followed by ``enabled true|false``.
    Use ``enabled=False`` for the global AF disable and ``enabled=True`` to
    restore it.

    Args:
        device (obj): Device object.
        af (str): Address family — ``'ipv4'`` or ``'ipv6'`` (case-insensitive).
        enabled (bool, optional): AF enabled state. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the ISIS global address family.
        ValueError: If ``af`` is invalid.

    Example:
        >>> configure_isis_address_family(
        ...     device=device,
        ...     af='ipv6',
        ...     enabled=False,
        ...     protocol_instance='isis1'
        ... )
    """
    af_name = _get_global_af_name(af)
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS global address family "
        f"{af_name} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global af {af_name}',
        f'enabled {"true" if enabled else "false"}',
        'exit',  # Exit global AF submode
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not {'enable' if enabled else 'disable'} ISIS global address "
            f"family {af_name} on {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


def unconfigure_isis_address_family(device, af, network_instance='default',
                                    protocol_instance='default'):
    """Remove an ISIS global (instance-level) address family submode.

    Emits ``no global af <AF> UNICAST`` to remove the AF submode entirely.

    Args:
        device (obj): Device object.
        af (str): Address family — ``'ipv4'`` or ``'ipv6'`` (case-insensitive).
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the ISIS global address family.
        ValueError: If ``af`` is invalid.

    Example:
        >>> unconfigure_isis_address_family(
        ...     device=device,
        ...     af='ipv4',
        ...     protocol_instance='isis1'
        ... )
    """
    af_name = _get_global_af_name(af)
    log.info(
        f"Removing ISIS global address family {af_name} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'no global af {af_name}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS global address family {af_name} on {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


def configure_isis_srv6(device, enabled=True, network_instance='default',
                        protocol_instance='default'):
    """Enable or disable ISIS SRv6 globally on the protocol instance.

    Emits ``global srv6 enabled true|false`` under the ISIS instance
    submode. Use ``enabled=False`` to disable SRv6 and ``enabled=True``
    to (re)enable it.

    Args:
        device (obj): Device object.
        enabled (bool, optional): SRv6 enabled state. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure ISIS SRv6.

    Example:
        >>> configure_isis_srv6(
        ...     device=device,
        ...     enabled=True,
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS SRv6 on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global srv6 enabled {"true" if enabled else "false"}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not {'enable' if enabled else 'disable'} ISIS SRv6 on {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


def unconfigure_isis_srv6(device, network_instance='default',
                          protocol_instance='default'):
    """Disable ISIS SRv6 globally on the protocol instance (reset to default).

    Emits ``no global srv6 enabled`` under the ISIS instance submode.

    Args:
        device (obj): Device object.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to disable ISIS SRv6.

    Example:
        >>> unconfigure_isis_srv6(
        ...     device=device,
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Disabling ISIS SRv6 on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global srv6 enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not disable ISIS SRv6 on {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


def configure_isis_srv6_locator(device, locator, network_instance='default',
                                protocol_instance='default'):
    """Bind an SRv6 locator to the ISIS protocol instance.

    Emits ``global srv6 locator <locator>`` under the ISIS instance
    submode.

    Args:
        device (obj): Device object.
        locator (str): SRv6 locator name to bind.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the ISIS SRv6 locator.

    Example:
        >>> configure_isis_srv6_locator(
        ...     device=device,
        ...     locator='LOC_R1_ALG128',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Binding ISIS SRv6 locator {locator} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global srv6 locator {locator}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not bind ISIS SRv6 locator {locator} on {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


def unconfigure_isis_srv6_locator(device, locator, network_instance='default',
                                  protocol_instance='default'):
    """Remove an SRv6 locator binding from the ISIS protocol instance.

    Emits ``no global srv6 locator <locator>`` under the ISIS instance
    submode.

    Args:
        device (obj): Device object.
        locator (str): SRv6 locator name to unbind.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the ISIS SRv6 locator.

    Example:
        >>> unconfigure_isis_srv6_locator(
        ...     device=device,
        ...     locator='LOC_R1_ALG128',
        ...     protocol_instance='isis1'
        ... )
    """
    log.info(
        f"Removing ISIS SRv6 locator {locator} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'no global srv6 locator {locator}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS SRv6 locator {locator} on {device.name} "
            f"(network-instance: {network_instance}, protocol-instance: {protocol_instance}). "
            f"Error:\n{e}"
        )


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-04 — config-coverage audit
# (arcos_pyats_sanity/docs/config-coverage/01-isis-sr-srv6.md)
#
# Every CLI line below traces to Command_Line_Interface/IS-IS.adoc; the cited
# line number is in each function's docstring.
#
# Lab-verified 2026-08-17 on rtr1 (arcOS docker, 10.27.168.246:10001): every
# configure AND unconfigure path below was applied, committed, and confirmed by
# running-config read-back in both directions.
#
# NOT implemented here: the audit also listed `default-metric` at the
# protocol-instance level (IS-IS.adoc:87). That leaf does not exist on this
# arcOS build — `default-metric ?` returns "% Invalid input detected" and the
# ISIS context offers only `global`, `interface`, `level`. An API for it would
# emit a command the device rejects, so it is deliberately absent.
# ---------------------------------------------------------------------------


def configure_isis_timers_fast_reroute_interval(device, interval,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure the ISIS FRR/TI-LFA start interval.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          global timers fast-reroute-interval {interval}

    adoc: IS-IS.adoc:637 — ``(config-protocol-ISIS/p1)# global timers ?`` lists
    ``fast-reroute-interval   FRR/TI-LFA start interval``.

    Units confirmed on-device (rtr1, 2026-08-17) — the CLI help reads: "The
    delay (in **milliseconds**) before FRR/TI-LFA calculation starts", default
    **500**. The adoc does not state the unit or the default.

    Args:
        device (obj): Device object
        interval (int): FRR/TI-LFA start delay in milliseconds. Device default
            is 500.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure the fast-reroute interval

    Example:
        >>> configure_isis_timers_fast_reroute_interval(device, interval=100)
    """
    log.info(
        f"Configuring ISIS global timers fast-reroute-interval {interval} on "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global timers fast-reroute-interval {interval}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS global timers fast-reroute-interval "
            f"{interval} on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_timers_fast_reroute_interval(device, network_instance='default',
                                                  protocol_instance='default'):
    """Remove the ISIS FRR/TI-LFA start interval configuration.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          no global timers fast-reroute-interval

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove the fast-reroute interval

    Example:
        >>> unconfigure_isis_timers_fast_reroute_interval(device)
    """
    log.info(
        f"Removing ISIS global timers fast-reroute-interval from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global timers fast-reroute-interval',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS global timers fast-reroute-interval from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_graceful_restart_helper_only(device, enabled=True,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Enable or disable the ISIS graceful-restart helper function.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          global graceful-restart helper-only {true|false}

    adoc: IS-IS.adoc:781, 788 — ``helper-only`` is a sibling leaf of ``enabled``
    under ``global graceful-restart``: "the local IS-IS router will be in
    graceful restart helper mode if the remote IS-IS router restarts; but
    forwarding state will not be preserved if restart occurs locally."

    This is a separate function from :func:`configure_isis_graceful_restart`,
    which sets the sibling ``enabled`` leaf. The two are independently settable.

    Args:
        device (obj): Device object
        enabled (bool, optional): Enable or disable helper-only mode. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure graceful-restart helper-only

    Example:
        >>> configure_isis_graceful_restart_helper_only(device, enabled=True)
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS graceful-restart helper-only "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        f'global graceful-restart helper-only {str(enabled).lower()}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS graceful-restart helper-only on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_graceful_restart_helper_only(device, network_instance='default',
                                                  protocol_instance='default'):
    """Remove the ISIS graceful-restart helper-only configuration.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi}
          no global graceful-restart helper-only

    Args:
        device (obj): Device object
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove graceful-restart helper-only

    Example:
        >>> unconfigure_isis_graceful_restart_helper_only(device)
    """
    log.info(
        f"Removing ISIS graceful-restart helper-only from {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    isis_context = _build_isis_config_context(network_instance, protocol_instance)
    config = [
        isis_context,
        'no global graceful-restart helper-only',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS graceful-restart helper-only from "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_mpls_ldp_sync(device, interface, enabled=True,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Enable or disable ISIS MPLS LDP synchronization on a single interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          mpls igp-ldp-sync enabled {true|false}

    adoc: IS-IS.adoc:809 — ``(config-interface-swp54)# mpls igp-ldp-sync ?``.
    Per the adoc, per-interface configuration matters only when global LDP sync
    is NOT enabled: with global sync on, every ISIS interface participates
    regardless of its own setting.

    Not to be confused with :func:`configure_isis_mpls_ldp_sync`, which sets the
    instance-wide ``global mpls igp-ldp-sync enabled`` leaf.

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g. 'swp1', 'ethernet-1/1').
        enabled (bool, optional): Enable or disable LDP sync on the interface.
            Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure interface LDP sync

    Example:
        >>> configure_isis_interface_mpls_ldp_sync(device, interface='swp1', enabled=True)
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS MPLS igp-ldp-sync on "
        f"interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'mpls igp-ldp-sync enabled {str(enabled).lower()}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS MPLS igp-ldp-sync on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_mpls_ldp_sync(device, interface,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove per-interface ISIS MPLS LDP synchronization configuration.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          no mpls igp-ldp-sync

    Args:
        device (obj): Device object
        interface (str): Interface name.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove interface LDP sync

    Example:
        >>> unconfigure_isis_interface_mpls_ldp_sync(device, interface='swp1')
    """
    log.info(
        f"Removing ISIS MPLS igp-ldp-sync from interface {interface} on "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no mpls igp-ldp-sync',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS MPLS igp-ldp-sync from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_isis_interface_ipv4_fast_reroute_ip(device, interface, enabled=True,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Enable or disable IPv4 IP fast-reroute (IP-FRR, RFC 5286) on an interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          af IPV4 UNICAST
            fast-reroute ip enabled {true|false}

    adoc: IS-IS.adoc:1499-1512 — "IP fast reroute (IP-FRR), as described in
    RFC 5286 may be enabled for an interface under address family
    configuration." The worked example is ``(config-interface-swp2)# af IPV6
    UNICAST`` then ``fast-reroute ip enabled true``.

    Distinct from :func:`configure_isis_interface_ipv4_ti_lfa_sr_mpls`, which
    sets ``fast-reroute ti-lfa sr-mpls enabled`` in the same submode.

    Note:
        Entering ``af <AF> UNICAST`` creates the AF container but does NOT
        enable it — verified on rtr1 2026-08-18: after this call the interface
        shows ``af IPV4 UNICAST`` with only ``fast-reroute ip enabled true``
        under it, and no ``enabled`` leaf. IS-IS.adoc:1495 notes that an
        address family which is not explicitly enabled under an interface is
        not active for that interface, so enable the AF separately (e.g.
        :func:`configure_isis_interface_ipv4`) for IP-FRR to take effect.

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g. 'swp1', 'ethernet-1/1').
        enabled (bool, optional): Enable or disable IPv4 IP-FRR. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure IPv4 IP-FRR

    Example:
        >>> configure_isis_interface_ipv4_fast_reroute_ip(
        ...     device, interface='swp2', enabled=True)
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} IPv4 IP-FRR on interface "
        f"{interface} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        f'fast-reroute ip enabled {str(enabled).lower()}',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv4 IP-FRR on interface {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv4_fast_reroute_ip(device, interface,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Remove IPv4 IP fast-reroute configuration from an interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          af IPV4 UNICAST
            no fast-reroute ip

    Args:
        device (obj): Device object
        interface (str): Interface name.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove IPv4 IP-FRR

    Example:
        >>> unconfigure_isis_interface_ipv4_fast_reroute_ip(device, interface='swp2')
    """
    log.info(
        f"Removing IPv4 IP-FRR from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV4 UNICAST',
        'no fast-reroute ip',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv4 IP-FRR from interface {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_ipv6_fast_reroute_ip(device, interface, enabled=True,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Enable or disable IPv6 IP fast-reroute (IP-FRR, RFC 5286) on an interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          af IPV6 UNICAST
            fast-reroute ip enabled {true|false}

    adoc: IS-IS.adoc:1505 — ``(config-af-IPV6/UNICAST)# fast-reroute ip enabled true``.

    Note:
        Entering ``af <AF> UNICAST`` creates the AF container but does NOT
        enable it — verified on rtr1 2026-08-18: after this call the interface
        shows ``af IPV4 UNICAST`` with only ``fast-reroute ip enabled true``
        under it, and no ``enabled`` leaf. IS-IS.adoc:1495 notes that an
        address family which is not explicitly enabled under an interface is
        not active for that interface, so enable the AF separately (e.g.
        :func:`configure_isis_interface_ipv4`) for IP-FRR to take effect.

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g. 'swp1', 'ethernet-1/1').
        enabled (bool, optional): Enable or disable IPv6 IP-FRR. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure IPv6 IP-FRR

    Example:
        >>> configure_isis_interface_ipv6_fast_reroute_ip(
        ...     device, interface='swp2', enabled=True)
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} IPv6 IP-FRR on interface "
        f"{interface} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        f'fast-reroute ip enabled {str(enabled).lower()}',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure IPv6 IP-FRR on interface {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_ipv6_fast_reroute_ip(device, interface,
                                                    network_instance='default',
                                                    protocol_instance='default'):
    """Remove IPv6 IP fast-reroute configuration from an interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          af IPV6 UNICAST
            no fast-reroute ip

    Args:
        device (obj): Device object
        interface (str): Interface name.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove IPv6 IP-FRR

    Example:
        >>> unconfigure_isis_interface_ipv6_fast_reroute_ip(device, interface='swp2')
    """
    log.info(
        f"Removing IPv6 IP-FRR from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'af IPV6 UNICAST',
        'no fast-reroute ip',
        'exit',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove IPv6 IP-FRR from interface {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_csnp_enabled(device, interface, enabled=True,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Enable or disable CSNP transmission on an ISIS interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          csnp enabled {true|false}

    adoc: IS-IS.adoc:1783-1789 — ``(config-interface-swp1)# csnp ?`` gives
    ``enabled   When set to false, CSNPs will not be sent out via this
    interface``, and "By default CSNP is enabled on all interfaces." The
    meaningful call is therefore ``enabled=False``.

    Distinct from :func:`configure_isis_csnp_authentication` (level-scoped
    ``authentication csnp-authentication``) and
    :func:`configure_isis_interface_csnp_interval` (``timers csnp-interval``).

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g. 'swp1', 'ethernet-1/1').
        enabled (bool, optional): Send CSNPs on this interface. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure interface CSNP enable

    Example:
        >>> configure_isis_interface_csnp_enabled(device, interface='swp1', enabled=False)
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} CSNP transmission on interface "
        f"{interface} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'csnp enabled {str(enabled).lower()}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure CSNP enable on interface {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_csnp_enabled(device, interface,
                                            network_instance='default',
                                            protocol_instance='default'):
    """Remove the per-interface CSNP enable configuration.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          no csnp enabled

    Note:
        CSNP is enabled by default on all interfaces, so removing this leaf
        restores CSNP transmission — absence of the leaf is NOT equivalent to
        ``enabled false``.

    Args:
        device (obj): Device object
        interface (str): Interface name.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove interface CSNP enable

    Example:
        >>> unconfigure_isis_interface_csnp_enabled(device, interface='swp1')
    """
    log.info(
        f"Removing CSNP enable from interface {interface} on {device.name} "
        f"(network-instance: {network_instance}, protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        'no csnp enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove CSNP enable from interface {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def configure_isis_interface_level_enabled(device, interface, level, enabled=True,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Enable or disable a specific ISIS level on an interface.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          level {level_num} enabled {true|false}

    adoc: IS-IS.adoc:575, 612 — ``(config-interface-loopback0)# level 2 enabled true``.

    Emitted as ONE line rather than entering the ``level`` submode (which is how
    :func:`configure_isis_interface_level_priority` and its siblings do it). The
    deviation is deliberate and is about blast radius, not style: in the submode
    form the unconfigure pair sends a bare ``no enabled``, and if the ``level``
    line were ever accepted-and-ignored — a documented arcOS failure mode — that
    ``no enabled`` would land at INTERFACE scope and shut ISIS off the whole
    interface, dropping the adjacency. The single-line form has no such window.
    Both directions lab-verified on rtr1 2026-08-17.

    Distinct from :func:`configure_isis_interface_enabled`, which sets the
    interface-scoped ``enabled`` leaf across all levels.

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g. 'swp1', 'loopback0').
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        enabled (bool, optional): Enable or disable the level. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``level`` is not 'level_1' or 'level_2'
        SubCommandFailure: Failed to configure the interface level enable

    Example:
        >>> configure_isis_interface_level_enabled(
        ...     device, interface='loopback0', level='level_2', enabled=True)
    """
    lvl = _get_level_number(level)

    log.info(
        f"{'Enabling' if enabled else 'Disabling'} ISIS level {lvl} on interface "
        f"{interface} on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'level {lvl} enabled {str(enabled).lower()}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure ISIS level {lvl} enable on interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_isis_interface_level_enabled(device, interface, level,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove the per-interface per-level enable configuration.

    CLI emitted::

        network-instance {ni} protocol ISIS {pi} interface {interface}
          no level {level_num} enabled

    Note:
        Confirmed on-device (rtr1, 2026-08-17): this removes the ``enabled``
        leaf but leaves an EMPTY ``level {level_num}`` container in the running
        config. Assert on the absence of the ``enabled`` leaf, not on the
        absence of the ``level`` block. The interface-scoped ``enabled`` leaf is
        left untouched — verified explicitly, since the submode spelling of this
        command could disable ISIS on the whole interface. See the configure
        counterpart for why this is one line.

    Args:
        device (obj): Device object
        interface (str): Interface name.
        level (str): ISIS level — ``'level_1'`` or ``'level_2'``.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.

    Returns:
        None

    Raises:
        ValueError: If ``level`` is not 'level_1' or 'level_2'
        SubCommandFailure: Failed to remove the interface level enable

    Example:
        >>> unconfigure_isis_interface_level_enabled(
        ...     device, interface='loopback0', level='level_2')
    """
    lvl = _get_level_number(level)

    log.info(
        f"Removing ISIS level {lvl} enable from interface {interface} on "
        f"{device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )

    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'no level {lvl} enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove ISIS level {lvl} enable from interface {interface} "
            f"on {device.name}. Error:\n{e}"
        )
