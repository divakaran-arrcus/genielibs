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
                                  second_interval=None, network_instance='default',
                                  protocol_instance='default'):
    """Configure SPF timer intervals (first, hold, second).
    
    Configures one or more SPF timer intervals atomically. All three timers control
    SPF calculation behavior and convergence speed.
    
    Args:
        device (obj): Device object
        first_interval (int, optional): SPF first interval in milliseconds (initial delay)
        hold_interval (int, optional): SPF hold interval in milliseconds (backoff interval)
        second_interval (int, optional): SPF second interval in milliseconds (max wait)
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure SPF intervals
        ValueError: If no intervals are provided
    
    Example:
        >>> # Configure all three intervals
        >>> configure_isis_spf_intervals(
        ...     device=device,
        ...     first_interval=50,
        ...     hold_interval=200,
        ...     second_interval=5000,
        ...     protocol_instance='default'
        ... )
        >>> # Configure only specific intervals
        >>> configure_isis_spf_intervals(
        ...     device=device,
        ...     first_interval=100,
        ...     hold_interval=500
        ... )
    """
    if first_interval is None and hold_interval is None and second_interval is None:
        raise ValueError(
            "At least one SPF interval must be specified (first_interval, "
            "hold_interval, or second_interval)"
        )
    
    intervals = []
    if first_interval is not None:
        intervals.append(f"first={first_interval}ms")
    if hold_interval is not None:
        intervals.append(f"hold={hold_interval}ms")
    if second_interval is not None:
        intervals.append(f"second={second_interval}ms")
    
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


def configure_isis_interface_bfd(device, interface, enabled=True,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Enable or disable BFD TLV for ISIS on interface.
    
    BFD TLV enables BFD negotiation in ISIS hello packets.
    
    Args:
        device (obj): Device object
        interface (str): Interface name
        enabled (bool, optional): Enable or disable BFD TLV. Defaults to True.
        network_instance (str, optional): Network instance name. Defaults to 'default'.
        protocol_instance (str, optional): ISIS protocol instance name. Defaults to 'default'.
    
    Returns:
        None
    
    Raises:
        SubCommandFailure: Failed to configure BFD TLV
    
    Example:
        >>> configure_isis_interface_bfd(
        ...     device=device,
        ...     interface='swp1',
        ...     enabled=True,
        ...     protocol_instance='default'
        ... )
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} BFD TLV on interface {interface} "
        f"on {device.name} (network-instance: {network_instance}, "
        f"protocol-instance: {protocol_instance})"
    )
    
    intf_context = _build_interface_context(interface, network_instance, protocol_instance)
    config = [
        intf_context,
        f'bfd bfd-tlv {str(enabled).lower()}',
        '!'
    ]
    
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
