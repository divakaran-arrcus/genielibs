"""Common configure functions for BFD on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_bfd_profile(device, profile_name, enabled=None, tx_interval=None,
                          rx_interval=None, detection_multiplier=None,
                          dscp_value=None, v4_hw_offload=None, v6_hw_offload=None):
    """Configure a BFD profile with optional parameters.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        enabled (bool, optional): Enable or disable the profile. Defaults to None.
        tx_interval (int, optional): Desired minimum TX interval in microseconds.
            Defaults to None.
        rx_interval (int, optional): Required minimum receive interval in microseconds.
            Defaults to None.
        detection_multiplier (int, optional): Detection multiplier. Defaults to None.
        dscp_value (int, optional): DSCP value for BFD packets. Defaults to None.
        v4_hw_offload (bool, optional): Enable/disable IPv4 hardware offload.
            Defaults to None.
        v6_hw_offload (bool, optional): Enable/disable IPv6 hardware offload.
            Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD profile

    Example:
        >>> configure_bfd_profile(
        ...     device=device,
        ...     profile_name='fast',
        ...     enabled=True,
        ...     tx_interval=100000,
        ...     rx_interval=100000,
        ...     detection_multiplier=3
        ... )
    """
    log.info(
        f"Configuring BFD profile '{profile_name}' on {device.name}"
    )

    config = [f'bfd profile {profile_name}']

    if enabled is not None:
        config.append(f'enabled {"true" if enabled else "false"}')
    if tx_interval is not None:
        config.append(f'desired-minimum-tx-interval {tx_interval}')
    if rx_interval is not None:
        config.append(f'required-minimum-receive {rx_interval}')
    if detection_multiplier is not None:
        config.append(f'detection-multiplier {detection_multiplier}')
    if dscp_value is not None:
        config.append(f'dscp-value {dscp_value}')
    if v4_hw_offload is not None:
        config.append(f'v4-hw-offload {"true" if v4_hw_offload else "false"}')
    if v6_hw_offload is not None:
        config.append(f'v6-hw-offload {"true" if v6_hw_offload else "false"}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD profile '{profile_name}' on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_bfd_profile(device, profile_name):
    """Remove an entire BFD profile.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name to remove

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD profile

    Example:
        >>> unconfigure_bfd_profile(device=device, profile_name='fast')
    """
    log.info(
        f"Removing BFD profile '{profile_name}' on {device.name}"
    )

    config = [
        f'no bfd profile {profile_name}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD profile '{profile_name}' on {device.name}. "
            f"Error:\n{e}"
        )


def configure_bfd_profile_tx_interval(device, profile_name, interval):
    """Configure BFD profile desired minimum TX interval.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        interval (int): Desired minimum TX interval in microseconds

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD profile TX interval

    Example:
        >>> configure_bfd_profile_tx_interval(
        ...     device=device, profile_name='fast', interval=100000
        ... )
    """
    log.info(
        f"Configuring BFD profile '{profile_name}' TX interval {interval} "
        f"on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        f'desired-minimum-tx-interval {interval}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD profile '{profile_name}' TX interval "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_bfd_profile_tx_interval(device, profile_name):
    """Remove BFD profile desired minimum TX interval.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD profile TX interval

    Example:
        >>> unconfigure_bfd_profile_tx_interval(
        ...     device=device, profile_name='fast'
        ... )
    """
    log.info(
        f"Removing BFD profile '{profile_name}' TX interval on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        'no desired-minimum-tx-interval',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD profile '{profile_name}' TX interval "
            f"on {device.name}. Error:\n{e}"
        )


def configure_bfd_profile_rx_interval(device, profile_name, interval):
    """Configure BFD profile required minimum receive interval.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        interval (int): Required minimum receive interval in microseconds

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD profile RX interval

    Example:
        >>> configure_bfd_profile_rx_interval(
        ...     device=device, profile_name='fast', interval=100000
        ... )
    """
    log.info(
        f"Configuring BFD profile '{profile_name}' RX interval {interval} "
        f"on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        f'required-minimum-receive {interval}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD profile '{profile_name}' RX interval "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_bfd_profile_rx_interval(device, profile_name):
    """Remove BFD profile required minimum receive interval.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD profile RX interval

    Example:
        >>> unconfigure_bfd_profile_rx_interval(
        ...     device=device, profile_name='fast'
        ... )
    """
    log.info(
        f"Removing BFD profile '{profile_name}' RX interval on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        'no required-minimum-receive',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD profile '{profile_name}' RX interval "
            f"on {device.name}. Error:\n{e}"
        )


def configure_bfd_profile_detection_multiplier(device, profile_name, multiplier):
    """Configure BFD profile detection multiplier.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        multiplier (int): Detection multiplier value

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD profile detection multiplier

    Example:
        >>> configure_bfd_profile_detection_multiplier(
        ...     device=device, profile_name='fast', multiplier=3
        ... )
    """
    log.info(
        f"Configuring BFD profile '{profile_name}' detection multiplier "
        f"{multiplier} on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        f'detection-multiplier {multiplier}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD profile '{profile_name}' detection "
            f"multiplier on {device.name}. Error:\n{e}"
        )


def unconfigure_bfd_profile_detection_multiplier(device, profile_name):
    """Remove BFD profile detection multiplier.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD profile detection multiplier

    Example:
        >>> unconfigure_bfd_profile_detection_multiplier(
        ...     device=device, profile_name='fast'
        ... )
    """
    log.info(
        f"Removing BFD profile '{profile_name}' detection multiplier "
        f"on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        'no detection-multiplier',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD profile '{profile_name}' detection "
            f"multiplier on {device.name}. Error:\n{e}"
        )


def configure_bfd_profile_enabled(device, profile_name, enabled=True):
    """Configure BFD profile enabled state.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        enabled (bool, optional): Enable or disable the profile. Defaults to True.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD profile enabled state

    Example:
        >>> configure_bfd_profile_enabled(
        ...     device=device, profile_name='fast', enabled=True
        ... )
    """
    log.info(
        f"Setting BFD profile '{profile_name}' enabled={enabled} "
        f"on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        f'enabled {"true" if enabled else "false"}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD profile '{profile_name}' enabled state "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_bfd_profile_enabled(device, profile_name):
    """Remove BFD profile enabled configuration (revert to default).

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD profile enabled configuration

    Example:
        >>> unconfigure_bfd_profile_enabled(
        ...     device=device, profile_name='fast'
        ... )
    """
    log.info(
        f"Removing BFD profile '{profile_name}' enabled config on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        'no enabled',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD profile '{profile_name}' enabled config "
            f"on {device.name}. Error:\n{e}"
        )


def configure_bfd_profile_hw_offload(device, profile_name, v4=None, v6=None):
    """Configure BFD profile hardware offload settings.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        v4 (bool, optional): Enable/disable IPv4 hardware offload.
            Defaults to None.
        v6 (bool, optional): Enable/disable IPv6 hardware offload.
            Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD profile hardware offload

    Example:
        >>> configure_bfd_profile_hw_offload(
        ...     device=device, profile_name='fast', v4=True, v6=True
        ... )
    """
    log.info(
        f"Configuring BFD profile '{profile_name}' hardware offload "
        f"(v4={v4}, v6={v6}) on {device.name}"
    )

    config = [f'bfd profile {profile_name}']

    if v4 is not None:
        config.append(f'v4-hw-offload {"true" if v4 else "false"}')
    if v6 is not None:
        config.append(f'v6-hw-offload {"true" if v6 else "false"}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD profile '{profile_name}' hardware "
            f"offload on {device.name}. Error:\n{e}"
        )


def unconfigure_bfd_profile_hw_offload(device, profile_name, v4=True, v6=True):
    """Remove BFD profile hardware offload settings.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        v4 (bool, optional): Remove IPv4 hardware offload config.
            Defaults to True.
        v6 (bool, optional): Remove IPv6 hardware offload config.
            Defaults to True.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD profile hardware offload

    Example:
        >>> unconfigure_bfd_profile_hw_offload(
        ...     device=device, profile_name='fast', v4=True, v6=True
        ... )
    """
    log.info(
        f"Removing BFD profile '{profile_name}' hardware offload "
        f"(v4={v4}, v6={v6}) on {device.name}"
    )

    config = [f'bfd profile {profile_name}']

    if v4:
        config.append('no v4-hw-offload')
    if v6:
        config.append('no v6-hw-offload')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD profile '{profile_name}' hardware "
            f"offload on {device.name}. Error:\n{e}"
        )


def configure_bfd_profile_dscp(device, profile_name, dscp_value):
    """Configure BFD profile DSCP value for BFD packets.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name
        dscp_value (int): DSCP value for BFD packets

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD profile DSCP value

    Example:
        >>> configure_bfd_profile_dscp(
        ...     device=device, profile_name='fast', dscp_value=48
        ... )
    """
    log.info(
        f"Configuring BFD profile '{profile_name}' DSCP value {dscp_value} "
        f"on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        f'dscp-value {dscp_value}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD profile '{profile_name}' DSCP value "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_bfd_profile_dscp(device, profile_name):
    """Remove BFD profile DSCP value configuration.

    Args:
        device (obj): Device object
        profile_name (str): BFD profile name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD profile DSCP value

    Example:
        >>> unconfigure_bfd_profile_dscp(
        ...     device=device, profile_name='fast'
        ... )
    """
    log.info(
        f"Removing BFD profile '{profile_name}' DSCP value on {device.name}"
    )

    config = [
        f'bfd profile {profile_name}',
        'no dscp-value',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD profile '{profile_name}' DSCP value "
            f"on {device.name}. Error:\n{e}"
        )


def configure_bfd_single_hop_interface(device, interface, tx_interval=None,
                                       rx_interval=None,
                                       detection_multiplier=None):
    """Configure BFD single-hop per-interface overrides.

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g., 'ethernet-1/1')
        tx_interval (int, optional): Desired minimum TX interval in microseconds.
            Defaults to None.
        rx_interval (int, optional): Required minimum receive interval in microseconds.
            Defaults to None.
        detection_multiplier (int, optional): Detection multiplier. Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure BFD single-hop interface

    Example:
        >>> configure_bfd_single_hop_interface(
        ...     device=device,
        ...     interface='ethernet-1/1',
        ...     tx_interval=100000,
        ...     rx_interval=100000,
        ...     detection_multiplier=3
        ... )
    """
    log.info(
        f"Configuring BFD single-hop interface '{interface}' on {device.name}"
    )

    config = [f'bfd single-hop interface {interface}']

    if tx_interval is not None:
        config.append(f'desired-minimum-tx-interval {tx_interval}')
    if rx_interval is not None:
        config.append(f'required-minimum-receive {rx_interval}')
    if detection_multiplier is not None:
        config.append(f'detection-multiplier {detection_multiplier}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure BFD single-hop interface '{interface}' "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_bfd_single_hop_interface(device, interface):
    """Remove BFD single-hop per-interface configuration.

    Args:
        device (obj): Device object
        interface (str): Interface name (e.g., 'ethernet-1/1')

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove BFD single-hop interface configuration

    Example:
        >>> unconfigure_bfd_single_hop_interface(
        ...     device=device, interface='ethernet-1/1'
        ... )
    """
    log.info(
        f"Removing BFD single-hop interface '{interface}' on {device.name}"
    )

    config = [
        f'no bfd single-hop interface {interface}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove BFD single-hop interface '{interface}' "
            f"on {device.name}. Error:\n{e}"
        )
