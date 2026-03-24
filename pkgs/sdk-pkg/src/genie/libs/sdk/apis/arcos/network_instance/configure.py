"""Common configure functions for Network Instance on ArcOS"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_network_instance(device, ni_name, ni_type=None):
    """Create a network instance, optionally setting its type.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name (e.g., 'vlan100', 'vrf-3001')
        ni_type (str, optional): NI type ('L2VLAN', 'L3VRF', 'L2P2P_EVPN',
            'L2VLAN_AWARE_BUNDLE'). Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to create network instance

    Example:
        >>> configure_network_instance(device, 'vlan100', ni_type='L2VLAN')
    """
    log.info(f"Creating network-instance {ni_name} on {device.name}")

    config = [f'network-instance {ni_name}']
    if ni_type is not None:
        config.append(f'type {ni_type}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not create network-instance {ni_name} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_network_instance(device, ni_name):
    """Remove a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove network instance

    Example:
        >>> unconfigure_network_instance(device, 'vlan100')
    """
    log.info(f"Removing network-instance {ni_name} from {device.name}")

    config = [
        f'no network-instance {ni_name}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove network-instance {ni_name} from {device.name}. "
            f"Error:\n{e}"
        )


def configure_network_instance_interface(device, ni_name, interface):
    """Bind an interface to a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        interface (str): Interface name (e.g., 'swp1.100', 'loopback0')

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to bind interface to network instance

    Example:
        >>> configure_network_instance_interface(device, 'vlan100', 'swp1.100')
    """
    log.info(
        f"Binding interface {interface} to network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'interface {interface}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not bind interface {interface} to network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_interface(device, ni_name, interface):
    """Unbind an interface from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        interface (str): Interface name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to unbind interface from network instance

    Example:
        >>> unconfigure_network_instance_interface(device, 'vlan100', 'swp1.100')
    """
    log.info(
        f"Unbinding interface {interface} from network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'no interface {interface}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not unbind interface {interface} from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_network_instance_vni(device, ni_name, vni, ltep_id=0):
    """Configure VNI on a network instance with local tunnel endpoint.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        vni (int): VNI number
        ltep_id (int, optional): Local tunnel endpoint ID. Defaults to 0.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure VNI

    Example:
        >>> configure_network_instance_vni(device, 'vlan100', 100, ltep_id=0)
    """
    log.info(
        f"Configuring VNI {vni} on network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'vni {vni} local-tunnel-endpoint-id {ltep_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure VNI {vni} on network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_vni(device, ni_name, vni):
    """Remove VNI from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        vni (int): VNI number

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove VNI

    Example:
        >>> unconfigure_network_instance_vni(device, 'vlan100', 100)
    """
    log.info(
        f"Removing VNI {vni} from network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'no vni {vni}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove VNI {vni} from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_network_instance_evi(device, ni_name, evi_id):
    """Configure EVI (EVPN Instance) on a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        evi_id (int): EVI ID

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure EVI

    Example:
        >>> configure_network_instance_evi(device, 'vlan100', 100)
    """
    log.info(
        f"Configuring EVI {evi_id} on network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'evi {evi_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure EVI {evi_id} on network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_evi(device, ni_name, evi_id):
    """Remove EVI from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        evi_id (int): EVI ID

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove EVI

    Example:
        >>> unconfigure_network_instance_evi(device, 'vlan100', 100)
    """
    log.info(
        f"Removing EVI {evi_id} from network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'no evi {evi_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove EVI {evi_id} from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_network_instance_advertise_mac_routes(device, ni_name, enabled=True):
    """Configure MAC route advertisement on a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        enabled (bool, optional): Enable MAC route advertisement. Defaults to True.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure advertise-mac-routes

    Example:
        >>> configure_network_instance_advertise_mac_routes(device, 'vlan100')
    """
    val = 'true' if enabled else 'false'
    log.info(
        f"Configuring advertise-mac-routes {val} on network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'advertise-mac-routes {val}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure advertise-mac-routes on network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_advertise_mac_routes(device, ni_name):
    """Remove MAC route advertisement configuration from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove advertise-mac-routes

    Example:
        >>> unconfigure_network_instance_advertise_mac_routes(device, 'vlan100')
    """
    log.info(
        f"Removing advertise-mac-routes from network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        'no advertise-mac-routes',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove advertise-mac-routes from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )
