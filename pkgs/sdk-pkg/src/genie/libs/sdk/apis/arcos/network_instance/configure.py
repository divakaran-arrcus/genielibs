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


def configure_network_instance_vlan(device, ni_name, vlan_id):
    """Set VLAN on a network instance (L2VLAN).

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        vlan_id (int): VLAN ID

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure VLAN

    Example:
        >>> configure_network_instance_vlan(device, 'vlan3500', 3500)
    """
    log.info(
        f"Configuring vlan {vlan_id} on network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'vlan {vlan_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure vlan {vlan_id} on network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_vlan(device, ni_name):
    """Remove VLAN from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove VLAN

    Example:
        >>> unconfigure_network_instance_vlan(device, 'vlan3500')
    """
    log.info(
        f"Removing vlan from network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        'no vlan',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove vlan from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_network_instance_description(device, ni_name, description):
    """Set description on a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        description (str): Description text

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure description

    Example:
        >>> configure_network_instance_description(device, 'VRF-1', 'L3VPN for customer A')
    """
    log.info(
        f"Configuring description on network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'description "{description}"',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure description on network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_description(device, ni_name):
    """Remove description from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove description

    Example:
        >>> unconfigure_network_instance_description(device, 'VRF-1')
    """
    log.info(
        f"Removing description from network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        'no description',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove description from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_network_instance_evi_attributes(device, ni_name, evi_id,
                                                arp_nd_suppression=None,
                                                control_word=None,
                                                flow_label=None,
                                                advertise_irb_mac_ip=None):
    """Configure EVI sub-fields on a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        evi_id (int): EVI ID
        arp_nd_suppression (bool, optional): Enable ARP/ND suppression.
        control_word (bool, optional): Enable control-word.
        flow_label (bool, optional): Enable flow-label.
        advertise_irb_mac_ip (bool, optional): Advertise IRB MAC-IP.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure EVI attributes

    Example:
        >>> configure_network_instance_evi_attributes(device, 'EPLAN-1', 2001,
        ...     arp_nd_suppression=True, control_word=True)
    """
    log.info(
        f"Configuring EVI {evi_id} attributes on network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'evi {evi_id}',
    ]

    if arp_nd_suppression is not None:
        val = 'true' if arp_nd_suppression else 'false'
        config.append(f'arp-nd-suppression {val}')

    if control_word is not None:
        val = 'true' if control_word else 'false'
        config.append(f'control-word {val}')

    if flow_label is not None:
        val = 'true' if flow_label else 'false'
        config.append(f'flow-label {val}')

    if advertise_irb_mac_ip is not None:
        val = 'true' if advertise_irb_mac_ip else 'false'
        config.append(f'advertise-irb-mac-ip {val}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure EVI {evi_id} attributes on network-instance "
            f"{ni_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_evi_attributes(device, ni_name, evi_id):
    """Remove EVI sub-field configuration from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        evi_id (int): EVI ID

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove EVI attributes

    Example:
        >>> unconfigure_network_instance_evi_attributes(device, 'EPLAN-1', 2001)
    """
    log.info(
        f"Removing EVI {evi_id} attributes from network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'evi {evi_id}',
        'no arp-nd-suppression',
        'no control-word',
        'no flow-label',
        'no advertise-irb-mac-ip',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove EVI {evi_id} attributes from network-instance "
            f"{ni_name} on {device.name}. Error:\n{e}"
        )


def configure_network_instance_fdb(device, ni_name, maximum_entries=None,
                                    packet_action=None, mac_learning=None):
    """Configure FDB settings on a network instance.

    Note: The NI must already exist as L2VLAN before FDB commands
    are accepted.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        maximum_entries (int, optional): FDB max entries limit.
        packet_action (str, optional): Packet action (e.g., 'FLOOD_ACTION').
        mac_learning (bool, optional): Enable/disable MAC learning.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure FDB

    Example:
        >>> configure_network_instance_fdb(device, 'EPLAN-1',
        ...     maximum_entries=2048, mac_learning=True)
    """
    log.info(
        f"Configuring FDB on network-instance {ni_name} on {device.name}"
    )

    config = [f'network-instance {ni_name}']

    if maximum_entries is not None:
        config.append(f'fdb maximum-entries {maximum_entries}')

    if packet_action is not None:
        config.append(f'fdb packet-action {packet_action}')

    if mac_learning is not None:
        val = 'true' if mac_learning else 'false'
        config.append(f'fdb mac-learning {val}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure FDB on network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_fdb(device, ni_name):
    """Remove FDB configuration from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove FDB config

    Example:
        >>> unconfigure_network_instance_fdb(device, 'EPLAN-1')
    """
    log.info(
        f"Removing FDB config from network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        'no fdb maximum-entries',
        'no fdb packet-action',
        'no fdb mac-learning',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove FDB config from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_network_instance_rib_options(device, ni_name, af='ipv4',
                                            max_prefix_limit=None,
                                            threshold=None):
    """Configure RIB options on a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        af (str, optional): Address family ('ipv4' or 'ipv6'). Defaults to 'ipv4'.
        max_prefix_limit (int, optional): Maximum prefix limit.
        threshold (int, optional): Threshold percentage.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure RIB options

    Example:
        >>> configure_network_instance_rib_options(device, 'VRF-1',
        ...     af='ipv4', max_prefix_limit=1000, threshold=90)
    """
    af_lower = af.lower()
    log.info(
        f"Configuring rib-options {af_lower} on network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [f'network-instance {ni_name}']

    if max_prefix_limit is not None:
        config.append(
            f'rib-options {af_lower} max-prefix-limit {max_prefix_limit}'
        )

    if threshold is not None:
        config.append(f'rib-options {af_lower} threshold {threshold}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure rib-options on network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_rib_options(device, ni_name, af='ipv4'):
    """Remove RIB options from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        af (str, optional): Address family ('ipv4' or 'ipv6'). Defaults to 'ipv4'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove RIB options

    Example:
        >>> unconfigure_network_instance_rib_options(device, 'VRF-1', af='ipv4')
    """
    af_lower = af.lower()
    log.info(
        f"Removing rib-options {af_lower} from network-instance {ni_name} "
        f"on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'no rib-options {af_lower} max-prefix-limit',
        f'no rib-options {af_lower} threshold',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove rib-options from network-instance {ni_name} "
            f"on {device.name}. Error:\n{e}"
        )


def configure_network_instance_table_connection(device, ni_name, src_proto,
                                                  dst_proto, af,
                                                  src_dst_instance=None,
                                                  import_policy=None):
    """Configure a table connection (redistribution) on a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        src_proto (str): Source protocol (e.g., 'STATIC', 'ISIS', 'BGP')
        dst_proto (str): Destination protocol (e.g., 'ISIS', 'BGP')
        af (str): Address family (e.g., 'IPV4', 'IPV6')
        src_dst_instance (str, optional): Source and destination instance
            (e.g., 'default default').
        import_policy (str, optional): Import policy name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure table connection

    Example:
        >>> configure_network_instance_table_connection(device, 'default',
        ...     'STATIC', 'ISIS', 'IPV4', import_policy='redis_static')
    """
    log.info(
        f"Configuring table-connection {src_proto}->{dst_proto} {af} on "
        f"network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'table-connection {src_proto} {dst_proto} {af}',
    ]

    if src_dst_instance is not None:
        config.append(f'src-dst-instance {src_dst_instance}')

    if import_policy is not None:
        config.append(f'import-policy [ {import_policy} ]')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure table-connection on network-instance "
            f"{ni_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_table_connection(device, ni_name, src_proto,
                                                    dst_proto, af):
    """Remove a table connection from a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        src_proto (str): Source protocol
        dst_proto (str): Destination protocol
        af (str): Address family

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove table connection

    Example:
        >>> unconfigure_network_instance_table_connection(device, 'default',
        ...     'STATIC', 'ISIS', 'IPV4')
    """
    log.info(
        f"Removing table-connection {src_proto}->{dst_proto} {af} from "
        f"network-instance {ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'no table-connection {src_proto} {dst_proto} {af}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove table-connection from network-instance "
            f"{ni_name} on {device.name}. Error:\n{e}"
        )


def configure_network_instance_vpws_service_id(device, ni_name, interface,
                                                 local_id, remote_id):
    """Configure VPWS service-id on an interface in a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name (L2P2P_EVPN)
        interface (str): Interface name (e.g., 'swp5.7001')
        local_id (int): Local service ID
        remote_id (int): Remote service ID

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure VPWS service-id

    Example:
        >>> configure_network_instance_vpws_service_id(device, 'VPWS-1',
        ...     'swp5.7001', local_id=1001, remote_id=2001)
    """
    log.info(
        f"Configuring VPWS service-id on {interface} in network-instance "
        f"{ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'interface {interface}',
        f'vpws-service-id local {local_id}',
        f'vpws-service-id remote {remote_id}',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure VPWS service-id on {interface} in "
            f"network-instance {ni_name} on {device.name}. Error:\n{e}"
        )


def unconfigure_network_instance_vpws_service_id(device, ni_name, interface):
    """Remove VPWS service-id from an interface in a network instance.

    Args:
        device (obj): Device object
        ni_name (str): Network instance name
        interface (str): Interface name

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove VPWS service-id

    Example:
        >>> unconfigure_network_instance_vpws_service_id(device, 'VPWS-1', 'swp5.7001')
    """
    log.info(
        f"Removing VPWS service-id from {interface} in network-instance "
        f"{ni_name} on {device.name}"
    )

    config = [
        f'network-instance {ni_name}',
        f'interface {interface}',
        'no vpws-service-id local',
        'no vpws-service-id remote',
        '!'
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove VPWS service-id from {interface} in "
            f"network-instance {ni_name} on {device.name}. Error:\n{e}"
        )
