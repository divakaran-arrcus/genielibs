"""ArcOS EVPN VPWS, E-Tree, and DCI configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# =====================================================================
# EVPN VPWS
# =====================================================================

def configure_evpn_vpws_link_loss_forwarding(device, ni_name, evi_id,
                                               enabled=True):
    """Configure link-loss-forwarding on VPWS EVI."""
    log.info(f"Configuring link-loss-forwarding on {ni_name} EVI {evi_id} on {device.name}")
    flag = 'true' if enabled else 'false'
    config = [
        f'network-instance {ni_name}',
        f'evi {evi_id}',
        f'link-loss-forwarding {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Link-loss-forwarding failed on {device.name}: {e}")


def configure_interface_evpn_esi(device, interface, esi):
    """Configure static EVPN ESI on an interface.

    Args:
        device: Device object.
        interface: Interface name (e.g., bond10).
        esi: ESI value (10 octets, e.g., '00:01:02:03:04:05:06:07:08:09').
    """
    log.info(f"Configuring EVPN ESI on {interface} on {device.name}")
    config = [
        f'interface {interface}',
        f'evpn esi {esi}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"EVPN ESI config failed on {device.name}: {e}")


def unconfigure_interface_evpn_esi(device, interface):
    """Remove EVPN ESI from an interface."""
    log.info(f"Removing EVPN ESI from {interface} on {device.name}")
    try:
        device.configure([f'interface {interface}', 'no evpn esi', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"EVPN ESI removal failed on {device.name}: {e}")


# =====================================================================
# EVPN E-Tree
# =====================================================================

def configure_evpn_etree(device, ni_name, evi_id, enabled=True):
    """Configure E-Tree on an EVI.

    Args:
        device: Device object.
        ni_name: Network-instance name.
        evi_id: EVI ID.
        enabled: Enable E-Tree (default True).
    """
    log.info(f"Configuring E-Tree on {ni_name} EVI {evi_id} on {device.name}")
    flag = 'true' if enabled else 'false'
    config = [
        f'network-instance {ni_name}',
        f'evi {evi_id}',
        f'e-tree {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"E-Tree config failed on {device.name}: {e}")


def configure_interface_etree_leaf(device, interface, sub_id, enabled=True):
    """Mark a subinterface as E-Tree Leaf AC.

    Args:
        device: Device object.
        interface: Interface name.
        sub_id: Subinterface ID.
        enabled: Mark as leaf (default True).
    """
    log.info(f"Configuring etree-leaf on {interface} sub {sub_id} on {device.name}")
    flag = 'true' if enabled else 'false'
    config = [
        f'interface {interface}',
        f'subinterface {sub_id}',
        f'etree-leaf {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"etree-leaf config failed on {device.name}: {e}")


# =====================================================================
# EVPN DCI
# =====================================================================

def configure_evpn_domain(device, domain_name):
    """Configure EVPN domain for DCI.

    Args:
        device: Device object.
        domain_name: Domain name (e.g., 'wan').
    """
    log.info(f"Configuring EVPN domain {domain_name} on {device.name}")
    try:
        device.configure([f'evpn domain {domain_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"EVPN domain config failed on {device.name}: {e}")


def unconfigure_evpn_domain(device, domain_name):
    """Remove EVPN domain."""
    log.info(f"Removing EVPN domain {domain_name} from {device.name}")
    try:
        device.configure([f'no evpn domain {domain_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"EVPN domain removal failed on {device.name}: {e}")


def configure_ni_evpn_domain(device, ni_name, domain_name, evi_id,
                              control_word=None):
    """Configure EVPN domain context on a network-instance.

    Args:
        device: Device object.
        ni_name: Network-instance name.
        domain_name: EVPN domain name.
        evi_id: EVI ID for this domain.
        control_word: Optional control-word setting (bool).
    """
    log.info(f"Configuring domain {domain_name} on {ni_name} on {device.name}")
    config = [
        f'network-instance {ni_name}',
        f'domain {domain_name}',
        f'evi {evi_id}',
    ]
    if control_word is not None:
        flag = 'true' if control_word else 'false'
        config.append(f'control-word {flag}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"NI domain config failed on {device.name}: {e}")


def configure_bgp_reoriginate_evpn_dci(device, afi_safi, enabled=True,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Configure reoriginate evpn-l3vpn-dci on BGP AFI-SAFI.

    Args:
        device: Device object.
        afi_safi: AFI-SAFI (e.g., IPV4_UNICAST, IPV6_UNICAST).
        enabled: Enable reorigination (default True).
        network_instance: VRF name.
        protocol_instance: BGP instance.
    """
    log.info(f"Configuring reoriginate evpn-l3vpn-dci on {network_instance} on {device.name}")
    flag = 'true' if enabled else 'false'
    config = [
        f'network-instance {network_instance} protocol BGP {protocol_instance}',
        f'global afi-safi {afi_safi}',
        f'reoriginate evpn-l3vpn-dci enabled {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Reoriginate DCI failed on {device.name}: {e}")


def configure_vni_centralized_evpn_routing(device, ni_name, vni_id,
                                             ltep_id=0, enabled=True):
    """Configure centralized-evpn-routing on a VNI.

    Args:
        device: Device object.
        ni_name: Network-instance name.
        vni_id: VNI ID.
        ltep_id: Local tunnel endpoint ID (default 0).
        enabled: Enable centralized routing (default True).
    """
    log.info(f"Configuring centralized-evpn-routing on {ni_name} VNI {vni_id} on {device.name}")
    flag = 'true' if enabled else 'false'
    config = [
        f'network-instance {ni_name}',
        f'vni {vni_id}',
        f'local-tunnel-endpoint-id {ltep_id}',
        f'centralized-evpn-routing {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Centralized-evpn-routing failed on {device.name}: {e}")
