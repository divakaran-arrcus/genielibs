"""ArcOS EVPN over MPLS configure APIs.

Extends existing EVPN APIs with MPLS-specific configuration:
- LACP system-id-mac (for all-active multihoming / ESI)
- BGP asymmetric IRB options
- Overlay router-IP (LTEP)
"""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_lacp_system_id_mac(device, bond_interface, system_id_mac):
    """Configure LACP system-id-mac for EVPN all-active multihoming.

    Auto-generates ESI as 03:<mac>:00:00:00.

    Args:
        device: Device object.
        bond_interface: Bond interface name (e.g., 'bond0').
        system_id_mac: MAC address (e.g., 'aa:bb:cc:dd:ee:ff').
    """
    log.info(f"Configuring LACP system-id-mac on {bond_interface} on {device.name}")
    config = [
        f'lacp interface {bond_interface}',
        f'system-id-mac {system_id_mac}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LACP system-id-mac failed on {device.name}: {e}"
        )


def unconfigure_lacp_system_id_mac(device, bond_interface):
    """Remove LACP system-id-mac."""
    log.info(f"Removing LACP system-id-mac from {bond_interface} on {device.name}")
    try:
        device.configure([
            f'lacp interface {bond_interface}',
            'no system-id-mac',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LACP system-id-mac removal failed on {device.name}: {e}"
        )


def configure_overlay_ltep(device, ltep_id=0, source_interface='loopback0'):
    """Configure overlay local-tunnel-endpoint for EVPN MPLS.

    Args:
        device: Device object.
        ltep_id: LTEP index (default 0).
        source_interface: Source interface (default loopback0).
    """
    log.info(f"Configuring overlay LTEP {ltep_id} on {device.name}")
    config = [
        f'overlay local-tunnel-endpoint {ltep_id}',
        f'source-interface {source_interface}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Overlay LTEP config failed on {device.name}: {e}"
        )


def unconfigure_overlay_ltep(device, ltep_id=0):
    """Remove overlay local-tunnel-endpoint."""
    log.info(f"Removing overlay LTEP {ltep_id} from {device.name}")
    try:
        device.configure([f'no overlay local-tunnel-endpoint {ltep_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Overlay LTEP removal failed on {device.name}: {e}"
        )


def configure_bgp_rib_install_l2_label(device, vrf_name, afi_safi='IPV4_UNICAST',
                                         enabled=True):
    """Configure rib-install use-l2-label-for-evpn-rt2-route (asymmetric IRB).

    Args:
        device: Device object.
        vrf_name: VRF network-instance name.
        afi_safi: AFI-SAFI (default IPV4_UNICAST).
        enabled: Enable the feature (default True).
    """
    log.info(f"Configuring rib-install l2-label on {vrf_name} on {device.name}")
    flag = 'true' if enabled else 'false'
    config = [
        f'network-instance {vrf_name} protocol BGP {vrf_name}',
        f'global afi-safi {afi_safi}',
        f'rib-install use-l2-label-for-evpn-rt2-route {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"rib-install l2-label failed on {device.name}: {e}"
        )


def configure_bgp_suppress_rt5_routes(device, vrf_name,
                                        afi_safi='IPV4_UNICAST',
                                        rt_afi_safi='L2VPN_EVPN',
                                        enabled=True):
    """Configure suppress-rt5-routes (asymmetric IRB).

    Args:
        device: Device object.
        vrf_name: VRF network-instance name.
        afi_safi: AFI-SAFI (default IPV4_UNICAST).
        rt_afi_safi: RT AFI-SAFI (default L2VPN_EVPN).
        enabled: Enable suppression (default True).
    """
    log.info(f"Configuring suppress-rt5-routes on {vrf_name} on {device.name}")
    flag = 'true' if enabled else 'false'
    config = [
        f'network-instance {vrf_name} protocol BGP {vrf_name}',
        f'global afi-safi {afi_safi}',
        f'rt-afi-safi {rt_afi_safi}',
        f'evpn-route-options suppress-rt5-routes {flag}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"suppress-rt5-routes failed on {device.name}: {e}"
        )
