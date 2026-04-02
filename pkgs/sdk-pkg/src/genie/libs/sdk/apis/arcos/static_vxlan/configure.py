"""ArcOS Static VXLAN configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_static_vxlan_global(device, enabled=True):
    """Enable/disable static VXLAN globally.

    Args:
        device: Device object.
        enabled: Enable static VXLAN (default True).
    """
    log.info(f"Configuring static VXLAN global on {device.name}")
    flag = 'true' if enabled else 'false'
    try:
        device.configure([f'overlay static-vxlan {flag}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Static VXLAN global failed on {device.name}: {e}")


def unconfigure_static_vxlan_global(device):
    """Disable static VXLAN globally."""
    log.info(f"Disabling static VXLAN on {device.name}")
    try:
        device.configure(['overlay static-vxlan false', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Static VXLAN disable failed on {device.name}: {e}")


def configure_static_vxlan_ni(device, ni_name, remote_vteps, vni_vlan_map,
                               ltep_id=0):
    """Configure a Static VXLAN network-instance (L2VLAN_AWARE_BUNDLE).

    Args:
        device: Device object.
        ni_name: Network-instance name.
        remote_vteps: List of remote VTEP IP addresses.
        vni_vlan_map: Dict of VNI -> VLAN ID mappings.
        ltep_id: Local tunnel endpoint ID (default 0).
    """
    log.info(f"Configuring static VXLAN NI {ni_name} on {device.name}")
    vtep_str = ' '.join(remote_vteps) if isinstance(remote_vteps, list) else remote_vteps
    config = [
        f'network-instance {ni_name}',
        'type L2VLAN_AWARE_BUNDLE',
        f'local-tunnel-endpoint-id {ltep_id}',
        f'static-vxlan remote-vteps [ {vtep_str} ]',
    ]
    for vni, vlan_id in sorted(vni_vlan_map.items()):
        config.append(f'vni {vni} vlan-id {vlan_id}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Static VXLAN NI failed on {device.name}: {e}")


def unconfigure_static_vxlan_ni(device, ni_name):
    """Remove a Static VXLAN network-instance."""
    log.info(f"Removing static VXLAN NI {ni_name} from {device.name}")
    try:
        device.configure([f'no network-instance {ni_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"Static VXLAN NI removal failed on {device.name}: {e}")
