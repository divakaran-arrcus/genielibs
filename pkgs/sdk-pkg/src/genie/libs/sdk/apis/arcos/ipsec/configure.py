"""ArcOS IPsec configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_ipsec_pad_entry(device, entry_type, ipv4_address, secret):
    """Configure IPsec pre-shared key (PAD entry).

    Args:
        device: Device object.
        entry_type: 'local' or 'remote'.
        ipv4_address: IP address for the PAD entry.
        secret: Pre-shared key secret string.
    """
    log.info(f"Configuring IPsec PAD entry {entry_type} on {device.name}")
    config = [
        f'ipsec-ike pad pad-entry {entry_type}',
        f'ipv4-address {ipv4_address}',
        f'peer-authentication pre-shared secret {secret}',
        '!',
    ]
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPsec PAD entry failed on {device.name}: {e}")


def unconfigure_ipsec_pad_entry(device, entry_type):
    """Remove IPsec PAD entry."""
    log.info(f"Removing IPsec PAD entry {entry_type} from {device.name}")
    try:
        device.configure([f'no ipsec-ike pad pad-entry {entry_type}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPsec PAD removal failed on {device.name}: {e}")


def configure_ipsec_conn_entry(device, name, version='ikev2',
                                autostartup='start', authalg=None,
                                encalg=None, dh_group=None,
                                rekey_time=None):
    """Configure IPsec IKE connection entry.

    Args:
        device: Device object.
        name: VPN connection name.
        version: IKE version (ikev1 or ikev2).
        autostartup: Auto startup mode (start).
        authalg: Authentication algorithm (e.g., sha1).
        encalg: Encryption algorithm (e.g., aes128).
        dh_group: Diffie-Hellman group number.
        rekey_time: IKE SA rekey time in seconds.
    """
    log.info(f"Configuring IPsec conn-entry {name} on {device.name}")
    config = [f'ipsec-ike conn-entry {name}']
    if autostartup:
        config.append(f'autostartup {autostartup}')
    config.append(f'version {version}')
    if rekey_time is not None:
        config.append(f'ike-sa-lifetime-soft rekey-time {rekey_time}')
    if authalg:
        config.append(f'authalg [ {authalg} ]')
    if encalg:
        config.append(f'encalg [ {encalg} ]')
    if dh_group is not None:
        config.append(f'dh-group {dh_group}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPsec conn-entry failed on {device.name}: {e}")


def unconfigure_ipsec_conn_entry(device, name):
    """Remove IPsec IKE connection entry."""
    log.info(f"Removing IPsec conn-entry {name} from {device.name}")
    try:
        device.configure([f'no ipsec-ike conn-entry {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPsec conn-entry removal failed on {device.name}: {e}")


def configure_ipsec_spd_entry(device, conn_name, spd_name,
                               local_subnets, remote_subnets,
                               tunnel_local=None, tunnel_remote=None,
                               spd_mark=None):
    """Configure IPsec SPD (Security Policy Database) entry.

    Args:
        device: Device object.
        conn_name: Connection entry name.
        spd_name: SPD policy name.
        local_subnets: List of local subnets (e.g., ['10.0.1.0/24']).
        remote_subnets: List of remote subnets.
        tunnel_local: Local tunnel endpoint IP.
        tunnel_remote: Remote tunnel endpoint IP.
        spd_mark: DSCP mark value for route-based VPN.
    """
    log.info(f"Configuring IPsec SPD {spd_name} on {device.name}")
    local_str = ' '.join(local_subnets) if isinstance(local_subnets, list) else local_subnets
    remote_str = ' '.join(remote_subnets) if isinstance(remote_subnets, list) else remote_subnets

    config = [
        f'ipsec-ike conn-entry {conn_name} spd spd-entry {spd_name}',
        f'ipsec-policy-config traffic-selector local-subnets [ {local_str} ]',
        f'ipsec-policy-config traffic-selector remote-subnets [ {remote_str} ]',
        'ipsec-policy-config processing-info action protect',
        'ipsec-policy-config processing-info ipsec-sa-cfg mode tunnel',
    ]
    if tunnel_local:
        config.append(f'ipsec-policy-config processing-info ipsec-sa-cfg tunnel local {tunnel_local}')
    if tunnel_remote:
        config.append(f'ipsec-policy-config processing-info ipsec-sa-cfg tunnel remote {tunnel_remote}')
    if spd_mark is not None:
        config.append(f'ipsec-policy-config spd-mark mark {spd_mark}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPsec SPD entry failed on {device.name}: {e}")


def unconfigure_ipsec_spd_entry(device, conn_name, spd_name):
    """Remove IPsec SPD entry."""
    log.info(f"Removing IPsec SPD {spd_name} from {device.name}")
    try:
        device.configure([
            f'ipsec-ike conn-entry {conn_name}',
            f'no spd spd-entry {spd_name}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"IPsec SPD removal failed on {device.name}: {e}")
