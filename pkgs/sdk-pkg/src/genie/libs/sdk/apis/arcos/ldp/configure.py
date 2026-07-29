"""Common configure functions for LDP on ArcOS.

All LDP commands live under:
    network-instance default mpls signaling-protocols ldp

Note: LDP can only be configured under the default network-instance.
"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

# Base CLI prefix for all LDP commands
_LDP_CTX = 'network-instance default mpls signaling-protocols ldp'


# =====================================================================
# Global
# =====================================================================

def configure_ldp_global(device, lsr_id, transport_ipv4,
                         fec_default_policy='ACCEPT_ROUTE',
                         php_type=None):
    """Configure LDP core global settings (lsr-id, transport, fec-filter).

    Args:
        device (obj): Device object.
        lsr_id (str): LSR identifier (IPv4 address, e.g., '10.0.0.1').
        transport_ipv4 (str): IPv4 transport address for LDP sessions.
        fec_default_policy (str, optional): FEC default export policy.
            Defaults to 'ACCEPT_ROUTE'.
        php_type (str, optional): PHP type — EXPLICIT or IMPLICIT.
            Defaults to None (not configured).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP global settings.

    Example:
        >>> configure_ldp_global(device, '10.0.0.1', '10.0.0.1', php_type='EXPLICIT')
    """

    log.info(
        f"Configuring LDP global on {device.name}: lsr-id={lsr_id}, "
        f"transport={transport_ipv4}"
    )

    config = [
        f'{_LDP_CTX} global lsr-id {lsr_id}',
        f'{_LDP_CTX} global enable true',
        f'{_LDP_CTX} global fec-filter default-export-policy {fec_default_policy}',
        f'{_LDP_CTX} global transport-address ipv4 {transport_ipv4}',
    ]

    if php_type is not None:
        config.append(f'{_LDP_CTX} global attributes php-type {php_type}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP global on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_ldp_global(device):
    """Remove LDP core global settings.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP global settings.

    Example:
        >>> unconfigure_ldp_global(device)
    """

    log.info(f"Removing LDP global config from {device.name}")

    config = [
        f'no {_LDP_CTX} global lsr-id',
        f'no {_LDP_CTX} global transport-address ipv4',
        f'no {_LDP_CTX} global fec-filter default-export-policy',
        f'no {_LDP_CTX} global attributes php-type',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP global config from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# Enable
# =====================================================================

def configure_ldp_enable(device, enabled=True):
    """Enable or disable LDP globally.

    Args:
        device (obj): Device object.
        enabled (bool, optional): True to enable, False to disable.
            Defaults to True.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP enable.

    Example:
        >>> configure_ldp_enable(device, enabled=True)
    """

    enabled_str = 'true' if enabled else 'false'
    log.info(f"Configuring LDP global enable {enabled_str} on {device.name}")

    config = [
        f'{_LDP_CTX} global enable {enabled_str}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP enable on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_ldp_enable(device):
    """Remove LDP global enable configuration.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP enable config.

    Example:
        >>> unconfigure_ldp_enable(device)
    """

    log.info(f"Removing LDP global enable from {device.name}")

    config = [
        f'no {_LDP_CTX} global enable',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP enable from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# Interface
# =====================================================================

def configure_ldp_interface(device, interface, ipv4_enabled=True):
    """Enable LDP on an interface (link-hello + address-family IPV4).

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp1').
        ipv4_enabled (bool, optional): Enable IPv4 AF. Defaults to True.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP interface.

    Example:
        >>> configure_ldp_interface(device, 'swp1')
    """

    log.info(
        f"Configuring LDP interface {interface} on {device.name}"
    )

    enabled_str = 'true' if ipv4_enabled else 'false'
    config = [
        f'{_LDP_CTX} interface-attributes interface {interface}',
        'link-hello true',
        'address-family IPV4',
        f'enabled {enabled_str}',
        '!',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP interface {interface} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_ldp_interface(device, interface):
    """Remove LDP configuration from an interface.

    Args:
        device (obj): Device object.
        interface (str): Interface name (e.g., 'swp1').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP interface config.

    Example:
        >>> unconfigure_ldp_interface(device, 'swp1')
    """

    log.info(
        f"Removing LDP interface {interface} from {device.name}"
    )

    config = [
        f'no {_LDP_CTX} interface-attributes interface {interface}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP interface {interface} from "
            f"{device.name}. Error:\n{e}"
        )


# =====================================================================
# Targeted
# =====================================================================

def configure_ldp_targeted(device, hello_accept=True, hello_holdtime=45,
                           hello_interval=15, strict=None):
    """Configure LDP targeted hello global settings.

    Args:
        device (obj): Device object.
        hello_accept (bool, optional): Accept targeted hellos. Defaults to True.
        hello_holdtime (int, optional): Targeted hello hold time. Defaults to 45.
        hello_interval (int, optional): Targeted hello interval. Defaults to 15.
        strict (bool, optional): Strict targeted hellos. Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP targeted.

    Example:
        >>> configure_ldp_targeted(device, hello_accept=True, hello_holdtime=45)
    """

    log.info(f"Configuring LDP targeted hellos on {device.name}")

    accept_str = 'true' if hello_accept else 'false'
    config = [
        f'{_LDP_CTX} targeted hello-accept {accept_str}',
        f'{_LDP_CTX} targeted hello-holdtime {hello_holdtime}',
        f'{_LDP_CTX} targeted hello-interval {hello_interval}',
    ]

    if strict is not None:
        strict_str = 'true' if strict else 'false'
        config.append(
            f'{_LDP_CTX} targeted strict-targeted-hellos {strict_str}'
        )

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP targeted on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_ldp_targeted(device):
    """Remove LDP targeted hello configuration.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP targeted config.

    Example:
        >>> unconfigure_ldp_targeted(device)
    """

    log.info(f"Removing LDP targeted config from {device.name}")

    config = [
        f'no {_LDP_CTX} targeted hello-accept',
        f'no {_LDP_CTX} targeted hello-holdtime',
        f'no {_LDP_CTX} targeted hello-interval',
        f'no {_LDP_CTX} targeted strict-targeted-hellos',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP targeted from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# Neighbor
# =====================================================================

def configure_ldp_neighbor(device, lsr_id, label_space_id=0,
                           targeted_ipv4=True, targeted_ipv4_dest=None):
    """Configure an LDP neighbor with targeted hellos.

    Args:
        device (obj): Device object.
        lsr_id (str): Neighbor LSR-ID (IPv4 address).
        label_space_id (int, optional): Label space ID. Defaults to 0.
        targeted_ipv4 (bool, optional): Enable IPv4 targeted hellos.
            Defaults to True.
        targeted_ipv4_dest (str, optional): IPv4 destination for targeted
            hellos. Defaults to None (uses LSR-ID).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP neighbor.

    Example:
        >>> configure_ldp_neighbor(device, '1.1.1.1')
    """

    log.info(
        f"Configuring LDP neighbor {lsr_id} {label_space_id} on "
        f"{device.name}"
    )

    config = [
        f'{_LDP_CTX} neighbor {lsr_id} {label_space_id}',
    ]

    if targeted_ipv4:
        config.append('targeted address-family IPV4')
        config.append('enabled true')
        if targeted_ipv4_dest:
            config.append(f'destination-address {targeted_ipv4_dest}')
        config.append('!')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP neighbor {lsr_id} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_ldp_neighbor(device, lsr_id, label_space_id=0):
    """Remove an LDP neighbor configuration.

    Args:
        device (obj): Device object.
        lsr_id (str): Neighbor LSR-ID (IPv4 address).
        label_space_id (int, optional): Label space ID. Defaults to 0.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP neighbor.

    Example:
        >>> unconfigure_ldp_neighbor(device, '1.1.1.1')
    """

    log.info(
        f"Removing LDP neighbor {lsr_id} {label_space_id} from "
        f"{device.name}"
    )

    config = [
        f'no {_LDP_CTX} neighbor {lsr_id} {label_space_id}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP neighbor {lsr_id} from "
            f"{device.name}. Error:\n{e}"
        )


# =====================================================================
# Authentication
# =====================================================================

def configure_ldp_authentication(device, auth_key, lsr_id=None,
                                 label_space_id=0):
    """Configure LDP MD5 authentication (global or per-neighbor).

    Args:
        device (obj): Device object.
        auth_key (str): MD5 authentication key.
        lsr_id (str, optional): Neighbor LSR-ID for per-neighbor auth.
            If None, configures global auth. Defaults to None.
        label_space_id (int, optional): Label space ID. Defaults to 0.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP authentication.

    Example:
        >>> configure_ldp_authentication(device, 'mykey123')
        >>> configure_ldp_authentication(device, 'peerkey', lsr_id='1.1.1.1')
    """

    if lsr_id:
        log.info(
            f"Configuring LDP per-neighbor auth for {lsr_id} on "
            f"{device.name}"
        )
        config = [
            f'{_LDP_CTX} neighbor {lsr_id} {label_space_id}',
            'authentication enable true',
            f'authentication authentication-key {auth_key}',
            '!',
        ]
    else:
        log.info(
            f"Configuring LDP global auth on {device.name}"
        )
        config = [
            f'{_LDP_CTX} global authentication enable true',
            f'{_LDP_CTX} global authentication authentication-key {auth_key}',
            '!',
        ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP authentication on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_ldp_authentication(device, lsr_id=None, label_space_id=0):
    """Remove LDP MD5 authentication (global or per-neighbor).

    Args:
        device (obj): Device object.
        lsr_id (str, optional): Neighbor LSR-ID for per-neighbor auth.
            If None, removes global auth. Defaults to None.
        label_space_id (int, optional): Label space ID. Defaults to 0.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP authentication.

    Example:
        >>> unconfigure_ldp_authentication(device)
        >>> unconfigure_ldp_authentication(device, lsr_id='1.1.1.1')
    """

    if lsr_id:
        log.info(
            f"Removing LDP per-neighbor auth for {lsr_id} on "
            f"{device.name}"
        )
        config = [
            f'{_LDP_CTX} neighbor {lsr_id} {label_space_id}',
            'authentication enable false',
            'no authentication authentication-key',
            '!',
        ]
    else:
        log.info(f"Removing LDP global auth from {device.name}")
        config = [
            f'{_LDP_CTX} global authentication enable false',
            f'no {_LDP_CTX} global authentication authentication-key',
            '!',
        ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP authentication from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# RIB Preference
# =====================================================================

def configure_ldp_rib_preference(device, preference):
    """Set LDP RIB route preference.

    Args:
        device (obj): Device object.
        preference (int): Preference value (1-255).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP rib-preference.

    Example:
        >>> configure_ldp_rib_preference(device, 20)
    """

    log.info(
        f"Configuring LDP rib-preference {preference} on {device.name}"
    )

    config = [
        f'{_LDP_CTX} global rib-preference {preference}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP rib-preference on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_ldp_rib_preference(device):
    """Remove LDP RIB preference configuration.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP rib-preference.

    Example:
        >>> unconfigure_ldp_rib_preference(device)
    """

    log.info(f"Removing LDP rib-preference from {device.name}")

    config = [
        f'no {_LDP_CTX} global rib-preference',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP rib-preference from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# Session Protection
# =====================================================================

def configure_ldp_session_protection(device, duration):
    """Set LDP session protection timer.

    Args:
        device (obj): Device object.
        duration (int): Session protection timer in seconds (0 = infinite).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LDP session-protection.

    Example:
        >>> configure_ldp_session_protection(device, 60)
    """

    log.info(
        f"Configuring LDP session-protection {duration} on {device.name}"
    )

    config = [
        f'{_LDP_CTX} global session-protection {duration}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LDP session-protection on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_ldp_session_protection(device):
    """Remove LDP session protection configuration.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LDP session-protection.

    Example:
        >>> unconfigure_ldp_session_protection(device)
    """

    log.info(
        f"Removing LDP session-protection from {device.name}"
    )

    config = [
        f'no {_LDP_CTX} global session-protection',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LDP session-protection from "
            f"{device.name}. Error:\n{e}"
        )
