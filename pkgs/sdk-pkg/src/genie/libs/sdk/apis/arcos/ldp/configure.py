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


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-06 — LDP attributes, bindings and hello timers
# (arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md)
#
# Paths confirmed by `?` capture on rtr1 2026-08-17. `_LDP_CTX` is a one-line
# PATH PREFIX, not a submode you enter — every line below is a full path, which
# is this file's existing convention.
#
# Note `global fec-filter` has TWO leaves: `default-export-policy` (already
# covered by configure_ldp_global) and `export-policy` (this batch).
# ---------------------------------------------------------------------------


def _ldp_hello_lines(prefix, hello_holdtime, hello_interval):
    """Build `<prefix> hello-holdtime/hello-interval` lines.

    Raises ``ValueError`` - not ``SubCommandFailure`` - when neither timer is
    given. This is a caller-side programming error caught before the device is
    touched, so it is deliberately a different class from the device-failure
    path that every other error site in this module raises. It is raised inside
    the caller's ``try:`` but escapes the ``except SubCommandFailure``, which is
    the intended behaviour.
    """
    if hello_holdtime is None and hello_interval is None:
        raise ValueError(
            "at least one of 'hello_holdtime' or 'hello_interval' is required")
    lines = []
    if hello_holdtime is not None:
        lines.append(f'{prefix} hello-holdtime {hello_holdtime}')
    if hello_interval is not None:
        lines.append(f'{prefix} hello-interval {hello_interval}')
    return lines


def configure_ldp_fec_filter_export_policy(device, policy):
    """Configure LDP global fec-filter export-policy.

    ``policy`` is a policy name or a list of names. Distinct from the
    ``default-export-policy`` leaf that :func:`configure_ldp_global` sets.
    """
    log.info(f"Configuring LDP global fec-filter export-policy on {device.name}")
    names = ' '.join(str(p) for p in policy) \
        if isinstance(policy, (list, tuple)) else policy
    try:
        device.configure([
            f'{_LDP_CTX} global fec-filter export-policy [ {names} ]',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP global fec-filter export-policy failed on {device.name}: {e}"
        )


def unconfigure_ldp_fec_filter_export_policy(device):
    """Remove LDP global fec-filter export-policy."""
    log.info(f"Removing LDP global fec-filter export-policy from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} global fec-filter export-policy', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP global fec-filter export-policy failed on {device.name}: {e}"
        )


def configure_ldp_attributes_php_enable(device, enabled=True):
    """Configure LDP global attributes php-enable."""
    log.info(f"Configuring LDP global attributes php-enable on {device.name}")
    try:
        device.configure([
            f'{_LDP_CTX} global attributes php-enable {str(enabled).lower()}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP global attributes php-enable failed on {device.name}: {e}"
        )


def unconfigure_ldp_attributes_php_enable(device):
    """Remove LDP global attributes php-enable."""
    log.info(f"Removing LDP global attributes php-enable from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} global attributes php-enable', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP global attributes php-enable failed on {device.name}: {e}"
        )


def configure_ldp_attributes_label_distribution_mode(device, mode):
    """Configure LDP global attributes label-distribution-mode.

    ``mode`` is passed through; arcOS rejects an unknown value outright
    (verified on rtr1 2026-08-17), so no Python allow-list is imposed.
    """
    log.info(f"Configuring LDP global attributes label-distribution-mode on {device.name}")
    try:
        device.configure([
            f'{_LDP_CTX} global attributes label-distribution-mode {mode}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP global attributes label-distribution-mode failed on {device.name}: {e}"
        )


def unconfigure_ldp_attributes_label_distribution_mode(device):
    """Remove LDP global attributes label-distribution-mode."""
    log.info(f"Removing LDP global attributes label-distribution-mode from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} global attributes label-distribution-mode', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP global attributes label-distribution-mode failed on {device.name}: {e}"
        )


def configure_ldp_attributes_post_session_up_delay(device, delay):
    """Configure LDP global attributes post-session-up-delay."""
    log.info(f"Configuring LDP global attributes post-session-up-delay on {device.name}")
    try:
        device.configure([
            f'{_LDP_CTX} global attributes post-session-up-delay {delay}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP global attributes post-session-up-delay failed on {device.name}: {e}"
        )


def unconfigure_ldp_attributes_post_session_up_delay(device):
    """Remove LDP global attributes post-session-up-delay."""
    log.info(f"Removing LDP global attributes post-session-up-delay from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} global attributes post-session-up-delay', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP global attributes post-session-up-delay failed on {device.name}: {e}"
        )


def configure_ldp_maximum_local_binding(device, maximum):
    """Configure LDP global maximum-local-binding."""
    log.info(f"Configuring LDP global maximum-local-binding on {device.name}")
    try:
        device.configure([
            f'{_LDP_CTX} global maximum-local-binding {maximum}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP global maximum-local-binding failed on {device.name}: {e}"
        )


def unconfigure_ldp_maximum_local_binding(device):
    """Remove LDP global maximum-local-binding."""
    log.info(f"Removing LDP global maximum-local-binding from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} global maximum-local-binding', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP global maximum-local-binding failed on {device.name}: {e}"
        )


def configure_ldp_interface_attributes_hello(device, hello_holdtime=None, hello_interval=None):
    """Configure LDP global interface-attributes hello timers.

    Applies to ALL LDP interfaces. At least one timer must be given.
    The unconfigure clears hello-holdtime only; call
    :func:`unconfigure_ldp_interface_attributes_hello_interval` for the other.
    """
    log.info(f"Configuring LDP global interface-attributes hello timers on {device.name}")
    try:
        device.configure([
            *_ldp_hello_lines(f'{_LDP_CTX} interface-attributes', hello_holdtime, hello_interval),
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP global interface-attributes hello timers failed on {device.name}: {e}"
        )


def unconfigure_ldp_interface_attributes_hello(device):
    """Remove LDP global interface-attributes hello timers."""
    log.info(f"Removing LDP global interface-attributes hello timers from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} interface-attributes hello-holdtime', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP global interface-attributes hello timers failed on {device.name}: {e}"
        )


def unconfigure_ldp_interface_attributes_hello_interval(device):
    """Remove the LDP global interface-attributes hello-interval leaf.

    Deliberately has no ``configure_`` counterpart: the leaf is SET by
    :func:`configure_ldp_interface_attributes_hello` (``hello_interval=``), whose
    own unconfigure clears only ``hello-holdtime``. This exists so the
    hello-interval leaf has an inverse without a second way to set it.
    """
    log.info(f"Removing LDP global interface-attributes hello-interval from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} interface-attributes hello-interval', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP global interface-attributes hello-interval failed on {device.name}: {e}"
        )


def configure_ldp_interface_hello(device, interface, hello_holdtime=None, hello_interval=None):
    """Configure LDP per-interface hello timers.

    Per-interface override of the global interface-attributes timers.
    """
    log.info(f"Configuring LDP per-interface hello timers on {device.name}")
    try:
        device.configure([
            *_ldp_hello_lines(f'{_LDP_CTX} interface-attributes interface {interface}', hello_holdtime, hello_interval),
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP per-interface hello timers failed on {device.name}: {e}"
        )


def unconfigure_ldp_interface_hello(device, interface):
    """Remove LDP per-interface hello timers."""
    log.info(f"Removing LDP per-interface hello timers from {device.name}")
    try:
        device.configure([
            f'no {_LDP_CTX} interface-attributes interface {interface} hello-holdtime',
            f'no {_LDP_CTX} interface-attributes interface {interface} hello-interval',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP per-interface hello timers failed on {device.name}: {e}"
        )


def configure_ldp_neighbor_maximum_remote_binding(device, lsr_id, maximum, label_space_id=0):
    """Configure LDP neighbor maximum-remote-binding.

    The neighbor key is TWO tokens — ``{lsr_id} {label_space_id}`` — matching
    :func:`configure_ldp_neighbor`.
    """
    log.info(f"Configuring LDP neighbor maximum-remote-binding on {device.name}")
    try:
        device.configure([
            f'{_LDP_CTX} neighbor {lsr_id} {label_space_id} maximum-remote-binding {maximum}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP neighbor maximum-remote-binding failed on {device.name}: {e}"
        )


def unconfigure_ldp_neighbor_maximum_remote_binding(device, lsr_id, label_space_id=0):
    """Remove LDP neighbor maximum-remote-binding."""
    log.info(f"Removing LDP neighbor maximum-remote-binding from {device.name}")
    try:
        device.configure([f'no {_LDP_CTX} neighbor {lsr_id} {label_space_id} maximum-remote-binding', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP neighbor maximum-remote-binding failed on {device.name}: {e}"
        )


def configure_ldp_neighbor_targeted_hello(device, lsr_id, hello_holdtime=None, hello_interval=None, label_space_id=0):
    """Configure LDP neighbor targeted hello timers.

    Per-neighbour override of the global ``targeted`` hello timers that
    :func:`configure_ldp_targeted` sets.
    """
    log.info(f"Configuring LDP neighbor targeted hello timers on {device.name}")
    try:
        device.configure([
            *_ldp_hello_lines(f'{_LDP_CTX} neighbor {lsr_id} {label_space_id} targeted', hello_holdtime, hello_interval),
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"LDP neighbor targeted hello timers failed on {device.name}: {e}"
        )


def unconfigure_ldp_neighbor_targeted_hello(device, lsr_id, label_space_id=0):
    """Remove LDP neighbor targeted hello timers."""
    log.info(f"Removing LDP neighbor targeted hello timers from {device.name}")
    try:
        device.configure([
            f'no {_LDP_CTX} neighbor {lsr_id} {label_space_id} targeted hello-holdtime',
            f'no {_LDP_CTX} neighbor {lsr_id} {label_space_id} targeted hello-interval',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing LDP neighbor targeted hello timers failed on {device.name}: {e}"
        )
