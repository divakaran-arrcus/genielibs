"""Common configure functions for LAG (LACP/Bond) on ArcOS.

Bond interfaces are configured under ``interface bond<N>``.
Member interfaces are assigned via ``ethernet aggregate-id bond<N>``.
"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# =====================================================================
# Bond
# =====================================================================

def configure_lag_bond(device, bond, lag_type='LACP', min_links=None):
    """Create a bond interface with lag-type and optional min-links.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name (e.g., 'bond10').
        lag_type (str, optional): Aggregation type — LACP or STATIC.
            Defaults to 'LACP'.
        min_links (int, optional): Minimum links for bond to be up.
            Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure bond interface.

    Example:
        >>> configure_lag_bond(device, 'bond10', lag_type='LACP', min_links=2)
    """

    log.info(
        f"Configuring {bond} (lag-type={lag_type}) on {device.name}"
    )

    config = [
        f'interface {bond}',
        'enabled true',
        f'aggregation lag-type {lag_type}',
    ]

    if min_links is not None:
        config.append(f'aggregation min-links {min_links}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure {bond} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_lag_bond(device, bond):
    """Remove a bond interface.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name (e.g., 'bond10').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove bond interface.

    Example:
        >>> unconfigure_lag_bond(device, 'bond10')
    """

    log.info(f"Removing {bond} from {device.name}")

    config = [
        f'no interface {bond}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove {bond} from {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# Member
# =====================================================================

def configure_lag_member(device, member, bond):
    """Assign a member interface to a bond.

    Args:
        device (obj): Device object.
        member (str): Member interface name (e.g., 'swp10').
        bond (str): Bond interface name (e.g., 'bond10').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to assign member to bond.

    Example:
        >>> configure_lag_member(device, 'swp10', 'bond10')
    """

    log.info(
        f"Assigning {member} to {bond} on {device.name}"
    )

    config = [
        f'interface {member}',
        'enabled true',
        f'ethernet aggregate-id {bond}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not assign {member} to {bond} on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_lag_member(device, member):
    """Remove a member interface from its bond.

    Args:
        device (obj): Device object.
        member (str): Member interface name (e.g., 'swp10').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove member from bond.

    Example:
        >>> unconfigure_lag_member(device, 'swp10')
    """

    log.info(
        f"Removing {member} aggregate-id from {device.name}"
    )

    config = [
        f'interface {member}',
        'no ethernet aggregate-id',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove {member} aggregate-id on {device.name}. "
            f"Error:\n{e}"
        )


# =====================================================================
# Fallback
# =====================================================================

def configure_lag_fallback(device, bond, mode='INDIVIDUAL',
                           timeout=None, primary=None):
    """Configure LACP fallback on a bond interface.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name (e.g., 'bond1').
        mode (str, optional): Fallback mode. Defaults to 'INDIVIDUAL'.
        timeout (int, optional): Fallback timeout in seconds.
            Defaults to None.
        primary (str, optional): Primary interface for fallback.
            Defaults to None.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LACP fallback.

    Example:
        >>> configure_lag_fallback(device, 'bond1', timeout=100, primary='swp3')
    """

    log.info(
        f"Configuring LACP fallback on {bond} on {device.name}"
    )

    config = [
        f'interface {bond}',
        f'aggregation lacp fallback mode {mode}',
    ]

    if timeout is not None:
        config.append(f'aggregation lacp fallback timeout {timeout}')

    if primary is not None:
        config.append(
            f'aggregation lacp fallback primary-interface {primary}'
        )

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LACP fallback on {bond} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_lag_fallback(device, bond):
    """Remove LACP fallback configuration from a bond.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name (e.g., 'bond1').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LACP fallback.

    Example:
        >>> unconfigure_lag_fallback(device, 'bond1')
    """

    log.info(
        f"Removing LACP fallback from {bond} on {device.name}"
    )

    config = [
        f'interface {bond}',
        'no aggregation lacp fallback mode',
        'no aggregation lacp fallback timeout',
        'no aggregation lacp fallback primary-interface',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LACP fallback from {bond} on "
            f"{device.name}. Error:\n{e}"
        )


# =====================================================================
# L2 Trunk
# =====================================================================

def configure_lag_l2_trunk(device, bond, trunk_vlans):
    """Configure L2 trunk mode on a bond interface.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name (e.g., 'bond11').
        trunk_vlans (list): List of trunk VLAN IDs (e.g., [10, 20]).

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure L2 trunk on bond.

    Example:
        >>> configure_lag_l2_trunk(device, 'bond11', [10, 20])
    """

    log.info(
        f"Configuring L2 trunk on {bond} with VLANs {trunk_vlans} "
        f"on {device.name}"
    )

    if isinstance(trunk_vlans, (list, tuple)):
        vlan_str = ' '.join(str(v) for v in trunk_vlans)
    else:
        vlan_str = str(trunk_vlans)

    config = [
        f'interface {bond}',
        'aggregation switched-vlan interface-mode TRUNK',
        f'aggregation switched-vlan trunk-vlans [ {vlan_str} ]',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure L2 trunk on {bond} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_lag_l2_trunk(device, bond):
    """Remove L2 trunk configuration from a bond.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name (e.g., 'bond11').

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove L2 trunk from bond.

    Example:
        >>> unconfigure_lag_l2_trunk(device, 'bond11')
    """

    log.info(
        f"Removing L2 trunk from {bond} on {device.name}"
    )

    config = [
        f'interface {bond}',
        'no aggregation switched-vlan interface-mode',
        'no aggregation switched-vlan trunk-vlans',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove L2 trunk from {bond} on "
            f"{device.name}. Error:\n{e}"
        )


# =====================================================================
# LACP Interval
# =====================================================================

def configure_lacp_interval(device, bond, interval='FAST'):
    """Configure LACP interval on a bond interface.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name (e.g., 'bond111').
        interval (str, optional): LACP interval — FAST or SLOW.
            Defaults to 'FAST'.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure LACP interval.

    Example:
        >>> configure_lacp_interval(device, 'bond111', 'SLOW')
    """

    log.info(
        f"Configuring LACP interval {interval} on {bond} on {device.name}"
    )

    config = [
        f'lacp interface {bond}',
        f'interval {interval}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure LACP interval on {bond} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_lacp_interval(device, bond):
    """Remove LACP interval configuration from a bond.

    Args:
        device (obj): Device object.
        bond (str): Bond interface name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove LACP interval.

    Example:
        >>> unconfigure_lacp_interval(device, 'bond111')
    """

    log.info(
        f"Removing LACP interval from {bond} on {device.name}"
    )

    config = [
        f'no lacp interface {bond}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove LACP interval from {bond} on "
            f"{device.name}. Error:\n{e}"
        )
