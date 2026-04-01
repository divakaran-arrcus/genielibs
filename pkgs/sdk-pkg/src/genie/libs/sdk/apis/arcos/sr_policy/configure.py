"""Common configure functions for SR-Policy on ArcOS.

All SR-Policy commands are under:
    network-instance default sr-policy ...

Note: SR-Policy is only supported in the default network-instance.
"""

# Python
import logging

# Unicon
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_NI = 'network-instance default'


# =====================================================================
# Segment List
# =====================================================================

def configure_sr_policy_segment_list(device, name, segments):
    """Create an SR-Policy segment-list with segments.

    Args:
        device (obj): Device object.
        name (str): Segment-list name (e.g., 'sl1').
        segments (list): List of segment dicts, each with:
            - index (int): Segment index
            - type (str): MPLS_LABEL or SRV6_SID
            - mpls_label (int, optional): MPLS label value
            - srv6_sid (str, optional): SRv6 SID value
            - validate (bool, optional): Validate this segment

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure segment-list.

    Example:
        >>> configure_sr_policy_segment_list(device, 'sl1', [
        ...     {'index': 1, 'type': 'MPLS_LABEL', 'mpls_label': 100000},
        ...     {'index': 2, 'type': 'MPLS_LABEL', 'mpls_label': 100001},
        ... ])
    """

    log.info(
        f"Configuring SR-Policy segment-list {name} on {device.name}"
    )

    config = [f'{_NI} sr-policy segment-list {name}']

    for seg in segments:
        idx = seg.get("index")
        if idx is None:
            continue

        config.append(f'segment {idx}')

        seg_type = seg.get("type")
        if seg_type:
            config.append(f'type {seg_type}')

        mpls_label = seg.get("mpls_label")
        if mpls_label is not None:
            config.append(f'mpls-label {mpls_label}')

        srv6_sid = seg.get("srv6_sid")
        if srv6_sid:
            config.append(f'srv6-sid {srv6_sid}')

        validate = seg.get("validate")
        if validate is not None:
            config.append(
                f'validate {"true" if validate else "false"}'
            )

        config.append('!')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SR-Policy segment-list {name} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_sr_policy_segment_list(device, name):
    """Remove an SR-Policy segment-list.

    Args:
        device (obj): Device object.
        name (str): Segment-list name.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove segment-list.

    Example:
        >>> unconfigure_sr_policy_segment_list(device, 'sl1')
    """

    log.info(
        f"Removing SR-Policy segment-list {name} from {device.name}"
    )

    config = [
        f'no {_NI} sr-policy segment-list {name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SR-Policy segment-list {name} from "
            f"{device.name}. Error:\n{e}"
        )


# =====================================================================
# Dynamic Policy Color
# =====================================================================

def configure_sr_policy_dynamic_color(device, color, sid_algorithm):
    """Create a dynamic-policy-color mapping to a flex-algo.

    Args:
        device (obj): Device object.
        color (int): Color value.
        sid_algorithm (int): Flexible algorithm ID.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure dynamic-policy-color.

    Example:
        >>> configure_sr_policy_dynamic_color(device, 100, 128)
    """

    log.info(
        f"Configuring SR-Policy dynamic-policy-color {color} "
        f"sid-algorithm {sid_algorithm} on {device.name}"
    )

    config = [
        f'{_NI} sr-policy dynamic-policy-color {color}',
        f'dynamic constraints segment-rules sid-algorithm {sid_algorithm}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SR-Policy dynamic-policy-color "
            f"{color} on {device.name}. Error:\n{e}"
        )


def unconfigure_sr_policy_dynamic_color(device, color):
    """Remove a dynamic-policy-color.

    Args:
        device (obj): Device object.
        color (int): Color value.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove dynamic-policy-color.

    Example:
        >>> unconfigure_sr_policy_dynamic_color(device, 100)
    """

    log.info(
        f"Removing SR-Policy dynamic-policy-color {color} from "
        f"{device.name}"
    )

    config = [
        f'no {_NI} sr-policy dynamic-policy-color {color}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SR-Policy dynamic-policy-color "
            f"{color} from {device.name}. Error:\n{e}"
        )


# =====================================================================
# Policy
# =====================================================================

def configure_sr_policy_policy(device, endpoint, color, name=None,
                               candidate_paths=None):
    """Create an SR-Policy with optional candidate paths.

    Args:
        device (obj): Device object.
        endpoint (str): Policy endpoint (IP address).
        color (int): Policy color.
        name (str, optional): Administrative name.
        candidate_paths (list, optional): List of candidate path dicts,
            each with: discriminator, preference, type,
            explicit_segment_list, dynamic_dataplane,
            dynamic_sid_algorithm.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure policy.

    Example:
        >>> configure_sr_policy_policy(device, '2.2.2.2', 100,
        ...     name='test-pol',
        ...     candidate_paths=[{
        ...         'discriminator': 10,
        ...         'preference': 200,
        ...         'type': 'EXPLICIT_SEGMENT_LIST',
        ...         'explicit_segment_list': 'sl1',
        ...     }])
    """

    log.info(
        f"Configuring SR-Policy policy {endpoint} {color} on "
        f"{device.name}"
    )

    config = [f'{_NI} sr-policy policy {endpoint} {color}']

    if name:
        config.append(f'name {name}')

    config.append('enabled true')

    if candidate_paths:
        for cp in candidate_paths:
            disc = cp.get("discriminator")
            if disc is None:
                continue

            config.append(f'candidate-path {disc}')

            pref = cp.get("preference")
            if pref is not None:
                config.append(f'preference {pref}')

            path_type = cp.get("type")
            if path_type:
                config.append(f'type {path_type}')

            # Explicit
            exp_sl = cp.get("explicit_segment_list")
            if exp_sl:
                config.append(f'explicit segment-list {exp_sl}')

            # Dynamic
            dp = cp.get("dynamic_dataplane")
            if dp:
                config.append(f'dynamic dataplane {dp}')

            algo = cp.get("dynamic_sid_algorithm")
            if algo is not None:
                config.append(
                    f'dynamic constraints segment-rules '
                    f'sid-algorithm {algo}'
                )

            config.append('!')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure SR-Policy policy {endpoint} {color} "
            f"on {device.name}. Error:\n{e}"
        )


def unconfigure_sr_policy_policy(device, endpoint, color):
    """Remove an SR-Policy.

    Args:
        device (obj): Device object.
        endpoint (str): Policy endpoint.
        color (int): Policy color.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove policy.

    Example:
        >>> unconfigure_sr_policy_policy(device, '2.2.2.2', 100)
    """

    log.info(
        f"Removing SR-Policy policy {endpoint} {color} from "
        f"{device.name}"
    )

    config = [
        f'no {_NI} sr-policy policy {endpoint} {color}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SR-Policy policy {endpoint} {color} "
            f"from {device.name}. Error:\n{e}"
        )


# =====================================================================
# Policy Enabled
# =====================================================================

def configure_sr_policy_enabled(device, endpoint, color, enabled=True):
    """Enable or disable an SR-Policy.

    Args:
        device (obj): Device object.
        endpoint (str): Policy endpoint.
        color (int): Policy color.
        enabled (bool, optional): True to enable, False to disable.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure policy enabled.

    Example:
        >>> configure_sr_policy_enabled(device, '2.2.2.2', 100, enabled=False)
    """

    enabled_str = 'true' if enabled else 'false'
    log.info(
        f"Setting SR-Policy {endpoint} {color} enabled={enabled_str} "
        f"on {device.name}"
    )

    config = [
        f'{_NI} sr-policy policy {endpoint} {color}',
        f'enabled {enabled_str}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not set SR-Policy {endpoint} {color} enabled on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_sr_policy_enabled(device, endpoint, color):
    """Remove enabled config from an SR-Policy.

    Args:
        device (obj): Device object.
        endpoint (str): Policy endpoint.
        color (int): Policy color.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove policy enabled config.

    Example:
        >>> unconfigure_sr_policy_enabled(device, '2.2.2.2', 100)
    """

    log.info(
        f"Removing SR-Policy {endpoint} {color} enabled config from "
        f"{device.name}"
    )

    config = [
        f'{_NI} sr-policy policy {endpoint} {color}',
        'no enabled',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove SR-Policy {endpoint} {color} enabled "
            f"from {device.name}. Error:\n{e}"
        )
