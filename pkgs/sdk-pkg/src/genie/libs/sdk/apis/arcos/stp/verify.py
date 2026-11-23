"""ArcOS STP verify APIs.

Verification helpers built on top of the ArcOS STP get APIs in
``genie.libs.sdk.apis.arcos.stp.get``.

These functions poll the device for a bounded amount of time and return a
boolean result. They call the STP get APIs only -- never ``device.parse``.

The whole verifiable surface is the three scalars exposed by
``genie.libs.parser.arcos.show_stp.ShowStpGlobal`` (``enabled-protocol``,
``bpdu-guard``, ``bridge-assurance``). Per-interface and per-VLAN STP state
(``show stp interface``, ``show stp rapid-pvst``) has no parser yet and
therefore has no verify API here.
"""

from __future__ import annotations

import logging
from typing import Optional

from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.stp.get import (
    get_stp_global,
    get_stp_enabled_protocol,
)

log = logging.getLogger(__name__)


def _get_stp_global_flag(device, key: str) -> Optional[bool]:
    """Read one boolean flag out of the STP global state.

    Args:
        device: pyATS device object.
        key: JSON key to read -- ``"bpdu-guard"`` or ``"bridge-assurance"``.

    Returns:
        The flag value as a ``bool``, or ``None`` when the key is absent or
        the STP global state could not be retrieved.

    Example:
        >>> _get_stp_global_flag(device, "bpdu-guard")
        False
    """

    data = get_stp_global(device)
    if not data:
        return None

    value = data.get(key)
    if value is None:
        return None

    return bool(value)


def verify_stp_enabled_protocol(
    device,
    expected_protocol: str = "RAPID_PVST",
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify the globally enabled STP protocol.

    This uses :func:`get_stp_enabled_protocol` to poll the device. The
    comparison is case-insensitive.

    The default of ``"RAPID_PVST"`` is the arcOS default that
    ``no stp enabled-protocol`` restores, so a zero-argument call is the
    natural post-unconfigure check.

    Args:
        device: pyATS device object.
        expected_protocol: Expected ``enabled-protocol`` value, for example
            ``"RAPID_PVST"`` or ``"NONE"``.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the enabled protocol matches within the timeout,
        False otherwise.
    """

    timeout = Timeout(max_time, check_interval)
    expected_upper = expected_protocol.upper()

    while timeout.iterate():
        try:
            protocol: Optional[str] = get_stp_enabled_protocol(device)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("get_stp_enabled_protocol failed: %s", exc)
            protocol = None

        log.debug(
            "verify_stp_enabled_protocol(): current=%s, expected=%s",
            protocol,
            expected_upper,
        )

        if protocol is not None and str(protocol).upper() == expected_upper:
            return True

        timeout.sleep()

    return False


def verify_stp_disabled(
    device,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify that STP is globally disabled.

    arcOS disables spanning tree entirely by setting the global
    ``enabled-protocol`` to ``NONE``.

    Args:
        device: pyATS device object.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if STP is globally disabled within the timeout,
        False otherwise.
    """

    return verify_stp_enabled_protocol(
        device=device,
        expected_protocol="NONE",
        max_time=max_time,
        check_interval=check_interval,
    )


def verify_stp_bpdu_guard(
    device,
    expected_enabled: bool = True,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify the global STP BPDU guard setting.

    This uses :func:`_get_stp_global_flag` (and therefore
    :func:`get_stp_global`) to poll the device.

    Args:
        device: pyATS device object.
        expected_enabled: Expected state of the global ``bpdu-guard`` flag.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the flag matches ``expected_enabled`` within the timeout,
        False otherwise. Absent or unreadable state never matches -- in
        particular it is NOT treated as "disabled" when ``expected_enabled``
        is False.
    """

    timeout = Timeout(max_time, check_interval)
    expected = bool(expected_enabled)

    while timeout.iterate():
        try:
            current: Optional[bool] = _get_stp_global_flag(
                device, "bpdu-guard"
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error("_get_stp_global_flag failed for bpdu-guard: %s", exc)
            current = None

        log.debug(
            "verify_stp_bpdu_guard(): current=%s, expected=%s",
            current,
            expected,
        )

        if current is not None and current == expected:
            return True

        timeout.sleep()

    return False


def verify_stp_bridge_assurance(
    device,
    expected_enabled: bool = True,
    max_time: int = 60,
    check_interval: int = 10,
) -> bool:
    """Verify the global STP bridge assurance setting.

    This uses :func:`_get_stp_global_flag` (and therefore
    :func:`get_stp_global`) to poll the device.

    Args:
        device: pyATS device object.
        expected_enabled: Expected state of the global ``bridge-assurance``
            flag.
        max_time: Maximum time to wait (seconds).
        check_interval: Poll interval (seconds).

    Returns:
        True if the flag matches ``expected_enabled`` within the timeout,
        False otherwise. Absent or unreadable state never matches -- in
        particular it is NOT treated as "disabled" when ``expected_enabled``
        is False.
    """

    timeout = Timeout(max_time, check_interval)
    expected = bool(expected_enabled)

    while timeout.iterate():
        try:
            current: Optional[bool] = _get_stp_global_flag(
                device, "bridge-assurance"
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "_get_stp_global_flag failed for bridge-assurance: %s", exc
            )
            current = None

        log.debug(
            "verify_stp_bridge_assurance(): current=%s, expected=%s",
            current,
            expected,
        )

        if current is not None and current == expected:
            return True

        timeout.sleep()

    return False
