"""ArcOS version get APIs.

Helpers built on top of the ArcOS ``show version`` parser.
"""

import logging
from typing import Any, Dict, Optional

from genie.metaparser.util.exceptions import SchemaEmptyParserError

log = logging.getLogger(__name__)


def get_version_info(device) -> Dict[str, Any]:
    """Return the ArcOS ``version`` dictionary from ``show version``.

    The ArcOS ``ShowVersion`` parser returns a top-level ``"version"`` key
    containing fields like ``software``, ``platform``, ``cpu_info``,
    ``total_memory``, ``uptime``, and ``version``.

    Args:
        device: pyATS/Unicon device object.

    Returns:
        Dict with the contents of the ``version`` block, or an empty dict
        if parsing fails or the output is empty.
    """

    try:
        out = device.parse("show version")
    except SchemaEmptyParserError:
        log.info("Command 'show version' returned no data")
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse 'show version': %s", exc)
        return {}

    info = out.get("version", {}) or {}
    if not isinstance(info, dict):
        log.error("Unexpected 'version' structure in parsed show version: %r", info)
        return {}

    return info


def get_software_version(device) -> Optional[str]:
    """Return the ArcOS software version string from ``show version``.

    This is a convenience wrapper over :func:`get_version_info` that
    extracts the ``version`` field (for example, ``"8.2.1A"``).

    Args:
        device: pyATS/Unicon device object.

    Returns:
        The software version string, or ``None`` if it cannot be
        determined.
    """

    info = get_version_info(device)
    ver = info.get("version") if isinstance(info, dict) else None

    if not ver:
        log.info("Software version not found in parsed 'show version' output")
        return None

    if not isinstance(ver, str):
        log.error("Unexpected type for software version: %r", ver)
        return None

    return ver
