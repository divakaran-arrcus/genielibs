"""ArcOS interface get APIs.

High-level helpers built on top of the upstream ArcOS interface parser
``genie.libs.parser.arcos.show_interface.ShowInterface``.

These functions wrap ``device.parse("show interface ...")`` and return
simple Python data structures for common use cases.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from genie.metaparser.util.exceptions import SchemaEmptyParserError

log = logging.getLogger(__name__)


def _parse_interfaces(device, interface: Optional[str] = None) -> Dict[str, Any]:
    """Internal helper to run the ArcOS ShowInterface parser via device.parse.

    Args:
        device: pyATS device object.
        interface: Optional interface name. If provided, only that interface
            is queried; otherwise, all interfaces are returned.

    Returns:
        Parsed dict keyed by interface name -> interface info.
    """

    try:
        if interface:
            parsed = device.parse(f"show interface {interface}")
        else:
            parsed = device.parse("show interface")
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse ArcOS show interface: %s", exc)
        return {}

    # ArcOS ShowInterface returns a flat dict keyed by interface name.
    return parsed or {}


def get_interface_status(device, interface: str) -> Optional[str]:
    """Get ArcOS interface operational status.

    Returns one of ``"up"``, ``"down"``, ``"admin-down"``, or ``None`` if
    the interface is not found.
    """

    intfs = _parse_interfaces(device, interface=interface)
    data = intfs.get(interface)
    if not data:
        return None

    admin_status = str(data.get("admin-status", "")).upper()
    oper_status = str(data.get("oper-status", "")).upper()

    if admin_status == "DOWN" or not data.get("enabled", True):
        return "admin-down"
    if oper_status == "UP":
        return "up"
    return "down"


def get_interface_information(device, interface: str) -> Optional[Dict[str, Any]]:
    """Get detailed ArcOS interface information for a single interface.

    Returns the per-interface dictionary from the ArcOS ShowInterface parser,
    or ``None`` if the interface is not present.
    """

    intfs = _parse_interfaces(device, interface=interface)
    return intfs.get(interface)


def is_interface_up(device, interface: str) -> bool:
    """Check if an ArcOS interface is operationally up."""

    status = get_interface_status(device, interface)
    return status == "up" if status is not None else False


def get_interface_mtu(device, interface: str) -> Optional[int]:
    """Get MTU for an ArcOS interface.

    Returns the ``mtu`` field from the parser output, or ``None`` if not
    available.
    """

    info = get_interface_information(device, interface)
    if not info:
        return None
    return info.get("mtu")


def get_interfaces(device) -> Dict[str, Any]:
    """Get all ArcOS interfaces.

    Returns a dict of ``{interface_name: interface_info}`` using the
    upstream ArcOS parser.
    """

    return _parse_interfaces(device)


def get_interface_names(device) -> List[str]:
    """Get list of all ArcOS interface names."""

    intfs = get_interfaces(device)
    return list(intfs.keys()) if intfs else []


def get_interface_description(device, interface: str) -> Optional[str]:
    """Get description for an ArcOS interface.

    Args:
        device: pyATS device object.
        interface: Interface name (e.g., 'swp1', 'loopback0').

    Returns:
        Description string, or None if not found.
    """

    info = get_interface_information(device, interface)
    if not info:
        return None
    return info.get("description")


def get_interface_ipv4_addresses(
    device, interface: str
) -> Dict[str, Any]:
    """Get all IPv4 addresses for an ArcOS interface.

    Args:
        device: pyATS device object.
        interface: Interface name.

    Returns:
        Dict keyed by IP address with prefix-length.
        Empty dict if none found.
    """

    info = get_interface_information(device, interface)
    if not info:
        return {}
    return info.get("ipv4-addresses", {})


def get_interface_ipv4_address(
    device, interface: str
) -> Optional[str]:
    """Get the first IPv4 address for an ArcOS interface.

    Args:
        device: pyATS device object.
        interface: Interface name.

    Returns:
        IPv4 address string (e.g., '1.1.1.1'), or None if not found.
    """

    addrs = get_interface_ipv4_addresses(device, interface)
    if not addrs:
        return None
    return next(iter(addrs.keys()))


def get_interface_ipv6_addresses(
    device, interface: str
) -> Dict[str, Any]:
    """Get all IPv6 addresses for an ArcOS interface.

    Args:
        device: pyATS device object.
        interface: Interface name.

    Returns:
        Dict keyed by IPv6 address with prefix-length.
        Empty dict if none found.
    """

    info = get_interface_information(device, interface)
    if not info:
        return {}
    return info.get("ipv6-addresses", {})
