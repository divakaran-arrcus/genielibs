"""ArcOS FIB (Forwarding Information Base) get APIs.

High-level helpers built on top of the upstream ArcOS FIB parsers in
``genie.libs.parser.arcos.show_fib``.

These functions wrap ``device.parse("show network-instance ... fib ...")``
and return simplified dictionaries for common use cases.

FIB is not a protocol — there is no protocol context or
network-instance/protocol hierarchy.  Commands operate directly on a
network-instance and address family.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# -------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------


def _parse_fib_prefix_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
    prefix: Optional[str] = None,
) -> Dict[str, Any]:
    """Wrap ``device.parse`` for ``ShowFibPrefixEntries``.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"``.
        ni: Network instance name.
        prefix: Optional specific prefix to filter.

    Returns:
        Parsed dict matching ``ShowFibPrefixEntriesSchema``, or ``{}`` on error.
    """
    af_upper = af.upper()
    entry_type = "ipv4-prefix-entry" if af_upper == "IPV4" else "ipv6-prefix-entry"
    cmd = f"show network-instance {ni} fib {af_upper} {entry_type}"
    if prefix:
        cmd += f" {prefix}"

    try:
        parsed = device.parse(cmd)
        return parsed
    except SchemaEmptyParserError:
        log.debug("_parse_fib_prefix_entries: no data for NI=%s AF=%s", ni, af_upper)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_fib_prefix_entries: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_fib_prefix_entries: unexpected error — %s", exc)
        return {}


def _parse_fib_nexthop_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
    index: Optional[int] = None,
) -> Dict[str, Any]:
    """Wrap ``device.parse`` for ``ShowFibNexthopEntries``.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"``.
        ni: Network instance name.
        index: Optional specific nexthop index to filter.

    Returns:
        Parsed dict matching ``ShowFibNexthopEntriesSchema``, or ``{}`` on error.
    """
    af_upper = af.upper()
    entry_type = "ipv4-nexthop-entry" if af_upper == "IPV4" else "ipv6-nexthop-entry"
    cmd = f"show network-instance {ni} fib {af_upper} {entry_type}"
    if index is not None:
        cmd += f" {index}"

    try:
        parsed = device.parse(cmd)
        return parsed
    except SchemaEmptyParserError:
        log.debug("_parse_fib_nexthop_entries: no data for NI=%s AF=%s", ni, af_upper)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_fib_nexthop_entries: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_fib_nexthop_entries: unexpected error — %s", exc)
        return {}


def _parse_fib_label_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
    label: Optional[str] = None,
) -> Dict[str, Any]:
    """Wrap ``device.parse`` for ``ShowFibLabelEntries``.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"``.
        ni: Network instance name.
        label: Optional specific label to filter.

    Returns:
        Parsed dict matching ``ShowFibLabelEntriesSchema``, or ``{}`` on error.
    """
    af_upper = af.upper()
    entry_type = "ipv4-label-entry" if af_upper == "IPV4" else "ipv6-label-entry"
    cmd = f"show network-instance {ni} fib {af_upper} {entry_type}"
    if label:
        cmd += f" {label}"

    try:
        parsed = device.parse(cmd)
        return parsed
    except SchemaEmptyParserError:
        log.debug("_parse_fib_label_entries: no data for NI=%s AF=%s", ni, af_upper)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_fib_label_entries: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_fib_label_entries: unexpected error — %s", exc)
        return {}


# -------------------------------------------------------------------
# Public API — Prefix entries
# -------------------------------------------------------------------


def get_fib_prefix_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> Dict[str, Any]:
    """Get all FIB prefix entries for a network-instance and address family.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict keyed by prefix containing prefix entry dicts.  Returns ``{}``
        if no entries are found or on any parse error.

    Example:
        >>> entries = get_fib_prefix_entries(device, af="IPV4")
        >>> for prefix, data in entries.items():
        ...     print(prefix, data.get("next-hop-id"))
    """
    parsed = _parse_fib_prefix_entries(device, af=af, ni=ni)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("prefix-entries", {})
    log.debug("get_fib_prefix_entries: found %d entries for NI=%s AF=%s", len(entries), ni, af)
    return entries


def get_fib_prefix_entry(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a single FIB prefix entry by prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix to look up (e.g. ``"5.5.5.5/32"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict with the prefix entry data, or ``None`` if the prefix is not
        found.

    Example:
        >>> entry = get_fib_prefix_entry(device, "10.0.0.0/24")
        >>> if entry:
        ...     print(entry.get("next-hop-id"))
    """
    parsed = _parse_fib_prefix_entries(device, af=af, ni=ni, prefix=prefix)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("prefix-entries", {})

    if prefix in entries:
        return entries[prefix]

    # Fallback: if parser returned a single entry (possibly normalized prefix)
    if len(entries) == 1:
        return next(iter(entries.values()))

    log.debug("get_fib_prefix_entry: prefix %s not found in FIB", prefix)
    return None


def get_fib_prefix_entry_count(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> int:
    """Get the total number of prefix entries in the FIB.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Count of FIB prefix entries, or ``0`` if none found.

    Example:
        >>> count = get_fib_prefix_entry_count(device, af="IPV4")
        >>> print(f"FIB has {count} IPv4 prefix entries")
    """
    entries = get_fib_prefix_entries(device, af=af, ni=ni)
    return len(entries)


def is_prefix_in_fib(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
) -> bool:
    """Check whether a prefix exists in the FIB.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check (e.g. ``"10.0.0.0/24"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        ``True`` if the prefix is present in the FIB, ``False`` otherwise.

    Example:
        >>> if is_prefix_in_fib(device, "10.0.0.0/24"):
        ...     print("Prefix is programmed in FIB")
    """
    entry = get_fib_prefix_entry(device, prefix, af=af, ni=ni)
    return entry is not None


# -------------------------------------------------------------------
# Public API — Nexthop entries
# -------------------------------------------------------------------


def get_fib_nexthop_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> Dict[str, Any]:
    """Get all FIB nexthop entries for a network-instance and address family.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict keyed by nexthop index containing nexthop entry dicts.  Returns
        ``{}`` if no entries are found or on any parse error.

    Example:
        >>> nexthops = get_fib_nexthop_entries(device, af="IPV4")
        >>> for idx, data in nexthops.items():
        ...     print(idx, data.get("paths"))
    """
    parsed = _parse_fib_nexthop_entries(device, af=af, ni=ni)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("nexthop-entries", {})
    log.debug(
        "get_fib_nexthop_entries: found %d entries for NI=%s AF=%s",
        len(entries), ni, af,
    )
    return entries


def get_fib_nexthop_entry(
    device,
    index: int,
    af: str = "IPV4",
    ni: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a single FIB nexthop entry by index.

    Args:
        device: pyATS device object.
        index: Nexthop index to look up (e.g. ``42``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict with the nexthop entry data, or ``None`` if the index is not
        found.

    Example:
        >>> entry = get_fib_nexthop_entry(device, 42)
        >>> if entry:
        ...     print(entry.get("paths"))
    """
    parsed = _parse_fib_nexthop_entries(device, af=af, ni=ni, index=index)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("nexthop-entries", {})

    # Try both int and str keys since parser may normalize differently
    for key in (index, str(index)):
        if key in entries:
            return entries[key]

    # Fallback: if parser returned a single entry (possibly normalized index)
    if len(entries) == 1:
        return next(iter(entries.values()))

    log.debug("get_fib_nexthop_entry: index %s not found in FIB", index)
    return None


def get_fib_nexthop_entry_count(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> int:
    """Get the total number of nexthop entries in the FIB.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Count of FIB nexthop entries, or ``0`` if none found.

    Example:
        >>> count = get_fib_nexthop_entry_count(device, af="IPV4")
        >>> print(f"FIB has {count} IPv4 nexthop entries")
    """
    entries = get_fib_nexthop_entries(device, af=af, ni=ni)
    return len(entries)


# -------------------------------------------------------------------
# Public API — Label entries
# -------------------------------------------------------------------


def get_fib_label_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> Dict[str, Any]:
    """Get all FIB MPLS label entries for a network-instance and address family.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict keyed by label containing label entry dicts.  Returns ``{}``
        if no entries are found or on any parse error.

    Example:
        >>> labels = get_fib_label_entries(device, af="IPV4")
        >>> for label, data in labels.items():
        ...     print(label, data.get("next-hop-id"), data.get("domain-name"))
    """
    parsed = _parse_fib_label_entries(device, af=af, ni=ni)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("label-entries", {})
    log.debug(
        "get_fib_label_entries: found %d label entries for NI=%s AF=%s",
        len(entries), ni, af,
    )
    return entries


def get_fib_label_entry(
    device,
    label: str,
    af: str = "IPV4",
    ni: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a single FIB MPLS label entry.

    Args:
        device: pyATS device object.
        label: MPLS label to look up (e.g. ``"10005"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict with the label entry data, or ``None`` if the label is not
        found.

    Example:
        >>> entry = get_fib_label_entry(device, "10005")
        >>> if entry:
        ...     print(entry.get("next-hop-id"), entry.get("domain-name"))
    """
    parsed = _parse_fib_label_entries(device, af=af, ni=ni, label=label)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("label-entries", {})

    if label in entries:
        return entries[label]

    # Fallback: if parser returned a single entry (possibly normalized label)
    if len(entries) == 1:
        return next(iter(entries.values()))

    log.debug("get_fib_label_entry: label %s not found in FIB", label)
    return None


def get_fib_label_entry_count(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> int:
    """Get the total number of MPLS label entries in the FIB.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Count of FIB label entries, or ``0`` if none found.

    Example:
        >>> count = get_fib_label_entry_count(device, af="IPV4")
        >>> print(f"FIB has {count} IPv4 label entries")
    """
    entries = get_fib_label_entries(device, af=af, ni=ni)
    return len(entries)
