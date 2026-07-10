"""ArcOS RIB (Routing Information Base) get APIs.

High-level helpers built on top of the upstream ArcOS RIB parsers in
``genie.libs.parser.arcos.show_rib``.

These functions wrap ``device.parse("show network-instance ... rib ...")``
and return simplified dictionaries for common use cases.

RIB is not a protocol — there is no protocol context or
network-instance/protocol hierarchy.  Commands operate directly on a
network-instance and address family.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


# -------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------


def _parse_rib_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
    prefix: Optional[str] = None,
) -> Dict[str, Any]:
    """Wrap ``device.parse`` for ``ShowRibEntries``.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"``.
        ni: Network instance name.
        prefix: Optional specific prefix to filter.

    Returns:
        Parsed dict matching ``_RibEntriesSchema``, or ``{}`` on error.
    """
    af_upper = af.upper()
    entry_type = "ipv4-entries" if af_upper == "IPV4" else "ipv6-entries"
    cmd = f"show network-instance {ni} rib {af_upper} {entry_type}"
    if prefix:
        cmd += f" entry {prefix}"

    try:
        parsed = device.parse(cmd)
        return parsed
    except SchemaEmptyParserError:
        log.debug("_parse_rib_entries: no data for NI=%s AF=%s", ni, af_upper)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_rib_entries: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_rib_entries: unexpected error — %s", exc)
        return {}


def _parse_rib_label_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
    label: Optional[str] = None,
) -> Dict[str, Any]:
    """Wrap ``device.parse`` for ``ShowRibLabelEntries``.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"``.
        ni: Network instance name.
        label: Optional specific label to filter.

    Returns:
        Parsed dict matching ``_RibLabelEntriesSchema``, or ``{}`` on error.
    """
    af_upper = af.upper()
    entry_type = "ipv4-label-entries" if af_upper == "IPV4" else "ipv6-label-entries"
    cmd = f"show network-instance {ni} rib {af_upper} {entry_type}"
    if label:
        cmd += f" entry {label}"

    try:
        parsed = device.parse(cmd)
        return parsed
    except SchemaEmptyParserError:
        log.debug("_parse_rib_label_entries: no data for NI=%s AF=%s", ni, af_upper)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_rib_label_entries: SubCommandFailure — %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_rib_label_entries: unexpected error — %s", exc)
        return {}


# -------------------------------------------------------------------
# Public API — Route entries
# -------------------------------------------------------------------


def get_rib_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> Dict[str, Any]:
    """Get all RIB route entries for a network-instance and address family.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict keyed by prefix containing route entry dicts.  Returns ``{}``
        if no entries are found or on any parse error.

    Example:
        >>> entries = get_rib_entries(device, af="IPV4")
        >>> for prefix, data in entries.items():
        ...     print(prefix, data.get("best-protocol"))
    """
    parsed = _parse_rib_entries(device, af=af, ni=ni)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("entries", {})
    log.debug("get_rib_entries: found %d entries for NI=%s AF=%s", len(entries), ni, af)
    return entries


def get_rib_entry(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a single RIB route entry by prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix to look up (e.g. ``"5.5.5.5/32"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict with the route entry data, or ``None`` if the prefix is not
        found.

    Example:
        >>> entry = get_rib_entry(device, "10.0.0.0/24")
        >>> if entry:
        ...     print(entry.get("best-protocol"))
    """
    parsed = _parse_rib_entries(device, af=af, ni=ni, prefix=prefix)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    entries = ni_data.get("entries", {})

    if prefix in entries:
        return entries[prefix]

    # Fallback: if parser returned a single entry (possibly normalized prefix)
    if len(entries) == 1:
        return next(iter(entries.values()))

    log.debug("get_rib_entry: prefix %s not found in RIB", prefix)
    return None


def get_route_best_protocol(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
) -> Optional[str]:
    """Get the best-protocol for a specific RIB route prefix.

    Args:
        device: pyATS device object.
        prefix: Route prefix (e.g. ``"5.5.5.5/32"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        The ``best-protocol`` string (e.g. ``"ISIS"``, ``"STATIC"``,
        ``"BGP"``), or ``None`` if the prefix is not found.

    Example:
        >>> proto = get_route_best_protocol(device, "10.0.0.0/24")
        >>> print(proto)  # "ISIS"
    """
    entry = get_rib_entry(device, prefix, af=af, ni=ni)
    if entry is None:
        return None
    return entry.get("best-protocol")


def is_route_in_rib(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
) -> bool:
    """Check whether a prefix exists in the RIB.

    Args:
        device: pyATS device object.
        prefix: Route prefix to check (e.g. ``"10.0.0.0/24"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        ``True`` if the prefix is present in the RIB, ``False`` otherwise.

    Example:
        >>> if is_route_in_rib(device, "10.0.0.0/24"):
        ...     print("Route is installed")
    """
    entry = get_rib_entry(device, prefix, af=af, ni=ni)
    return entry is not None


def get_rib_entry_count(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> int:
    """Get the total number of route entries in the RIB.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Count of RIB route entries, or ``0`` if none found.

    Example:
        >>> count = get_rib_entry_count(device, af="IPV4")
        >>> print(f"RIB has {count} IPv4 entries")
    """
    entries = get_rib_entries(device, af=af, ni=ni)
    return len(entries)


# -------------------------------------------------------------------
# Public API — Label entries
# -------------------------------------------------------------------


def get_rib_label_entries(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> Dict[str, Any]:
    """Get all RIB MPLS label entries for a network-instance and address family.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict keyed by label string containing label entry dicts.  Returns
        ``{}`` if no entries are found or on any parse error.

    Example:
        >>> labels = get_rib_label_entries(device, af="IPV4")
        >>> for label, data in labels.items():
        ...     print(label, data.get("protocol"), data.get("fec"))
    """
    parsed = _parse_rib_label_entries(device, af=af, ni=ni)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    label_entries = ni_data.get("label-entries", {})
    log.debug(
        "get_rib_label_entries: found %d label entries for NI=%s AF=%s",
        len(label_entries), ni, af,
    )
    return label_entries


def get_rib_label_entry(
    device,
    label: str,
    af: str = "IPV4",
    ni: str = "default",
) -> Optional[Dict[str, Any]]:
    """Get a single RIB MPLS label entry.

    Args:
        device: pyATS device object.
        label: MPLS label to look up (e.g. ``"10005"``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Dict with the label entry data, or ``None`` if the label is not
        found.

    Example:
        >>> entry = get_rib_label_entry(device, "10005")
        >>> if entry:
        ...     print(entry.get("fec"), entry.get("protocol"))
    """
    parsed = _parse_rib_label_entries(device, af=af, ni=ni, label=label)
    ni_data = parsed.get("network-instance", {}).get(ni, {})
    label_entries = ni_data.get("label-entries", {})

    if label in label_entries:
        return label_entries[label]

    # Fallback: if parser returned a single entry (possibly normalized label)
    if len(label_entries) == 1:
        return next(iter(label_entries.values()))

    log.debug("get_rib_label_entry: label %s not found in RIB", label)
    return None


def get_rib_label_entry_count(
    device,
    af: str = "IPV4",
    ni: str = "default",
) -> int:
    """Get the total number of MPLS label entries in the RIB.

    Args:
        device: pyATS device object.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        Count of RIB label entries, or ``0`` if none found.

    Example:
        >>> count = get_rib_label_entry_count(device, af="IPV4")
        >>> print(f"RIB has {count} IPv4 label entries")
    """
    label_entries = get_rib_label_entries(device, af=af, ni=ni)
    return len(label_entries)


def get_rib_backup_nexthops(
    device,
    prefix: str,
    af: str = "IPV4",
    ni: str = "default",
    backup_flag: str = "BACKUP",
) -> List[Dict[str, Any]]:
    """Return the RIB backup next-hops for a prefix.

    A next-hop is a backup when its ``flags`` field contains ``backup_flag``.
    arcOS renders TI-LFA / FRR backups in the RIB entry as a second next-hop
    with e.g. ``flags ATTACH,BACKUP`` (SR-MPLS: ``ATTACH,BACKUP,SR`` plus a
    ``pushed-mpls-label-stack`` repair label). This is the control-plane
    observable for TI-LFA backup programming (the ISIS route table and ISIS
    ``fast-reroute`` output do NOT surface it).

    Args:
        device: pyATS device object.
        prefix: Route prefix string (e.g. ``'6.6.6.6/32'``).
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).
        backup_flag: Flag token identifying a backup next-hop (default
            ``"BACKUP"``).

    Returns:
        List of matching next-hop dicts (each may carry ``interface``,
        ``next-hop``, ``flags``, ``pushed-mpls-label-stack``). Empty list
        if the prefix is absent or has no backup next-hop.

    Example:
        >>> bk = get_rib_backup_nexthops(device, '6.6.6.6/32')
        >>> bk and bk[0].get('interface')
        'swp2'
    """
    entry = get_rib_entry(device, prefix=prefix, af=af, ni=ni)
    if not entry:
        return []

    backups: List[Dict[str, Any]] = []
    for origin in (entry.get("origins") or {}).values():
        for nh in (origin.get("next-hops") or {}).values():
            if backup_flag in (nh.get("flags") or ""):
                backups.append(nh)

    log.debug(
        "get_rib_backup_nexthops(%s, af=%s, ni=%s): %d backup next-hop(s)",
        prefix,
        af,
        ni,
        len(backups),
    )
    return backups
