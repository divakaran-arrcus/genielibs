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
# SR-MPLS indirect (ECMP-FEC-optimized) next-hop resolution
# -------------------------------------------------------------------
#
# When IS-IS installs a prefix that carries an active prefix-SID, it sets
# RIB_RT_ECMP_OPTIMIZE_FLAG on the route. If the route then has >1 path, every
# path carries a label, and the label stacks share a common suffix, the RIB
# collapses them onto ONE synthetic recursive next-hop so N labeled ECMP paths
# cost one FEC instead of N. The route then renders as:
#
#   "flags": "ECMP_FEC_OPTIMIZE", "nhid": "327",
#   "next-hops": {"next-hop": [{"pathid": "326", "type": "IGP",
#                               "next-hop": 317, "weight": 100,
#                               "flags": "RECURSIVE SR IGP_NH",
#                               "pushed-mpls-label-stack": [16006]}]}
#
# `next-hop` is now an INTEGER id, not an address, and there is no `interface`
# and no BACKUP flag: the synthetic path is built with only
# RIB_PATH_IGP_VIA_FLAG | RIB_PATH_RECURSIVE_FLAG (+ SR_MPLS), so BACKUP can
# never appear on it by construction. The real paths — with their egress
# interface, ATTACH/BACKUP flags and repair label stack — sit one level down,
# reachable via the IGP-RNH id, which is also the NHID of that path set.
#
# There is no config knob to switch this off: IS-IS sets the flag for every
# prefix-SID-bearing route, unconditionally. Suites that assert on TI-LFA
# backups therefore have to follow the indirection.
#
# Historically these suites passed WITHOUT following it, because the testbeds
# pushed an invalid `usage SRGB` token which arcOS rejected leaf-only. With no
# valid SRGB, IS-IS could not download labels, the "every path has a label"
# precondition failed, and the RIB rendered flat. Fixing the token turned
# SR-MPLS genuinely on and exposed that the assertions had never exercised the
# SR-MPLS shape.

_IGP_NH_FLAG = "IGP_NH"


def _walk_lists(obj, key):
    """Yield every list found under ``key``, at any depth.

    Deliberately nesting-agnostic. These oper tables are read over
    ``| display json``, and the exact wrapper ConfD emits for a container
    carrying ``tailf:cli-drop-node-name`` (``igp-rnhs`` vs ``igp-rnh``) is not
    something we want the caller to depend on. Searching by key survives
    either, and survives a wrapper being added or removed between releases.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).split(":")[-1] == key:
                if isinstance(v, list):
                    yield v
                elif isinstance(v, dict):
                    yield [v]
            yield from _walk_lists(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_lists(v, key)


def _leaf(obj, key, default=None):
    """Fetch ``key`` from a dict, ignoring any YANG module prefix."""
    if not isinstance(obj, dict):
        return default
    for k, v in obj.items():
        if str(k).split(":")[-1] == key:
            return v
    return default


def _execute_json(device, command):
    """Run a ``| display json`` show command and return the parsed document.

    Uses ``execute`` rather than ``parse``: there is no upstream parser for the
    igp-rnh / pathid oper tables, and inventing a strict schema for output
    whose JSON nesting has not been confirmed on a device would be worse than
    walking the document. Returns ``{}`` on any failure — a resolution we
    cannot perform must degrade to "no backup found", never raise.
    """
    import json

    try:
        out = device.execute(f"{command} | display json | nomore")
    except Exception as exc:  # noqa: BLE001 - oper read is best-effort
        log.debug("_execute_json(%s) failed: %s", command, exc)
        return {}
    if not out:
        return {}
    text = out if isinstance(out, str) else str(out)
    start = text.find("{")
    if start < 0:
        log.debug("_execute_json(%s): no JSON in output", command)
        return {}
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except Exception as exc:  # noqa: BLE001
                    log.debug("_execute_json(%s): bad JSON: %s", command, exc)
                    return {}
    return {}


def is_indirect_nexthop(nh: Dict[str, Any]) -> bool:
    """True when a next-hop is the synthetic recursive SR-MPLS one.

    Both conditions are required. The flag alone is not enough (a genuinely
    recursive BGP next-hop also carries RECURSIVE), and an integer ``next-hop``
    alone is not enough either — we want to be certain before spending two
    extra device reads, and certain the flat path is still taken on an image
    that renders flat.
    """
    if _IGP_NH_FLAG not in str(_leaf(nh, "flags") or ""):
        return False
    value = _leaf(nh, "next-hop")
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return bool(str(value).strip().isdigit())


def get_rib_igp_rnh_pathids(
    device,
    rnh_id,
    af: str = "IPV4",
    ni: str = "default",
) -> List[int]:
    """Return the underlying pathids for an IGP-RNH id.

    The IGP-RNH id is also the NHID of the real path set, so either table
    answers. ``igp-rnh`` is tried first because it is one read and reports the
    NHID back for cross-checking; the nhid table is the fallback.

    Args:
        device: pyATS device object.
        rnh_id: IGP-RNH id — the integer ``next-hop`` of a recursive next-hop.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        List of pathid integers; empty when the id cannot be resolved.
    """
    fam = "ipv4" if str(af).upper() == "IPV4" else "ipv6"
    reads = (
        (f"show network-instance {ni} rib {af} igp-rnh {rnh_id}", "paths"),
        (f"show network-instance {ni} rib {af} {fam}-nhids "
         f"{fam}-nhids {rnh_id}", "pathids-list"),
    )
    for command, field in reads:
        doc = _execute_json(device, command)
        if not doc:
            continue
        # The row we want is whichever object carries the pathid list.
        found: List[int] = []
        def _scan(obj):
            if isinstance(obj, dict):
                val = _leaf(obj, field)
                if isinstance(val, list):
                    for x in val:
                        try:
                            found.append(int(x))
                        except (TypeError, ValueError):
                            continue
                elif isinstance(val, str):
                    for tok in val.replace("[", " ").replace("]", " ").split():
                        if tok.isdigit():
                            found.append(int(tok))
                for v in obj.values():
                    _scan(v)
            elif isinstance(obj, list):
                for v in obj:
                    _scan(v)
        _scan(doc)
        if found:
            log.debug("igp-rnh %s -> pathids %s (via %s)",
                      rnh_id, found, command)
            return found
    log.debug("igp-rnh %s: could not resolve pathids", rnh_id)
    return []


def get_rib_pathid(
    device,
    pathid,
    af: str = "IPV4",
    ni: str = "default",
) -> Dict[str, Any]:
    """Return one resolved pathid: the object carrying egress and flags.

    This is the only table that holds the real forwarding detail —
    ``interface``, ``next-hop`` address, ``flags`` (ATTACH/BACKUP/...), the
    ``backup`` boolean, ``weight`` and ``pushed-mpls-label-stack``.

    Args:
        device: pyATS device object.
        pathid: Pathid integer.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        The pathid dict, or ``{}`` when absent/unreadable.
    """
    fam = "ipv4" if str(af).upper() == "IPV4" else "ipv6"
    doc = _execute_json(
        device,
        f"show network-instance {ni} rib {af} {fam}-pathids pathids {pathid}",
    )
    if not doc:
        return {}
    best: Dict[str, Any] = {}
    def _scan(obj):
        nonlocal best
        if isinstance(obj, dict):
            if _leaf(obj, "interface") is not None or \
               _leaf(obj, "pathid") is not None:
                if len(obj) > len(best):
                    best = obj
            for v in obj.values():
                _scan(v)
        elif isinstance(obj, list):
            for v in obj:
                _scan(v)
    _scan(doc)
    return best


def resolve_indirect_nexthops(
    device,
    nh: Dict[str, Any],
    af: str = "IPV4",
    ni: str = "default",
) -> List[Dict[str, Any]]:
    """Expand one recursive SR-MPLS next-hop into its real underlying paths.

    Each returned path is the pathid object, with the parent's common label
    suffix recorded as ``parent-pushed-mpls-label-stack`` so a caller can
    reconstruct the full stack the packet actually gets: the RIB subtracts the
    common suffix from each sub-path, leaving the primary with no labels and
    the backup with only its repair SIDs.

    Args:
        device: pyATS device object.
        nh: A next-hop dict from a RIB entry origin.
        af: Address family — ``"IPV4"`` or ``"IPV6"`` (default ``"IPV4"``).
        ni: Network instance name (default ``"default"``).

    Returns:
        List of resolved path dicts; empty when resolution fails.
    """
    rnh_id = _leaf(nh, "next-hop")
    parent_labels = _leaf(nh, "pushed-mpls-label-stack") or []
    out: List[Dict[str, Any]] = []
    for pathid in get_rib_igp_rnh_pathids(device, rnh_id, af=af, ni=ni):
        path = get_rib_pathid(device, pathid, af=af, ni=ni)
        if not path:
            continue
        path = dict(path)
        path.setdefault("pathid", pathid)
        path["parent-pushed-mpls-label-stack"] = parent_labels
        out.append(path)
    return out

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
    indirect_seen = False
    for origin in (entry.get("origins") or {}).values():
        for nh in (origin.get("next-hops") or {}).values():
            # Flat rendering: the backup is right here, as it was before
            # SR-MPLS FEC optimization existed. Checked FIRST so an image that
            # renders flat costs no extra device reads.
            if backup_flag in (_leaf(nh, "flags") or ""):
                backups.append(nh)
                continue
            # Indirect rendering: follow the recursion. The BACKUP flag lives
            # on the underlying pathids, never on the synthetic parent.
            if is_indirect_nexthop(nh):
                indirect_seen = True
                for path in resolve_indirect_nexthops(
                        device, nh, af=af, ni=ni):
                    is_backup = (
                        backup_flag in str(_leaf(path, "flags") or "")
                        or _leaf(path, "backup") is True
                        or str(_leaf(path, "backup") or "").lower() == "true"
                    )
                    if is_backup:
                        backups.append(path)

    log.debug(
        "get_rib_backup_nexthops(%s, af=%s, ni=%s): %d backup next-hop(s)"
        "%s",
        prefix,
        af,
        ni,
        len(backups),
        " (via SR-MPLS indirection)" if indirect_seen else "",
    )
    if indirect_seen and not backups:
        # Worth saying out loud: this is the shape that silently returned []
        # and turned four TI-LFA lanes red without naming a cause.
        log.warning(
            "%s has an ECMP-FEC-optimized recursive next-hop but no backup "
            "resolved behind it. Either TI-LFA programmed no backup, or the "
            "igp-rnh/pathid oper read is unavailable on this image.",
            prefix,
        )
    return backups
