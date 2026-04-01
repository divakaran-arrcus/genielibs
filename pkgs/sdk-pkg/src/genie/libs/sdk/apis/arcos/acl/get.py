"""ArcOS ACL get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.parser.arcos.show_acl import ShowAclSet

log = logging.getLogger(__name__)


def _parse_acl(device, name=None, acl_type=None) -> Dict[str, Any]:
    try:
        parser = ShowAclSet(device=device)
        return parser.parse(name=name, acl_type=acl_type)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse ACL: %s", exc)
        return {}


def get_acl_sets(device) -> Dict[str, Any]:
    """Get all ACL sets.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by 'name type' with ACL data. Empty if none.
    """
    parsed = _parse_acl(device)
    return parsed.get("acl-sets", {})


def get_acl_set(
    device, name: str, acl_type: str
) -> Optional[Dict[str, Any]]:
    """Get a single ACL set by name and type.

    Args:
        device: pyATS device object.
        name: ACL name (e.g., 'v4-acl').
        acl_type: ACL type (e.g., 'ACL_IPV4').

    Returns:
        Dict with ACL data, or None if not found.
    """
    parsed = _parse_acl(device, name=name, acl_type=acl_type)
    acl_sets = parsed.get("acl-sets", {})
    key = f"{name} {acl_type}"
    if key in acl_sets:
        return acl_sets[key]
    if len(acl_sets) == 1:
        return next(iter(acl_sets.values()))
    return None


def get_acl_entries(
    device, name: str, acl_type: str
) -> Dict[str, Any]:
    """Get ACL entries for a specific ACL set.

    Args:
        device: pyATS device object.
        name: ACL name.
        acl_type: ACL type.

    Returns:
        Dict keyed by sequence-id. Empty if none.
    """
    acl = get_acl_set(device, name, acl_type)
    if not acl:
        return {}
    return acl.get("acl-entries", {})


def is_acl_set_present(
    device, name: str, acl_type: str
) -> bool:
    """Check if an ACL set exists.

    Args:
        device: pyATS device object.
        name: ACL name.
        acl_type: ACL type.

    Returns:
        True if ACL exists, False otherwise.
    """
    return get_acl_set(device, name, acl_type) is not None


def get_acl_set_count(device) -> int:
    """Get total number of ACL sets.

    Args:
        device: pyATS device object.

    Returns:
        Number of ACL sets.
    """
    return len(get_acl_sets(device))
