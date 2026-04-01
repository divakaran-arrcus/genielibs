"""ArcOS SR-Policy get APIs.

High-level helpers built on top of the upstream ArcOS SR-Policy parsers:
- ``ShowSrPolicySegmentList``
- ``ShowSrPolicyPolicy``
- ``ShowSrPolicyDatabasePolicy``

These functions instantiate parsers directly.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_sr_policy import (
    ShowSrPolicySegmentList,
    ShowSrPolicyPolicy,
    ShowSrPolicyDatabasePolicy,
)

log = logging.getLogger(__name__)


# =====================================================================
# Parse helpers
# =====================================================================

def _parse_segment_lists(device) -> Dict[str, Any]:
    try:
        parser = ShowSrPolicySegmentList(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse SR-Policy segment-lists: %s", exc)
        return {}


def _parse_policies(device) -> Dict[str, Any]:
    try:
        parser = ShowSrPolicyPolicy(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse SR-Policy policies: %s", exc)
        return {}


def _parse_db_policies(device) -> Dict[str, Any]:
    try:
        parser = ShowSrPolicyDatabasePolicy(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse SR-Policy database policies: %s", exc)
        return {}


# =====================================================================
# Public get functions
# =====================================================================

def get_sr_policy_segment_lists(device) -> Dict[str, Any]:
    """Get all SR-Policy segment-lists.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by segment-list name with segments data.
        Empty dict if none found.
    """

    parsed = _parse_segment_lists(device)
    return parsed.get("segment-lists", {})


def get_sr_policy_segment_list(
    device, name: str
) -> Optional[Dict[str, Any]]:
    """Get a single SR-Policy segment-list by name.

    Args:
        device: pyATS device object.
        name: Segment-list name (e.g., 'sl1').

    Returns:
        Dict with segment-list data, or None if not found.
    """

    sls = get_sr_policy_segment_lists(device)
    return sls.get(name)


def get_sr_policy_policies(device) -> Dict[str, Any]:
    """Get all SR-Policy policies (configuration state).

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by 'endpoint color' with policy config data.
        Empty dict if none found.
    """

    parsed = _parse_policies(device)
    return parsed.get("policies", {})


def get_sr_policy_policy(
    device, endpoint: str, color: int
) -> Optional[Dict[str, Any]]:
    """Get a single SR-Policy by endpoint and color.

    Args:
        device: pyATS device object.
        endpoint: Policy endpoint (e.g., '2.2.2.2').
        color: Policy color (e.g., 100).

    Returns:
        Dict with policy data, or None if not found.
    """

    policies = get_sr_policy_policies(device)
    pol_key = f"{endpoint} {color}"
    return policies.get(pol_key)


def get_sr_policy_db_policies(device) -> Dict[str, Any]:
    """Get all SR-Policy database policies (operational state).

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by 'endpoint color' with oper-state, candidate-paths.
        Empty dict if none found.
    """

    parsed = _parse_db_policies(device)
    return parsed.get("policies", {})


def get_sr_policy_db_oper_state(
    device, endpoint: str, color: int
) -> Optional[str]:
    """Get operational state for an SR-Policy from the database.

    Args:
        device: pyATS device object.
        endpoint: Policy endpoint.
        color: Policy color.

    Returns:
        Oper-state string (e.g., 'UP', 'DOWN'), or None if not found.
    """

    db = get_sr_policy_db_policies(device)
    pol_key = f"{endpoint} {color}"
    pol = db.get(pol_key)
    if not pol:
        return None
    return pol.get("oper-state")


def get_sr_policy_policy_count(device) -> int:
    """Get total number of SR-Policy policies.

    Args:
        device: pyATS device object.

    Returns:
        Number of policies.
    """

    policies = get_sr_policy_policies(device)
    return len(policies)
