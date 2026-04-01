"""ArcOS QoS get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.parser.arcos.show_qos import ShowQosPolicy

log = logging.getLogger(__name__)


def _parse_qos_policies(device, name="*") -> Dict[str, Any]:
    try:
        parser = ShowQosPolicy(device=device)
        return parser.parse(name=name)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse QoS policies: %s", exc)
        return {}


def get_qos_policies(device) -> Dict[str, Any]:
    """Get all QoS policies.

    Args:
        device: pyATS device object.

    Returns:
        Dict keyed by policy name. Empty if none.
    """
    parsed = _parse_qos_policies(device)
    return parsed.get("policies", {})


def get_qos_policy(device, name: str) -> Optional[Dict[str, Any]]:
    """Get a single QoS policy by name.

    Args:
        device: pyATS device object.
        name: Policy name.

    Returns:
        Dict with policy data, or None if not found.
    """
    parsed = _parse_qos_policies(device, name=name)
    policies = parsed.get("policies", {})
    if name in policies:
        return policies[name]
    if len(policies) == 1:
        return next(iter(policies.values()))
    return None


def is_qos_policy_present(device, name: str) -> bool:
    """Check if a QoS policy exists.

    Args:
        device: pyATS device object.
        name: Policy name.

    Returns:
        True if policy exists, False otherwise.
    """
    return get_qos_policy(device, name) is not None


def get_qos_policy_count(device) -> int:
    """Get total number of QoS policies.

    Args:
        device: pyATS device object.

    Returns:
        Number of QoS policies.
    """
    return len(get_qos_policies(device))
