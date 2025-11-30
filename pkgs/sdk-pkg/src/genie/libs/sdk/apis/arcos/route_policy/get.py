"""ArcOS routing-policy get APIs.

Helpers built on top of the ArcOS routing-policy parsers in
``genie.libs.parser.arcos.show_routing_policy``.

All functions here use ``device.parse()`` and operate on the normalized
``routing_policy`` model described in the design document.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from genie.metaparser.util.exceptions import SchemaEmptyParserError

log = logging.getLogger(__name__)


def _parse_routing_policy_defined_sets(
    device,
    command: str = "show routing-policy defined-sets",
) -> Dict[str, Any]:
    """Return the normalized ``defined_sets`` subtree for ArcOS.

    Executes ``device.parse(command)`` and extracts
    ``parsed["routing_policy"]["defined_sets"]``.
    """

    try:
        parsed = device.parse(command)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to parse %r for routing-policy defined-sets: %s", command, exc)
        return {}

    rp_root = parsed.get("routing_policy", {}) or {}
    return rp_root.get("defined_sets", {}) or {}


def _parse_routing_policy_policy_definitions(
    device,
    command: str = "show routing-policy policy-definition",
) -> Dict[str, Any]:
    """Return the normalized ``policy_definitions`` subtree for ArcOS."""

    try:
        parsed = device.parse(command)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error(
            "Failed to parse %r for routing-policy policy-definitions: %s",
            command,
            exc,
        )
        return {}

    rp_root = parsed.get("routing_policy", {}) or {}
    return rp_root.get("policy_definitions", {}) or {}


def _parse_running_config_routing_policy(
    device,
    command: str = "show running-config routing-policy",
) -> Dict[str, Any]:
    """Return the combined ``routing_policy`` tree from running-config."""

    try:
        parsed = device.parse(command)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.error(
            "Failed to parse %r for running-config routing-policy: %s",
            command,
            exc,
        )
        return {}

    return parsed.get("routing_policy", {}) or {}


# ---------------------------------------------------------------------------
# Public Get APIs – Defined Sets
# ---------------------------------------------------------------------------


def get_routing_policy_defined_sets(
    device,
    *,
    command: str = "show routing-policy defined-sets",
) -> Dict[str, Any]:
    """Return the full ``defined_sets`` model for ArcOS routing-policy.

    The returned dict may contain the following optional keys:

    - ``"prefix_sets"``
    - ``"string_sets"``
    - ``"tag_sets"``
    - ``"next_hop_sets"``
    """

    return _parse_routing_policy_defined_sets(device, command=command)


def get_prefix_set(
    device,
    name: str,
    *,
    command: str = "show routing-policy defined-sets",
) -> Optional[Dict[str, Any]]:
    """Return a single prefix-set definition by name, or ``None`` if absent."""

    defined_sets = _parse_routing_policy_defined_sets(device, command=command)
    prefix_sets = defined_sets.get("prefix_sets", {}) or {}
    return prefix_sets.get(name)


def get_string_set(
    device,
    name: str,
    *,
    command: str = "show routing-policy defined-sets",
) -> Optional[Dict[str, Any]]:
    """Return a single string-set definition by name, or ``None`` if absent."""

    defined_sets = _parse_routing_policy_defined_sets(device, command=command)
    string_sets = defined_sets.get("string_sets", {}) or {}
    return string_sets.get(name)


def get_tag_set(
    device,
    name: str,
    *,
    command: str = "show routing-policy defined-sets",
) -> Optional[Dict[str, Any]]:
    """Return a single tag-set definition by name, or ``None`` if absent."""

    defined_sets = _parse_routing_policy_defined_sets(device, command=command)
    tag_sets = defined_sets.get("tag_sets", {}) or {}
    return tag_sets.get(name)


def get_next_hop_set(
    device,
    name: str,
    *,
    command: str = "show routing-policy defined-sets",
) -> Optional[Dict[str, Any]]:
    """Return a single next-hop-set definition by name, or ``None`` if absent."""

    defined_sets = _parse_routing_policy_defined_sets(device, command=command)
    nh_sets = defined_sets.get("next_hop_sets", {}) or {}
    return nh_sets.get(name)


# ---------------------------------------------------------------------------
# Public Get APIs – Policy Definitions
# ---------------------------------------------------------------------------


def get_routing_policy_policy_definitions(
    device,
    *,
    command: str = "show routing-policy policy-definition",
) -> Dict[str, Any]:
    """Return the full ``policy_definitions`` model for ArcOS routing-policy."""

    return _parse_routing_policy_policy_definitions(device, command=command)


def get_policy_definition(
    device,
    policy_name: str,
    *,
    command: str = "show routing-policy policy-definition",
) -> Optional[Dict[str, Any]]:
    """Return a single policy definition (all statements) by name."""

    policy_defs = _parse_routing_policy_policy_definitions(device, command=command)
    return policy_defs.get(policy_name)


def get_policy_statements(
    device,
    policy_name: str,
    *,
    command: str = "show routing-policy policy-definition",
) -> Optional[Dict[str, Any]]:
    """Return the ``statements`` dict for a given policy, or ``None`` if missing."""

    policy = get_policy_definition(device, policy_name, command=command)
    if not policy:
        return None
    return policy.get("statements") or {}


def get_policy_statement(
    device,
    policy_name: str,
    statement_name: str,
    *,
    command: str = "show routing-policy policy-definition",
) -> Optional[Dict[str, Any]]:
    """Return a single statement within a policy, or ``None`` if missing."""

    stmts = get_policy_statements(device, policy_name, command=command)
    if stmts is None:
        return None
    return stmts.get(statement_name)


# ---------------------------------------------------------------------------
# Public Get APIs – Running-config view
# ---------------------------------------------------------------------------


def get_running_config_routing_policy(
    device,
    *,
    command: str = "show running-config routing-policy",
) -> Dict[str, Any]:
    """Return the combined ``routing_policy`` tree from running-config.

    This is a thin wrapper over ``device.parse()`` using the
    ``ShowRunningConfigRoutingPolicy`` parser. The returned dict has the
    shape::

        {
            "defined_sets": {...}?,
            "policy_definitions": {...}?,
        }
    """

    return _parse_running_config_routing_policy(device, command=command)
