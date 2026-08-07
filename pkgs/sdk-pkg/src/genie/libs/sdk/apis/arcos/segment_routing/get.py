"""ArcOS Segment Routing get APIs.

High-level helpers built on top of the upstream ArcOS Segment Routing
parsers in ``genie.libs.parser.arcos.show_srv6`` and
``genie.libs.parser.arcos.show_segment_routing``.

These functions use parser classes directly (not ``device.parse``) and
return simplified dictionaries for common use cases.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_srv6 import (
    ShowSrv6Config, ShowSrv6Locator, ShowSrv6LocalSids,
)
from genie.libs.parser.arcos.show_segment_routing import (
    ShowSrmsMappingsConfig,
)
from genie.libs.parser.arcos.show_mpls import (
    ShowMplsReservedLabelBlockConfig,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_srv6_config(device, ni: str = 'default') -> Dict[str, Any]:
    """Parse SRv6 running configuration for a network instance.

    Args:
        device: pyATS device object.
        ni: Network instance name.

    Returns:
        Parsed output dict from ShowSrv6Config, or empty dict on error.
    """
    try:
        return ShowSrv6Config(device=device).parse(instance=ni)
    except SchemaEmptyParserError:
        log.debug("_parse_srv6_config: no SRv6 config found for ni=%s", ni)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_srv6_config: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_srv6_config: unexpected error - %s", exc)
        return {}


def _parse_srv6_locator(device, ni: str = 'default') -> Dict[str, Any]:
    """Parse SRv6 locator operational state for a network instance.

    Args:
        device: pyATS device object.
        ni: Network instance name.

    Returns:
        Parsed output dict from ShowSrv6Locator, or empty dict on error.
    """
    try:
        return ShowSrv6Locator(device=device).parse(instance=ni)
    except SchemaEmptyParserError:
        log.debug("_parse_srv6_locator: no SRv6 locators found for ni=%s", ni)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_srv6_locator: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_srv6_locator: unexpected error - %s", exc)
        return {}


def _parse_srms_mappings(device, ni: str = 'default') -> Dict[str, Any]:
    """Parse SRMS mapping configuration for a network instance.

    Args:
        device: pyATS device object.
        ni: Network instance name.

    Returns:
        Parsed output dict from ShowSrmsMappingsConfig, or empty dict on
        error.
    """
    try:
        return ShowSrmsMappingsConfig(device=device).parse(instance=ni)
    except SchemaEmptyParserError:
        log.debug(
            "_parse_srms_mappings: no SRMS mappings found for ni=%s", ni
        )
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_srms_mappings: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_srms_mappings: unexpected error - %s", exc)
        return {}


# ---------------------------------------------------------------------------
# SRv6 locator APIs
# ---------------------------------------------------------------------------

def get_srv6_locators(device, ni: str = 'default') -> Dict[str, Any]:
    """Get all SRv6 locators from operational state.

    Args:
        device: pyATS device object.
        ni: Network instance name (default: 'default').

    Returns:
        Dictionary of locators keyed by locator name, e.g.::

            {
                "loc1": {
                    "name": "loc1",
                    "prefix": "fcbb:bb00:1::/48",
                    "locator-node-length": 24,
                    ...
                }
            }

        Returns empty dict if no locators are found.
    """
    parsed = _parse_srv6_locator(device, ni=ni)
    return (
        parsed
        .get("network-instances", {})
        .get(ni, {})
        .get("srv6", {})
        .get("locators", {})
    )


def get_srv6_locator(device, locator_name: str,
                     ni: str = 'default') -> Optional[Dict[str, Any]]:
    """Get a single SRv6 locator by name from operational state.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator to retrieve.
        ni: Network instance name (default: 'default').

    Returns:
        Dictionary with the locator details, or None if not found.
    """
    locators = get_srv6_locators(device, ni=ni)
    return locators.get(locator_name)


def get_srv6_locator_count(device, ni: str = 'default') -> int:
    """Get the number of SRv6 locators.

    Args:
        device: pyATS device object.
        ni: Network instance name (default: 'default').

    Returns:
        Number of configured SRv6 locators.
    """
    locators = get_srv6_locators(device, ni=ni)
    return len(locators)


def get_srv6_encap_source_address(device,
                                  ni: str = 'default') -> Optional[str]:
    """Get the SRv6 encapsulation source address from running config.

    Args:
        device: pyATS device object.
        ni: Network instance name (default: 'default').

    Returns:
        Source address string, or None if not configured.
    """
    parsed = _parse_srv6_config(device, ni=ni)
    return (
        parsed
        .get("network-instances", {})
        .get(ni, {})
        .get("srv6", {})
        .get("config", {})
        .get("encapsulation", {})
        .get("source-address")
    )


def is_srv6_locator_present(device, locator_name: str,
                            ni: str = 'default') -> bool:
    """Check if an SRv6 locator exists in operational state.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator to check.
        ni: Network instance name (default: 'default').

    Returns:
        True if the locator is present, False otherwise.
    """
    return get_srv6_locator(device, locator_name, ni=ni) is not None


# ---------------------------------------------------------------------------
# SRMS mapping APIs
# ---------------------------------------------------------------------------

def get_srms_mappings(device, ni: str = 'default') -> Dict[str, Any]:
    """Get all SRMS mappings.

    Args:
        device: pyATS device object.
        ni: Network instance name (default: 'default').

    Returns:
        Dictionary of mappings keyed by mapping local-id, e.g.::

            {
                "100": {
                    "local-id": "100",
                    "ipv4-prefixes": [...],
                    ...
                }
            }

        Returns empty dict if no mappings are found.
    """
    parsed = _parse_srms_mappings(device, ni=ni)
    return (
        parsed
        .get("network-instances", {})
        .get(ni, {})
        .get("srms", {})
        .get("mappings", {})
    )


def get_srms_mapping(device, mapping_id: str,
                     ni: str = 'default') -> Optional[Dict[str, Any]]:
    """Get a single SRMS mapping by identifier.

    Args:
        device: pyATS device object.
        mapping_id: Mapping identifier (local-id) to retrieve.
        ni: Network instance name (default: 'default').

    Returns:
        Dictionary with the mapping details, or None if not found.
    """
    mappings = get_srms_mappings(device, ni=ni)
    return mappings.get(mapping_id)


def get_srms_mapping_count(device, ni: str = 'default') -> int:
    """Get the number of SRMS mappings.

    Args:
        device: pyATS device object.
        ni: Network instance name (default: 'default').

    Returns:
        Number of configured SRMS mappings.
    """
    mappings = get_srms_mappings(device, ni=ni)
    return len(mappings)


def is_srms_mapping_present(device, mapping_id: str,
                            ni: str = 'default') -> bool:
    """Check if an SRMS mapping exists.

    Args:
        device: pyATS device object.
        mapping_id: Mapping identifier (local-id) to check.
        ni: Network instance name (default: 'default').

    Returns:
        True if the mapping is present, False otherwise.
    """
    return get_srms_mapping(device, mapping_id, ni=ni) is not None


# ---------------------------------------------------------------------------
# SRv6 locator scalar getters
# ---------------------------------------------------------------------------

def get_srv6_locator_prefix(device, locator_name: str,
                            ni: str = 'default') -> Optional[str]:
    """Get the IPv6 prefix of an SRv6 locator.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator.
        ni: Network instance name (default: 'default').

    Returns:
        Prefix string (e.g. ``'fcbb:bb00:1::/48'``), or ``None`` if the
        locator is not found.
    """
    loc = get_srv6_locator(device, locator_name, ni=ni)
    if not loc:
        return None
    return loc.get("prefix")


def get_srv6_locator_algorithm(device, locator_name: str,
                               ni: str = 'default') -> Optional[int]:
    """Get the algorithm identifier of an SRv6 locator.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator.
        ni: Network instance name (default: 'default').

    Returns:
        Algorithm integer (e.g. ``128``), or ``None`` if the locator is
        not found or algorithm is not set.
    """
    loc = get_srv6_locator(device, locator_name, ni=ni)
    if not loc:
        return None
    return loc.get("algorithm")


def get_srv6_locator_micro_segment_enabled(
    device, locator_name: str, ni: str = 'default',
) -> Optional[bool]:
    """Check if micro-segment-behavior-unode is enabled on a locator.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator.
        ni: Network instance name (default: 'default').

    Returns:
        ``True`` if micro-segment is enabled, ``False`` if disabled, or
        ``None`` if the locator is not found.
    """
    loc = get_srv6_locator(device, locator_name, ni=ni)
    if not loc:
        return None
    return loc.get("micro-segment-behavior-unode")


def get_srv6_locator_node_length(device, locator_name: str,
                                 ni: str = 'default') -> Optional[int]:
    """Get the locator-node-length of an SRv6 locator.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator.
        ni: Network instance name (default: 'default').

    Returns:
        Node length integer (e.g. ``16``), or ``None`` if the locator is
        not found.
    """
    loc = get_srv6_locator(device, locator_name, ni=ni)
    if not loc:
        return None
    return loc.get("locator-node-length")


def get_srv6_locator_function_length(device, locator_name: str,
                                     ni: str = 'default') -> Optional[int]:
    """Get the function-length of an SRv6 locator.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator.
        ni: Network instance name (default: 'default').

    Returns:
        Function length integer (e.g. ``16``), or ``None`` if the locator
        is not found or function-length is not set.
    """
    loc = get_srv6_locator(device, locator_name, ni=ni)
    if not loc:
        return None
    return loc.get("function-length")


# ---------------------------------------------------------------------------
# SRv6 local-SID APIs
# ---------------------------------------------------------------------------

def _parse_srv6_local_sids(device,
                           ni: str = 'default') -> Dict[str, Any]:
    """Parse SRv6 local-SID table operational state for a network instance.

    Args:
        device: pyATS device object.
        ni: Network instance name.

    Returns:
        Parsed output dict from ShowSrv6LocalSids, or empty dict on error.
    """
    try:
        return ShowSrv6LocalSids(device=device).parse(instance=ni)
    except SchemaEmptyParserError:
        log.debug(
            "_parse_srv6_local_sids: no local-SIDs found for ni=%s",
            ni
        )
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_srv6_local_sids: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_srv6_local_sids: unexpected error - %s", exc)
        return {}


def get_srv6_local_sids(device,
                        ni: str = 'default') -> Dict[str, Any]:
    """Get all SRv6 local-SIDs from operational state.

    Args:
        device: pyATS device object.
        ni: Network instance name (default: 'default').

    Returns:
        Dictionary of local-SID entries keyed by SID, e.g.::

            {
                "fcbb:bb00:1:1::/64": {
                    "behavior": "END_PSP_USD",
                    "locator_name": "base_slice0",
                    "client_name": "isis",
                    "sid_paths": [...],
                }
            }

        Returns empty dict if no local-SIDs are found.
    """
    parsed = _parse_srv6_local_sids(device, ni=ni)
    return (
        parsed
        .get("network_instance", {})
        .get(ni, {})
        .get("local_sids", {})
    )


def get_srv6_local_sid(device, sid: str,
                       ni: str = 'default'
                       ) -> Optional[Dict[str, Any]]:
    """Get a single SRv6 local-SID entry by SID.

    Args:
        device: pyATS device object.
        sid: SID value to retrieve (e.g. ``'fcbb:bb00:1:1::/64'``).
        ni: Network instance name (default: 'default').

    Returns:
        Dictionary with the local-SID details, or None if not found.
    """
    sids = get_srv6_local_sids(device, ni=ni)
    return sids.get(sid)


def get_srv6_local_sid_behavior(device, sid: str,
                                ni: str = 'default'
                                ) -> Optional[str]:
    """Get the behavior of a single SRv6 local-SID.

    Args:
        device: pyATS device object.
        sid: SID value to look up.
        ni: Network instance name (default: 'default').

    Returns:
        Behavior string (e.g. ``'END_PSP_USD'``), or None if the SID is
        not found or behavior is not set.
    """
    entry = get_srv6_local_sid(device, sid, ni=ni)
    if not entry:
        return None
    return entry.get("behavior")


def get_srv6_local_sids_by_locator(device, locator_name: str,
                                   ni: str = 'default'
                                   ) -> Dict[str, Any]:
    """Get all SRv6 local-SIDs belonging to a given locator.

    Args:
        device: pyATS device object.
        locator_name: Name of the locator to filter by.
        ni: Network instance name (default: 'default').

    Returns:
        Dictionary of local-SID entries (same shape as
        :func:`get_srv6_local_sids`) filtered to those whose
        ``locator_name`` matches. Returns empty dict if none match.
    """
    sids = get_srv6_local_sids(device, ni=ni)
    return {
        sid: entry for sid, entry in sids.items()
        if entry.get("locator_name") == locator_name
    }


# ---------------------------------------------------------------------------
# MPLS reserved label blocks (SRGB / SRLB)
# ---------------------------------------------------------------------------

def _parse_reserved_label_blocks(device, ni: str = 'default') -> Dict[str, Any]:
    """Parse ``show running-config ... mpls global reserved-label-block``."""
    try:
        return ShowMplsReservedLabelBlockConfig(device=device).parse(
            network_instance=ni
        )
    except SchemaEmptyParserError:
        # No blocks configured. The device answers "% No entries found." here,
        # which is a legitimate state, not an error.
        log.debug("_parse_reserved_label_blocks: none configured for ni=%s", ni)
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_reserved_label_blocks: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_reserved_label_blocks: unexpected error - %s", exc)
        return {}


def get_mpls_reserved_label_blocks(device, ni: str = 'default') -> Dict[str, Any]:
    """Return ``{local_id: block_config}`` for every reserved label block.

    Each value carries ``lower-bound`` / ``upper-bound`` and, when set, ``usage``,
    ``protocol-identifier`` and ``protocol-name``.

    ``usage`` is Optional in the parser schema for a real reason: arcOS rejects an
    unknown usage token as ``syntax error: unknown element`` but still commits the
    rest of the block, so a block created with a bad token exists WITHOUT a usage
    leaf. An absent ``usage`` here means exactly that.

    Args:
        device: pyATS device object.
        ni: Network instance name (default: ``'default'``).

    Returns:
        Mapping of local-id to the block's config dict; ``{}`` when none exist.
    """
    parsed = _parse_reserved_label_blocks(device, ni=ni)
    return (
        ((parsed.get("network-instance") or {}).get(ni) or {})
        .get("mpls", {})
        .get("reserved-label-blocks", {})
    ) or {}


def get_mpls_reserved_label_block(device, block_id: str,
                                  ni: str = 'default') -> Optional[Dict[str, Any]]:
    """Return one reserved label block's config, or ``None`` when absent.

    Args:
        device: pyATS device object.
        block_id: Label block local-id, e.g. ``'SRGB_BLOCK'``.
        ni: Network instance name (default: ``'default'``).

    Returns:
        The block's config dict, or ``None``.
    """
    return get_mpls_reserved_label_blocks(device, ni=ni).get(block_id)
