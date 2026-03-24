"""ArcOS EVPN get APIs.

High-level helpers built on top of the upstream ArcOS EVPN parser
``genie.libs.parser.arcos.show_evpn.ShowEvpn``.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def _parse_evpn(device) -> Dict[str, Any]:
    """Parse EVPN global state using ShowEvpn parser.

    Args:
        device: pyATS device object.

    Returns:
        Parsed dict of EVPN state, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_evpn import ShowEvpn
        parser = ShowEvpn(device=device)
        parsed = parser.parse()
    except SchemaEmptyParserError:
        log.debug("_parse_evpn: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_evpn: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_evpn: Unexpected exception - %s", exc)
        return {}

    return parsed


def get_evpn_state(device) -> Dict[str, Any]:
    """Get full EVPN global state on ArcOS.

    Args:
        device: pyATS device object.

    Returns:
        Dict with EVPN state fields (anycast-gateway-mac, df-election-time,
        duplicate-mac-detection, arp-nd-suppression-counters), or empty dict.
    """
    return _parse_evpn(device)


def get_evpn_anycast_gateway_mac(device) -> Optional[str]:
    """Get EVPN anycast gateway MAC address on ArcOS.

    Args:
        device: pyATS device object.

    Returns:
        MAC address string if configured, None otherwise.
    """
    state = _parse_evpn(device)
    return state.get("anycast-gateway-mac")


def get_evpn_df_election_time(device) -> Optional[int]:
    """Get EVPN DF election hold timer on ArcOS.

    Args:
        device: pyATS device object.

    Returns:
        DF election time in seconds if configured, None otherwise.
    """
    state = _parse_evpn(device)
    val = state.get("df-election-time")
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            return val
    return None


def get_evpn_duplicate_mac_detection(device) -> Dict[str, Any]:
    """Get EVPN duplicate MAC detection parameters on ArcOS.

    Args:
        device: pyATS device object.

    Returns:
        Dict with keys 'window', 'threshold', 'auto-recovery-time',
        or empty dict if not configured.
    """
    state = _parse_evpn(device)
    return state.get("duplicate-mac-detection", {})


def get_evpn_arp_nd_suppression_counters(device) -> Dict[str, Any]:
    """Get EVPN ARP/ND suppression counters on ArcOS.

    Args:
        device: pyATS device object.

    Returns:
        Dict with keys 'arp-suppression-counters', 'nd-suppression-counters',
        or empty dict if not available.
    """
    state = _parse_evpn(device)
    return state.get("arp-nd-suppression-counters", {})
