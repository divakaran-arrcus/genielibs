"""ArcOS EVPN MPLS get APIs."""

from __future__ import annotations
from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_evpn_mpls import (
    ShowEvpnState,
    ShowEvpnEsiInfo,
    ShowL2ribMacEntries,
)

log = logging.getLogger(__name__)


def get_evpn_router_ip(device) -> Optional[str]:
    """Get EVPN selected router IP."""
    try:
        parser = ShowEvpnState(device=device)
        result = parser.parse()
        return result.get("router-ip-selected")
    except SchemaEmptyParserError:
        return None
    except Exception as exc:
        log.error("Failed to get EVPN router-ip: %s", exc)
        return None


def get_evpn_esi_info(device) -> Dict[str, Any]:
    """Get EVPN ESI information."""
    try:
        parser = ShowEvpnEsiInfo(device=device)
        result = parser.parse()
        return result.get("esi-entries", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get EVPN ESI info: %s", exc)
        return {}


def get_l2rib_mac_entries(device, ni="*") -> Dict[str, Any]:
    """Get L2RIB MAC entries for a network-instance."""
    try:
        parser = ShowL2ribMacEntries(device=device)
        result = parser.parse(ni=ni)
        return result.get("mac-entries", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get L2RIB MAC entries: %s", exc)
        return {}
