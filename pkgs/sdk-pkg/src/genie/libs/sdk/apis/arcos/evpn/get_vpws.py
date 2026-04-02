"""ArcOS EVPN VPWS get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_evpn_vpws import ShowEvpnVpws, ShowL2ribVpwsEviEntries

log = logging.getLogger(__name__)


def get_evpn_vpws_services(device) -> Dict[str, Any]:
    """Get EVPN VPWS services summary."""
    try:
        parser = ShowEvpnVpws(device=device)
        result = parser.parse()
        return result.get("vpws-services", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get EVPN VPWS services: %s", exc)
        return {}


def get_l2rib_vpws_evi_entries(device, ni="*") -> Dict[str, Any]:
    """Get L2RIB VPWS EVI entries."""
    try:
        parser = ShowL2ribVpwsEviEntries(device=device)
        result = parser.parse(ni=ni)
        return result.get("vpws-evi-entries", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get L2RIB VPWS EVI entries: %s", exc)
        return {}
