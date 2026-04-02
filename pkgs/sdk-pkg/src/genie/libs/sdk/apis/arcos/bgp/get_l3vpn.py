"""ArcOS BGP L3VPN get APIs.

Extends BGP get APIs with L3VPN-specific functions for VRF BGP state,
deaggregation labels, and exported VPN routes.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_bgp import ShowBgpGlobalState, ShowBgpGlobalAfiSafi
from genie.libs.parser.arcos.show_bgp_l3vpn import (
    ShowBgpDeaggregationLabel,
    ShowBgpVpnExportedRoutes,
)

log = logging.getLogger(__name__)


def get_bgp_vrf_state(device, vrf_name, protocol_instance=None) -> Dict[str, Any]:
    """Get BGP global state for a VRF network-instance.

    Args:
        device: pyATS device object.
        vrf_name: VRF network-instance name.
        protocol_instance: BGP protocol instance (defaults to vrf_name).

    Returns:
        Dict with BGP global state for the VRF, or empty dict.
    """
    pi = protocol_instance or vrf_name
    try:
        parser = ShowBgpGlobalState(device=device)
        return parser.parse(network_instance=vrf_name, protocol_instance=pi)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get BGP VRF state for %s: %s", vrf_name, exc)
        return {}


def get_bgp_vrf_afi_safi_state(device, vrf_name, protocol_instance=None) -> Dict[str, Any]:
    """Get BGP AFI-SAFI state for a VRF.

    Returns per-AFI stats including total-paths, total-prefixes, labels.
    """
    pi = protocol_instance or vrf_name
    try:
        parser = ShowBgpGlobalAfiSafi(device=device)
        result = parser.parse(network_instance=vrf_name, protocol_instance=pi)
        return result.get("afi-safis", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get BGP VRF AFI-SAFI for %s: %s", vrf_name, exc)
        return {}


def get_bgp_deaggregation_labels(device) -> Dict[str, Any]:
    """Get BGP deaggregation label state across all VRFs/AFI-SAFIs.

    Returns:
        Dict with VRF/AFI-SAFI deaggregation label info.
    """
    try:
        parser = ShowBgpDeaggregationLabel(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get BGP deaggregation labels: %s", exc)
        return {}


def get_bgp_vpn_exported_routes(device, afi_safi='L3VPN_IPV4_UNICAST',
                                 vrf_name='*') -> Dict[str, Any]:
    """Get BGP VPN exported routes.

    Args:
        device: pyATS device object.
        afi_safi: L3VPN_IPV4_UNICAST or L3VPN_IPV6_UNICAST.
        vrf_name: VRF name filter (default '*' for all).

    Returns:
        Dict with exported route entries.
    """
    try:
        parser = ShowBgpVpnExportedRoutes(device=device)
        return parser.parse(afi_safi=afi_safi, vrf_name=vrf_name)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get BGP VPN exported routes: %s", exc)
        return {}
