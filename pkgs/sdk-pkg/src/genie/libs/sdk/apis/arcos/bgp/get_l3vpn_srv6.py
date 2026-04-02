"""ArcOS BGP L3VPN-SRv6 get APIs.

Extends BGP get APIs with SRv6-specific functions for SID allocation
and per-nexthop SID state.
"""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_bgp import ShowBgpGlobalState

log = logging.getLogger(__name__)


def get_bgp_srv6_tunnels(device) -> Dict[str, Any]:
    """Get BGP SRv6 tunnel state from global BGP.

    Returns:
        Dict with tunnel information, or empty dict.
    """
    try:
        parser = ShowBgpGlobalState(device=device)
        result = parser.parse()
        return result.get("tunnels", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get BGP SRv6 tunnels: %s", exc)
        return {}


def get_bgp_vrf_sid_state(device, vrf_name, protocol_instance=None) -> Dict[str, Any]:
    """Get BGP VRF SID allocation state for SRv6.

    Queries the VRF AFI-SAFI state for per-nexthop SID information.

    Args:
        device: pyATS device object.
        vrf_name: VRF network-instance name.
        protocol_instance: BGP protocol instance (defaults to vrf_name).

    Returns:
        Dict with SID info, or empty dict.
    """
    from genie.libs.parser.arcos.show_bgp import ShowBgpGlobalAfiSafi

    pi = protocol_instance or vrf_name
    try:
        parser = ShowBgpGlobalAfiSafi(device=device)
        result = parser.parse(network_instance=vrf_name, protocol_instance=pi)
        return result.get("afi-safis", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get BGP VRF SID state for %s: %s", vrf_name, exc)
        return {}
