"""ArcOS BGP 6PE get APIs.

Extends BGP get APIs with 6PE-specific functions for label database
and IPv6 labeled unicast route verification.
"""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_bgp import ShowBgpLabelDb, ShowBgpGlobalAfiSafi

log = logging.getLogger(__name__)


def get_bgp_label_db(device, ni="default", instance="default") -> Dict[str, Any]:
    """Get BGP MPLS label database.

    Args:
        device: pyATS device object.
        ni: Network instance (default 'default').
        instance: BGP protocol instance (default 'default').

    Returns:
        Dict with label entries, or empty dict if none found.
    """
    try:
        parser = ShowBgpLabelDb(device=device)
        result = parser.parse(ni=ni, instance=instance)
        return result.get("labels", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get BGP label-db: %s", exc)
        return {}


def get_bgp_label_count(device, ni="default", instance="default") -> int:
    """Get count of BGP MPLS labels allocated."""
    labels = get_bgp_label_db(device, ni=ni, instance=instance)
    return len(labels)


def is_bgp_6pe_afi_safi_active(device, ni="default",
                                instance="default") -> bool:
    """Check if IPV6_LABELED_UNICAST AFI-SAFI is active in BGP.

    Returns True if the AFI-SAFI has at least one prefix.
    """
    try:
        parser = ShowBgpGlobalAfiSafi(device=device)
        result = parser.parse(network_instance=ni, protocol_instance=instance)
        afis = result.get("afi-safis", {})
        labeled = afis.get("IPV6_LABELED_UNICAST", {})
        total = labeled.get("total-prefixes", 0)
        return total > 0
    except SchemaEmptyParserError:
        return False
    except Exception as exc:
        log.error("Failed to check BGP 6PE AFI-SAFI: %s", exc)
        return False
