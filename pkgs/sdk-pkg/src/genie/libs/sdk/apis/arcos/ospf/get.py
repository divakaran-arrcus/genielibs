"""ArcOS OSPF get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_ospf import ShowOspfGlobal, ShowOspfNeighbor

log = logging.getLogger(__name__)


def get_ospf_global(device) -> Dict[str, Any]:
    """Get OSPF global state."""
    try:
        parser = ShowOspfGlobal(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF global: %s", exc)
        return {}


def get_ospf_router_id(device) -> Optional[str]:
    """Get OSPF router-id."""
    data = get_ospf_global(device)
    return data.get("router-id")


def get_ospf_neighbor_count(device) -> int:
    """Get OSPF neighbor count."""
    data = get_ospf_global(device)
    return data.get("full-neighbor-count", 0)


def get_ospf_neighbors(device, area="*") -> Dict[str, Any]:
    """Get OSPF neighbors."""
    try:
        parser = ShowOspfNeighbor(device=device)
        result = parser.parse(area=area)
        return result.get("neighbors", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPF neighbors: %s", exc)
        return {}


def is_ospf_neighbor_full(device, neighbor_rid, area="*") -> bool:
    """Check if an OSPF neighbor is in FULL state."""
    nbrs = get_ospf_neighbors(device, area=area)
    for key, nbr in nbrs.items():
        if nbr.get("neighbor-router-id") == neighbor_rid:
            return nbr.get("adjacency-state") == "NEIGHBOR_FULL"
    return False
