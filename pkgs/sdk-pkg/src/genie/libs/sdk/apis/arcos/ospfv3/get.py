"""ArcOS OSPFv3 get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_ospfv3 import ShowOspfv3Global, ShowOspfv3Neighbor

log = logging.getLogger(__name__)


def get_ospfv3_global(device) -> Dict[str, Any]:
    """Get OSPFv3 global state."""
    try:
        parser = ShowOspfv3Global(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 global: %s", exc)
        return {}


def get_ospfv3_router_id(device) -> Optional[str]:
    """Get OSPFv3 router-id."""
    data = get_ospfv3_global(device)
    return data.get("router-id")


def get_ospfv3_neighbor_count(device) -> int:
    """Get OSPFv3 neighbor count."""
    data = get_ospfv3_global(device)
    return data.get("full-neighbor-count", 0)


def get_ospfv3_neighbors(device, area="*") -> Dict[str, Any]:
    """Get OSPFv3 neighbors."""
    try:
        parser = ShowOspfv3Neighbor(device=device)
        result = parser.parse(area=area)
        return result.get("neighbors", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get OSPFv3 neighbors: %s", exc)
        return {}


def is_ospfv3_neighbor_full(device, neighbor_rid, area="*") -> bool:
    """Check if an OSPFv3 neighbor is in FULL state."""
    nbrs = get_ospfv3_neighbors(device, area=area)
    for key, nbr in nbrs.items():
        if nbr.get("neighbor-router-id") == neighbor_rid:
            return nbr.get("adjacency-state") == "NEIGHBOR_FULL"
    return False
