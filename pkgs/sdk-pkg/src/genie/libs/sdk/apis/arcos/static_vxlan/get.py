"""ArcOS Static VXLAN get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_static_vxlan import ShowStaticVxlanTunnels

log = logging.getLogger(__name__)


def get_static_vxlan_tunnels(device) -> Dict[str, Any]:
    """Get static VXLAN tunnel state."""
    try:
        parser = ShowStaticVxlanTunnels(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get static VXLAN tunnels: %s", exc)
        return {}
