"""ArcOS Bridge Isolation get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_bridge_isolation import ShowBridgeIsolation

log = logging.getLogger(__name__)


def get_bridge_isolation(device, interface) -> Dict[str, Any]:
    """Get bridge isolation state for an interface."""
    try:
        parser = ShowBridgeIsolation(device=device)
        return parser.parse(interface=interface)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get bridge isolation state: %s", exc)
        return {}
