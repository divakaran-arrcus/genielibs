"""ArcOS gNMI get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_gnmi import ShowGnmiServer

log = logging.getLogger(__name__)


def get_gnmi_server(device) -> Dict[str, Any]:
    """Get gNMI gRPC server state."""
    try:
        parser = ShowGnmiServer(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get gNMI server state: %s", exc)
        return {}


def is_gnmi_server_enabled(device) -> bool:
    """Check if gNMI server is enabled."""
    data = get_gnmi_server(device)
    return data.get("enabled", False)
