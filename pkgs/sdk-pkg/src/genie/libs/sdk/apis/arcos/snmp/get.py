"""ArcOS SNMP get APIs."""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_snmp import ShowSnmpServer

log = logging.getLogger(__name__)


def get_snmp_server(device) -> Dict[str, Any]:
    """Get SNMP server state."""
    try:
        parser = ShowSnmpServer(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get SNMP server state: %s", exc)
        return {}


def is_snmp_server_enabled(device) -> bool:
    """Check if SNMP server is enabled."""
    data = get_snmp_server(device)
    return data.get("enabled", False)
