"""ArcOS DHCP Relay get APIs."""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_dhcp_relay import ShowDhcpRelay

log = logging.getLogger(__name__)


def get_dhcp_relay(device) -> Dict[str, Any]:
    """Get DHCP relay state."""
    try:
        parser = ShowDhcpRelay(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get DHCP relay state: %s", exc)
        return {}
