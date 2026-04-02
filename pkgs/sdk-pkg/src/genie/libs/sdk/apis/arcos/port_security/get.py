"""ArcOS Port Security get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_port_security import ShowPortSecurity

log = logging.getLogger(__name__)


def get_port_security(device) -> Dict[str, Any]:
    """Get port-security state."""
    try:
        parser = ShowPortSecurity(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get port security state: %s", exc)
        return {}
