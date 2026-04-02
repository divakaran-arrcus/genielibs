"""ArcOS IPFIX get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_ipfix import ShowIpfix

log = logging.getLogger(__name__)


def get_ipfix_state(device) -> Dict[str, Any]:
    """Get IPFIX state."""
    try:
        parser = ShowIpfix(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get IPFIX state: %s", exc)
        return {}
