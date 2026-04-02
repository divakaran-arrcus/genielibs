"""ArcOS STP get APIs."""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_stp import ShowStpGlobal

log = logging.getLogger(__name__)


def get_stp_global(device) -> Dict[str, Any]:
    """Get STP global state."""
    try:
        parser = ShowStpGlobal(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get STP global state: %s", exc)
        return {}


def get_stp_enabled_protocol(device) -> Optional[str]:
    """Get STP enabled protocol."""
    data = get_stp_global(device)
    return data.get("enabled-protocol")
