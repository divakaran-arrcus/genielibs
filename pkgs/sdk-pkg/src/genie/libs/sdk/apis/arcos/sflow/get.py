"""ArcOS sFlow get APIs."""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_sflow import ShowSflow

log = logging.getLogger(__name__)


def get_sflow_state(device) -> Dict[str, Any]:
    """Get sFlow global state."""
    try:
        parser = ShowSflow(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get sFlow state: %s", exc)
        return {}
