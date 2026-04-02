"""ArcOS Telemetry get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_telemetry import ShowTelemetry

log = logging.getLogger(__name__)


def get_telemetry_state(device) -> Dict[str, Any]:
    """Get telemetry system state."""
    try:
        parser = ShowTelemetry(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get telemetry state: %s", exc)
        return {}
