"""ArcOS Monitor Session get APIs."""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_monitor_session import ShowMonitorSession

log = logging.getLogger(__name__)


def get_monitor_sessions(device) -> Dict[str, Any]:
    """Get all monitor sessions."""
    try:
        parser = ShowMonitorSession(device=device)
        result = parser.parse()
        return result.get("sessions", {})
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get monitor sessions: %s", exc)
        return {}


def is_monitor_session_present(device, name) -> bool:
    """Check if a monitor session exists."""
    sessions = get_monitor_sessions(device)
    return name in sessions
