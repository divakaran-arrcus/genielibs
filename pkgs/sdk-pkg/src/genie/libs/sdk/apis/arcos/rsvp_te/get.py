"""ArcOS RSVP-TE get APIs."""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_rsvp_te import ShowRsvpGlobal

log = logging.getLogger(__name__)


def get_rsvp_global(device) -> Dict[str, Any]:
    """Get RSVP-TE global state."""
    try:
        parser = ShowRsvpGlobal(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get RSVP global state: %s", exc)
        return {}
