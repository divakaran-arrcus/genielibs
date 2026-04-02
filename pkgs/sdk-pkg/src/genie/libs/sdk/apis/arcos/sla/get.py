"""ArcOS SLA get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_sla import ShowSlaIcmp

log = logging.getLogger(__name__)


def get_sla_icmp(device, network_instance='default') -> Dict[str, Any]:
    """Get SLA ICMP state."""
    try:
        parser = ShowSlaIcmp(device=device)
        return parser.parse(ni=network_instance)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get SLA ICMP state: %s", exc)
        return {}
