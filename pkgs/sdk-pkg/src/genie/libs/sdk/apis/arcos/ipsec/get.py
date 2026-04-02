"""ArcOS IPsec get APIs."""

from __future__ import annotations

from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_ipsec import ShowIpsecConnEntry

log = logging.getLogger(__name__)


def get_ipsec_conn_entry(device, name) -> Dict[str, Any]:
    """Get IPsec IKE connection entry state."""
    try:
        parser = ShowIpsecConnEntry(device=device)
        return parser.parse(name=name)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get IPsec conn-entry: %s", exc)
        return {}
