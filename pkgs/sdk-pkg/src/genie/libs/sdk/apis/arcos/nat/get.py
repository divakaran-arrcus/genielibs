"""ArcOS NAT get APIs."""

from __future__ import annotations
from typing import Dict, Any
import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.parser.arcos.show_nat import ShowNatInstance

log = logging.getLogger(__name__)


def get_nat_instance(device, instance_id) -> Dict[str, Any]:
    """Get NAT instance state."""
    try:
        parser = ShowNatInstance(device=device)
        return parser.parse(instance_id=instance_id)
    except SchemaEmptyParserError:
        return {}
    except Exception as exc:
        log.error("Failed to get NAT instance: %s", exc)
        return {}
