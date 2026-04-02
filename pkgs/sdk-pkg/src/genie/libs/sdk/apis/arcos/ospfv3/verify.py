"""ArcOS OSPFv3 verify APIs."""

from __future__ import annotations

import logging
from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.ospfv3.get import (
    is_ospfv3_neighbor_full,
    get_ospfv3_router_id,
)

log = logging.getLogger(__name__)


def verify_ospfv3_neighbor_full(device, neighbor_rid, area="*",
                                 max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 neighbor is in FULL state."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            if is_ospfv3_neighbor_full(device, neighbor_rid, area=area):
                return True
        except Exception as exc:
            log.error("is_ospfv3_neighbor_full failed: %s", exc)
        timeout.sleep()
    return False


def verify_ospfv3_router_id(device, expected_rid,
                             max_time=60, check_interval=10) -> bool:
    """Verify OSPFv3 router-id matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            rid = get_ospfv3_router_id(device)
        except Exception as exc:
            log.error("get_ospfv3_router_id failed: %s", exc)
            rid = None

        if rid == expected_rid:
            return True
        timeout.sleep()
    return False
