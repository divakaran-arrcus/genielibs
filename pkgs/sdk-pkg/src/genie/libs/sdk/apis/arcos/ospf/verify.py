"""ArcOS OSPF verify APIs."""

from __future__ import annotations

import logging
from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.ospf.get import (
    is_ospf_neighbor_full,
    get_ospf_router_id,
)

log = logging.getLogger(__name__)


def verify_ospf_neighbor_full(device, neighbor_rid, area="*",
                                max_time=60, check_interval=10) -> bool:
    """Verify OSPF neighbor is in FULL state."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            if is_ospf_neighbor_full(device, neighbor_rid, area=area):
                return True
        except Exception as exc:
            log.error("is_ospf_neighbor_full failed: %s", exc)
        timeout.sleep()
    return False


def verify_ospf_router_id(device, expected_rid,
                            max_time=60, check_interval=10) -> bool:
    """Verify OSPF router-id matches expected."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            rid = get_ospf_router_id(device)
        except Exception as exc:
            log.error("get_ospf_router_id failed: %s", exc)
            rid = None

        if rid == expected_rid:
            return True
        timeout.sleep()
    return False
