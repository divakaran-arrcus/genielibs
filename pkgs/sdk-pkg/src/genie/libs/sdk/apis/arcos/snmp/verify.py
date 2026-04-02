"""ArcOS SNMP verify APIs."""

from __future__ import annotations

import logging
from genie.utils.timeout import Timeout

from genie.libs.sdk.apis.arcos.snmp.get import is_snmp_server_enabled

log = logging.getLogger(__name__)


def verify_snmp_server_enabled(device, max_time=30, check_interval=5) -> bool:
    """Verify SNMP server is enabled."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            if is_snmp_server_enabled(device):
                return True
        except Exception as exc:
            log.error("is_snmp_server_enabled failed: %s", exc)
        timeout.sleep()
    return False


def verify_snmp_server_disabled(device, max_time=30, check_interval=5) -> bool:
    """Verify SNMP server is disabled."""
    timeout = Timeout(max_time, check_interval)
    while timeout.iterate():
        try:
            if not is_snmp_server_enabled(device):
                return True
        except Exception as exc:
            log.error("is_snmp_server_enabled failed: %s", exc)
        timeout.sleep()
    return False
