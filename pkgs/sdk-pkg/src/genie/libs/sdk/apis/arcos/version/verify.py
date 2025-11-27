"""ArcOS version verify APIs."""

import logging
from typing import Optional

from genie.libs.sdk.apis.arcos.version.get import get_software_version

log = logging.getLogger(__name__)


def verify_software_version(device, expected_version: str) -> bool:
    """Verify that the running ArcOS software version matches ``expected_version``.

    This helper is intentionally simple (no polling/timeout) because the
    software version is effectively static during the test run.

    Args:
        device: pyATS/Unicon device object.
        expected_version: Expected software version string
            (for example, ``"8.2.1A"``).

    Returns:
        ``True`` if the current version equals ``expected_version``,
        ``False`` otherwise.
    """

    current: Optional[str] = get_software_version(device)

    log.info(
        "verify_software_version: expected=%s current=%s",
        expected_version,
        current,
    )

    return current == expected_version
