"""ArcOS TE get APIs.

High-level helpers built on top of the upstream ArcOS TE parser
``genie.libs.parser.arcos.show_te.ShowTeAdminGroup``.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def _parse_te_admin_groups(device, network_instance='default') -> Dict[str, Any]:
    """Parse TE admin-group data using ShowTeAdminGroup parser.

    Args:
        device: pyATS device object.
        network_instance: Network instance name.

    Returns:
        Dict of admin-groups keyed by name, or empty dict on error.
    """
    try:
        from genie.libs.parser.arcos.show_te import ShowTeAdminGroup
        parser = ShowTeAdminGroup(device=device)
        parsed = parser.parse(network_instance=network_instance)
    except SchemaEmptyParserError:
        log.debug("_parse_te_admin_groups: no data found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_te_admin_groups: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:
        log.warning("_parse_te_admin_groups: Unexpected exception - %s", exc)
        return {}

    ni_data = parsed.get("network-instance", {}).get(network_instance, {})
    return ni_data.get("admin-groups", {})


def get_te_admin_groups(device, network_instance='default') -> Dict[str, Any]:
    """Get all TE admin-groups on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").

    Returns:
        Dict of admin-groups keyed by name, each containing
        'name' and 'bit-position'. Empty dict if none found.
    """
    return _parse_te_admin_groups(device, network_instance)


def get_te_admin_group(device, name, network_instance='default') -> Optional[Dict[str, Any]]:
    """Get a specific TE admin-group by name on ArcOS.

    Args:
        device: pyATS device object.
        name: Admin-group name (e.g., 'red').
        network_instance: Network instance name (default: "default").

    Returns:
        Dict with admin-group data (name, bit-position) if found,
        None otherwise.
    """
    groups = _parse_te_admin_groups(device, network_instance)
    return groups.get(name)


def is_te_admin_group_present(device, name, network_instance='default') -> bool:
    """Check if a TE admin-group exists on ArcOS.

    Args:
        device: pyATS device object.
        name: Admin-group name to check.
        network_instance: Network instance name (default: "default").

    Returns:
        True if admin-group exists, False otherwise.
    """
    group = get_te_admin_group(device, name, network_instance)
    return group is not None


def get_te_admin_group_count(device, network_instance='default') -> int:
    """Get count of TE admin-groups on ArcOS.

    Args:
        device: pyATS device object.
        network_instance: Network instance name (default: "default").

    Returns:
        Number of admin-groups.
    """
    groups = _parse_te_admin_groups(device, network_instance)
    return len(groups)
