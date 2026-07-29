"""ArcOS BFD get APIs.

High-level helpers built on top of the upstream ArcOS BFD parser
``genie.libs.parser.arcos.show_bfd.ShowBfd``.

These functions wrap ``device.parse("show bfd ...")`` and return
simplified dictionaries for common use cases.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
import logging
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_bfd import ShowBfd

log = logging.getLogger(__name__)


def _parse_bfd(device) -> Dict[str, Any]:
    """Parse BFD operational state from the device.

    Uses the ``ShowBfd`` parser class directly (bypasses ``device.parse``
    lookup) and handles common failure modes so callers always receive a
    dictionary.

    Args:
        device: pyATS device object.

    Returns:
        Parsed BFD output dictionary, or ``{}`` on any error.
    """
    try:
        parser = ShowBfd(device=device)
        return parser.parse()
    except SchemaEmptyParserError:
        log.debug("BFD parser returned empty output")
        return {}
    except SubCommandFailure as exc:
        log.warning("BFD command failed: %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("Unexpected error parsing BFD output: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Profile-level helpers
# ---------------------------------------------------------------------------


def get_bfd_profiles(device) -> Dict[str, Any]:
    """Get all BFD profiles from the device.

    Args:
        device: pyATS device object.

    Returns:
        Dictionary keyed by profile name, or ``{}`` when no profiles
        are present.
    """
    return _parse_bfd(device).get("profile", {})


def get_bfd_profile(device, profile_name: str) -> Optional[Dict[str, Any]]:
    """Get a single BFD profile by name.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile to retrieve.

    Returns:
        Profile dictionary if found, ``None`` otherwise.
    """
    return get_bfd_profiles(device).get(profile_name)


def get_bfd_profile_count(device) -> int:
    """Get the number of BFD profiles configured on the device.

    Args:
        device: pyATS device object.

    Returns:
        Integer count of BFD profiles.
    """
    return len(get_bfd_profiles(device))


def get_bfd_profile_enabled(device, profile_name: str) -> Optional[bool]:
    """Check whether a BFD profile is enabled.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile.

    Returns:
        ``True`` or ``False`` reflecting the profile's *enabled* flag,
        or ``None`` if the profile does not exist.
    """
    profile = get_bfd_profile(device, profile_name)
    if not profile:
        return None
    return profile.get("enabled")


def is_bfd_profile_present(device, profile_name: str) -> bool:
    """Check whether a BFD profile exists on the device.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile to look for.

    Returns:
        ``True`` if the profile is present, ``False`` otherwise.
    """
    return profile_name in get_bfd_profiles(device)


# ---------------------------------------------------------------------------
# Session (peer)-level helpers
# ---------------------------------------------------------------------------


def get_bfd_sessions(device, profile_name: str) -> Dict[str, Any]:
    """Get all BFD sessions (peers) under a given profile.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile.

    Returns:
        Dictionary of sessions keyed by local-discriminator string,
        or ``{}`` if the profile is not found.
    """
    profile = get_bfd_profile(device, profile_name)
    if not profile:
        return {}
    return profile.get("peers", {})


def get_bfd_session(
    device, profile_name: str, discriminator: str
) -> Optional[Dict[str, Any]]:
    """Get a single BFD session by its local discriminator.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile.
        discriminator: Local discriminator value (converted to ``str``
            for the lookup).

    Returns:
        Session dictionary if found, ``None`` otherwise.
    """
    sessions = get_bfd_sessions(device, profile_name)
    return sessions.get(str(discriminator))


def get_bfd_session_count(device, profile_name: str) -> int:
    """Get the number of BFD sessions under a profile.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile.

    Returns:
        Integer count of BFD sessions for the given profile.
    """
    return len(get_bfd_sessions(device, profile_name))


def get_bfd_session_state(
    device, profile_name: str, discriminator: str
) -> Optional[str]:
    """Get the session state of a specific BFD session.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile.
        discriminator: Local discriminator value.

    Returns:
        Session state string (e.g. ``"UP"``, ``"DOWN"``), or ``None``
        if the session is not found.
    """
    session = get_bfd_session(device, profile_name, discriminator)
    if not session:
        return None
    return session.get("session-state")


def is_bfd_session_present(
    device, profile_name: str, discriminator: str
) -> bool:
    """Check whether a BFD session exists under a profile.

    Args:
        device: pyATS device object.
        profile_name: Name of the BFD profile.
        discriminator: Local discriminator value.

    Returns:
        ``True`` if the session is present, ``False`` otherwise.
    """
    return str(discriminator) in get_bfd_sessions(device, profile_name)


def get_bfd_session_by_remote(
    device, remote_address: str
) -> Optional[Dict[str, Any]]:
    """Find a BFD session by its remote peer address.

    Searches across all profiles and returns the first session whose
    ``remote-address`` matches *remote_address*.

    Args:
        device: pyATS device object.
        remote_address: Remote IP address to search for.

    Returns:
        Session dictionary of the first match, or ``None`` if no
        session with that remote address is found.
    """
    profiles = get_bfd_profiles(device)
    for profile_data in profiles.values():
        for peer_data in profile_data.get("peers", {}).values():
            if peer_data.get("remote-address") == remote_address:
                return peer_data
    return None
