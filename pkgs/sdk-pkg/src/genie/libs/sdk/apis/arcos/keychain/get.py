"""ArcOS Keychain get APIs.

High-level helpers built on top of the upstream ArcOS Keychain parsers
in ``genie.libs.parser.arcos.show_keychain``.

These functions use parser classes directly (not ``device.parse``) and
return simplified dictionaries for common use cases.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

import logging

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.parser.arcos.show_keychain import (
    ShowKeychainConfig,
    ShowKeychain,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_keychain_config(device, name: Optional[str] = None) -> Dict[str, Any]:
    """Parse keychain running configuration.

    Args:
        device: pyATS device object.
        name: Optional keychain name to filter.

    Returns:
        Parsed output dict from ShowKeychainConfig, or empty dict on error.
    """
    try:
        return ShowKeychainConfig(device=device).parse(name=name)
    except SchemaEmptyParserError:
        log.debug("_parse_keychain_config: no keychain config found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_keychain_config: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_keychain_config: unexpected error - %s", exc)
        return {}


def _parse_keychain_state(device, name: Optional[str] = None) -> Dict[str, Any]:
    """Parse keychain operational state.

    Args:
        device: pyATS device object.
        name: Optional keychain name to filter.

    Returns:
        Parsed output dict from ShowKeychain, or empty dict on error.
    """
    try:
        return ShowKeychain(device=device).parse(name=name)
    except SchemaEmptyParserError:
        log.debug("_parse_keychain_state: no keychain state found")
        return {}
    except SubCommandFailure as exc:
        log.debug("_parse_keychain_state: SubCommandFailure - %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("_parse_keychain_state: unexpected error - %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Public get APIs
# ---------------------------------------------------------------------------

def get_keychains(device) -> Dict[str, Any]:
    """Get all keychains from running configuration.

    Args:
        device: pyATS device object.

    Returns:
        Dictionary of keychains keyed by keychain name, e.g.::

            {
                "isis-key": {
                    "name": "isis-key",
                    "tolerance": 30,
                    "keys": {
                        "10": {"key-id": "10", "crypto-algorithm": "HMAC_SHA_1", ...},
                        ...
                    }
                }
            }

        Returns empty dict if no keychains are found.
    """
    parsed = _parse_keychain_config(device)
    return parsed.get("keychains", {})


def get_keychain(device, name: str) -> Optional[Dict[str, Any]]:
    """Get a single keychain by name from running configuration.

    Args:
        device: pyATS device object.
        name: Keychain name to retrieve.

    Returns:
        Dictionary with the keychain details, or None if not found.
    """
    parsed = _parse_keychain_config(device, name=name)
    keychains = parsed.get("keychains", {})
    return keychains.get(name)


def get_keychain_count(device) -> int:
    """Get the number of configured keychains.

    Args:
        device: pyATS device object.

    Returns:
        Number of configured keychains.
    """
    keychains = get_keychains(device)
    return len(keychains)


def is_keychain_present(device, name: str) -> bool:
    """Check if a keychain exists in running configuration.

    Args:
        device: pyATS device object.
        name: Keychain name to check.

    Returns:
        True if the keychain is present, False otherwise.
    """
    return get_keychain(device, name) is not None
