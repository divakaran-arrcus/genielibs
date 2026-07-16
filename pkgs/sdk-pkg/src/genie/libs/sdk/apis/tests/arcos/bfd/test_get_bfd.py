#!/usr/bin/env python3
"""Unit tests for arcOS BFD get APIs (full coverage).

genie.libs.sdk.apis.arcos.bfd.get._parse_bfd instantiates
``genie.libs.parser.arcos.show_bfd.ShowBfd`` directly (bypassing
``device.parse``) and calls ``.parse()`` on it. Tests therefore patch the
``ShowBfd`` name as imported into the ``get`` module and return canned
parser output shaped like the real ``ShowBfd`` schema (``{"profile": {...}}``
with peers keyed by local-discriminator).
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.bfd import get as bfd_get
from genie.libs.sdk.apis.arcos.bfd.get import (
    get_bfd_profiles,
    get_bfd_profile,
    get_bfd_profile_count,
    get_bfd_profile_enabled,
    is_bfd_profile_present,
    get_bfd_sessions,
    get_bfd_session,
    get_bfd_session_count,
    get_bfd_session_state,
    is_bfd_session_present,
    get_bfd_session_by_remote,
)

MOD = "genie.libs.sdk.apis.arcos.bfd.get"

CANNED_OUTPUT = {
    "profile": {
        "fast-profile": {
            "id": "fast-profile",
            "enabled": True,
            "desired-minimum-tx-interval": 300,
            "required-minimum-receive": 300,
            "detection-multiplier": 3,
            "v4-hw-offload": True,
            "v6-hw-offload": False,
            "dscp-value": 48,
            "peers": {
                "20": {
                    "local-address": "10.1.1.1",
                    "remote-address": "10.1.1.2",
                    "session-state": "UP",
                    "local-discriminator": 20,
                    "remote-discriminator": 30,
                    "interface": "ethernet-1/1",
                },
                "21": {
                    "local-address": "10.1.2.1",
                    "remote-address": "10.1.2.2",
                    "session-state": "DOWN",
                    "local-discriminator": 21,
                    "remote-discriminator": 0,
                    "interface": "ethernet-1/2",
                },
            },
        },
        "slow-profile": {
            "id": "slow-profile",
            "enabled": False,
            "desired-minimum-tx-interval": 1000,
            "required-minimum-receive": 1000,
            "detection-multiplier": 5,
        },
    }
}


class TestGetBfd(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowBfd")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_bfd_profiles(self):
        profiles = get_bfd_profiles(self.device)
        self.assertEqual(set(profiles), {"fast-profile", "slow-profile"})

    def test_get_bfd_profile_found(self):
        profile = get_bfd_profile(self.device, "fast-profile")
        self.assertEqual(profile["desired-minimum-tx-interval"], 300)

    def test_get_bfd_profile_missing(self):
        self.assertIsNone(get_bfd_profile(self.device, "no-such-profile"))

    def test_get_bfd_profile_count(self):
        self.assertEqual(get_bfd_profile_count(self.device), 2)

    def test_get_bfd_profile_enabled_true(self):
        self.assertTrue(get_bfd_profile_enabled(self.device, "fast-profile"))

    def test_get_bfd_profile_enabled_false(self):
        self.assertFalse(get_bfd_profile_enabled(self.device, "slow-profile"))

    def test_get_bfd_profile_enabled_missing(self):
        self.assertIsNone(
            get_bfd_profile_enabled(self.device, "no-such-profile")
        )

    def test_is_bfd_profile_present_true(self):
        self.assertTrue(is_bfd_profile_present(self.device, "fast-profile"))

    def test_is_bfd_profile_present_false(self):
        self.assertFalse(
            is_bfd_profile_present(self.device, "no-such-profile")
        )

    def test_get_bfd_sessions(self):
        sessions = get_bfd_sessions(self.device, "fast-profile")
        self.assertEqual(set(sessions), {"20", "21"})

    def test_get_bfd_sessions_missing_profile(self):
        self.assertEqual(get_bfd_sessions(self.device, "no-such-profile"), {})

    def test_get_bfd_sessions_profile_without_peers(self):
        self.assertEqual(get_bfd_sessions(self.device, "slow-profile"), {})

    def test_get_bfd_session_found(self):
        session = get_bfd_session(self.device, "fast-profile", "20")
        self.assertEqual(session["remote-address"], "10.1.1.2")

    def test_get_bfd_session_missing(self):
        self.assertIsNone(get_bfd_session(self.device, "fast-profile", "99"))

    def test_get_bfd_session_count(self):
        self.assertEqual(get_bfd_session_count(self.device, "fast-profile"), 2)

    def test_get_bfd_session_count_zero(self):
        self.assertEqual(
            get_bfd_session_count(self.device, "slow-profile"), 0
        )

    def test_get_bfd_session_state(self):
        self.assertEqual(
            get_bfd_session_state(self.device, "fast-profile", "20"), "UP"
        )
        self.assertEqual(
            get_bfd_session_state(self.device, "fast-profile", "21"), "DOWN"
        )

    def test_get_bfd_session_state_missing(self):
        self.assertIsNone(
            get_bfd_session_state(self.device, "fast-profile", "99")
        )

    def test_is_bfd_session_present_true(self):
        self.assertTrue(
            is_bfd_session_present(self.device, "fast-profile", "20")
        )

    def test_is_bfd_session_present_false(self):
        self.assertFalse(
            is_bfd_session_present(self.device, "fast-profile", "99")
        )

    def test_get_bfd_session_by_remote_found(self):
        session = get_bfd_session_by_remote(self.device, "10.1.2.2")
        self.assertEqual(session["session-state"], "DOWN")

    def test_get_bfd_session_by_remote_missing(self):
        self.assertIsNone(
            get_bfd_session_by_remote(self.device, "9.9.9.9")
        )


class TestGetBfdEmpty(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -- _parse_bfd should degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowBfd")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )

    def test_get_bfd_profiles_empty(self):
        self.assertEqual(get_bfd_profiles(self.device), {})

    def test_get_bfd_profile_none(self):
        self.assertIsNone(get_bfd_profile(self.device, "fast-profile"))

    def test_get_bfd_profile_count_zero(self):
        self.assertEqual(get_bfd_profile_count(self.device), 0)

    def test_get_bfd_profile_enabled_none(self):
        self.assertIsNone(
            get_bfd_profile_enabled(self.device, "fast-profile")
        )

    def test_is_bfd_profile_present_false(self):
        self.assertFalse(is_bfd_profile_present(self.device, "fast-profile"))

    def test_get_bfd_sessions_empty(self):
        self.assertEqual(get_bfd_sessions(self.device, "fast-profile"), {})

    def test_get_bfd_session_none(self):
        self.assertIsNone(
            get_bfd_session(self.device, "fast-profile", "20")
        )

    def test_get_bfd_session_count_zero(self):
        self.assertEqual(
            get_bfd_session_count(self.device, "fast-profile"), 0
        )

    def test_get_bfd_session_state_none(self):
        self.assertIsNone(
            get_bfd_session_state(self.device, "fast-profile", "20")
        )

    def test_is_bfd_session_present_false(self):
        self.assertFalse(
            is_bfd_session_present(self.device, "fast-profile", "20")
        )

    def test_get_bfd_session_by_remote_none(self):
        self.assertIsNone(
            get_bfd_session_by_remote(self.device, "10.1.1.2")
        )


class TestBfdGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    bfd/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(bfd_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == bfd_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered BFD get functions: {missing}")

        print(
            f"\nBFD get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
