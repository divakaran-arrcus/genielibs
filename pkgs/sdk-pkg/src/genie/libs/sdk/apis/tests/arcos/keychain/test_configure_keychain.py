#!/usr/bin/env python3
"""Unit tests for arcOS Keychain configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.keychain.configure builds an arcOS CLI config list
(starting with the `keychain <name>` context, optionally nested under
`key <key_id>`) and calls device.configure(config). Tests mock
device.configure and assert on a distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.keychain import configure as keychain_configure
from genie.libs.sdk.apis.arcos.keychain.configure import (
    configure_keychain,
    unconfigure_keychain,
    configure_keychain_key,
    unconfigure_keychain_key,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureKeychain(unittest.TestCase):
    """configure_keychain / unconfigure_keychain"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_keychain_basic(self):
        configure_keychain(self.d, "isis-key")
        c = self.d.cfg()
        self.assertIn("keychain isis-key", c)
        self.assertIn("!", c)

    def test_configure_keychain_tolerance(self):
        configure_keychain(self.d, "isis-key", tolerance=30)
        c = self.d.cfg()
        self.assertIn("keychain isis-key", c)
        self.assertIn("tolerance 30", c)

    def test_configure_keychain_with_single_key(self):
        configure_keychain(self.d, "isis-key", keys={
            10: {
                "secret_key": "MyPass",
                "crypto_algorithm": "HMAC_SHA_1",
                "send_lifetime_always": True,
                "send_lifetime_start_time": "2024-01-01T00:00:00",
                "send_lifetime_end_time": "2024-12-31T23:59:59",
            }
        })
        c = self.d.cfg()
        self.assertIn("keychain isis-key", c)
        self.assertIn("key 10", c)
        self.assertIn("secret-key MyPass", c)
        self.assertIn("crypto-algorithm HMAC_SHA_1", c)
        self.assertIn("send-lifetime always true", c)
        self.assertIn("send-lifetime start-time 2024-01-01T00:00:00", c)
        self.assertIn("send-lifetime end-time 2024-12-31T23:59:59", c)

    def test_configure_keychain_send_lifetime_always_false(self):
        configure_keychain(self.d, "isis-key", keys={
            10: {"send_lifetime_always": False}
        })
        self.assertIn("send-lifetime always false", self.d.cfg())

    def test_configure_keychain_multiple_keys_sorted_numerically(self):
        # keys dict given out of order (and as int keys) - config must emit
        # them sorted numerically (key 10 before key 20).
        configure_keychain(self.d, "isis-key", keys={
            20: {"secret_key": "second"},
            10: {"secret_key": "first"},
        })
        c = self.d.cfg()
        self.assertIn("key 10", c)
        self.assertIn("key 20", c)
        self.assertLess(c.index("key 10"), c.index("key 20"))

    def test_configure_keychain_skips_non_dict_key_entries(self):
        configure_keychain(self.d, "isis-key", keys={10: "not-a-dict"})
        c = self.d.cfg()
        self.assertIn("keychain isis-key", c)
        self.assertNotIn("key 10", c)

    def test_configure_keychain_no_keys_no_tolerance(self):
        configure_keychain(self.d, "plain-key")
        c = self.d.cfg()
        self.assertIn("keychain plain-key", c)
        self.assertNotIn("tolerance", c)
        self.assertNotIn("key ", c)

    def test_unconfigure_keychain(self):
        unconfigure_keychain(self.d, "isis-key")
        c = self.d.cfg()
        self.assertIn("no keychain isis-key", c)


class TestConfigureKeychainKey(unittest.TestCase):
    """configure_keychain_key / unconfigure_keychain_key"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_keychain_key_full(self):
        configure_keychain_key(
            self.d, "isis-key", 10,
            secret_key="MyPass",
            crypto_algorithm="HMAC_SHA_1",
            send_lifetime_always=True,
            send_lifetime_start_time="2024-01-01T00:00:00",
            send_lifetime_end_time="2024-12-31T23:59:59",
        )
        c = self.d.cfg()
        self.assertIn("keychain isis-key", c)
        self.assertIn("key 10", c)
        self.assertIn("secret-key MyPass", c)
        self.assertIn("crypto-algorithm HMAC_SHA_1", c)
        self.assertIn("send-lifetime always true", c)
        self.assertIn("send-lifetime start-time 2024-01-01T00:00:00", c)
        self.assertIn("send-lifetime end-time 2024-12-31T23:59:59", c)

    def test_configure_keychain_key_send_lifetime_always_false(self):
        configure_keychain_key(self.d, "isis-key", 10, send_lifetime_always=False)
        self.assertIn("send-lifetime always false", self.d.cfg())

    def test_configure_keychain_key_minimal(self):
        configure_keychain_key(self.d, "isis-key", 10)
        c = self.d.cfg()
        self.assertIn("keychain isis-key", c)
        self.assertIn("key 10", c)
        self.assertNotIn("secret-key", c)
        self.assertNotIn("crypto-algorithm", c)
        self.assertNotIn("send-lifetime", c)

    def test_unconfigure_keychain_key(self):
        unconfigure_keychain_key(self.d, "isis-key", 10)
        c = self.d.cfg()
        self.assertIn("keychain isis-key", c)
        self.assertIn("no key 10", c)


class TestConfigureKeychainErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_keychain_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            configure_keychain(self.d, "isis-key")

    def test_unconfigure_keychain_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            unconfigure_keychain(self.d, "isis-key")

    def test_configure_keychain_key_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            configure_keychain_key(self.d, "isis-key", 10)

    def test_unconfigure_keychain_key_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            unconfigure_keychain_key(self.d, "isis-key", 10)


class TestKeychainConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in keychain/configure.py must be referenced by name somewhere
    in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(keychain_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == keychain_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered keychain configure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nKeychain configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
