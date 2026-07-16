#!/usr/bin/env python3
"""Unit tests for arcOS Keychain get APIs (full coverage).

genie.libs.sdk.apis.arcos.keychain.get instantiates
``genie.libs.parser.arcos.show_keychain.ShowKeychainConfig`` /
``ShowKeychain`` directly (bypassing ``device.parse``) and calls
``.parse()`` on them. Tests therefore patch the parser class names as
imported into the ``get`` module and return canned parser output shaped
like the real ``ShowKeychainConfig``/``ShowKeychain`` schema
(``{"keychains": {<name>: {...}}}``).
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.keychain import get as keychain_get
from genie.libs.sdk.apis.arcos.keychain.get import (
    get_keychains,
    get_keychain,
    get_keychain_count,
    is_keychain_present,
    _parse_keychain_config,
    _parse_keychain_state,
)

MOD = "genie.libs.sdk.apis.arcos.keychain.get"

_CONFIG_PARSED = {
    "keychains": {
        "isis-key": {
            "name": "isis-key",
            "tolerance": 30,
            "keys": {
                "10": {
                    "key-id": "10",
                    "secret-key": "MyPass",
                    "crypto-algorithm": "HMAC_SHA_1",
                    "send-lifetime": {"always": True},
                },
            },
        },
        "bgp-key": {
            "name": "bgp-key",
        },
    }
}

_STATE_PARSED = {
    "keychains": {
        "isis-key": {
            "name": "isis-key",
            "tolerance": 30,
            "keys": {
                "10": {
                    "key-id": "10",
                    "crypto-algorithm": "HMAC_SHA_1",
                    "send-active": True,
                    "receive-active": True,
                    "send-lifetime": {
                        "always": True,
                        "send-and-receive": True,
                    },
                },
            },
        },
    }
}


class TestGetKeychainConfig(unittest.TestCase):
    """get_keychains / get_keychain / get_keychain_count / is_keychain_present"""

    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychains(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        result = get_keychains(self.device)
        self.assertEqual(set(result), {"isis-key", "bgp-key"})
        self.assertEqual(result["isis-key"]["tolerance"], 30)

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychain_found(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        result = get_keychain(self.device, "isis-key")
        self.assertEqual(result["name"], "isis-key")
        self.assertEqual(result["keys"]["10"]["secret-key"], "MyPass")

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychain_not_found(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        self.assertIsNone(get_keychain(self.device, "no-such-key"))

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychain_count(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        self.assertEqual(get_keychain_count(self.device), 2)

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_is_keychain_present_true(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        self.assertTrue(is_keychain_present(self.device, "isis-key"))

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_is_keychain_present_false(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        self.assertFalse(is_keychain_present(self.device, "no-such-key"))


class TestGetKeychainEmpty(unittest.TestCase):
    """Empty / error handling: SchemaEmptyParserError, SubCommandFailure,
    and unexpected exceptions must all degrade to an empty dict / falsy
    result rather than propagating (all handled inside
    _parse_keychain_config).
    """

    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychains_empty_schema_error(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_keychains(self.device), {})

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychains_subcommand_failure(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SubCommandFailure("bad")
        self.assertEqual(get_keychains(self.device), {})

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychains_unexpected_error(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = ValueError("boom")
        self.assertEqual(get_keychains(self.device), {})

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychain_none_when_empty(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertIsNone(get_keychain(self.device, "isis-key"))

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_get_keychain_count_zero_when_empty(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_keychain_count(self.device), 0)

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_is_keychain_present_false_when_empty(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertFalse(is_keychain_present(self.device, "isis-key"))


class TestParseKeychainConfigHelper(unittest.TestCase):
    """_parse_keychain_config direct exercise (all 3 error branches)."""

    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_parse_keychain_config_success(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        self.assertEqual(_parse_keychain_config(self.device), _CONFIG_PARSED)

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_parse_keychain_config_with_name_filter(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _CONFIG_PARSED
        result = _parse_keychain_config(self.device, name="isis-key")
        mock_parser_cls.return_value.parse.assert_called_with(name="isis-key")
        self.assertEqual(result, _CONFIG_PARSED)

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_parse_keychain_config_schema_empty(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(_parse_keychain_config(self.device), {})

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_parse_keychain_config_subcommand_failure(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SubCommandFailure("bad")
        self.assertEqual(_parse_keychain_config(self.device), {})

    @patch(f"{MOD}.ShowKeychainConfig")
    def test_parse_keychain_config_unexpected_error(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = ValueError("boom")
        self.assertEqual(_parse_keychain_config(self.device), {})


class TestParseKeychainStateHelper(unittest.TestCase):
    """_parse_keychain_state (operational-state helper, built on
    ShowKeychain). Not exercised by any public get_*/is_* function today,
    but it is part of the module's surface - exercised directly here for
    completeness / full statement coverage.
    """

    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowKeychain")
    def test_parse_keychain_state_success(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _STATE_PARSED
        result = _parse_keychain_state(self.device)
        self.assertEqual(
            result["keychains"]["isis-key"]["keys"]["10"]["send-active"], True
        )

    @patch(f"{MOD}.ShowKeychain")
    def test_parse_keychain_state_with_name_filter(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.return_value = _STATE_PARSED
        result = _parse_keychain_state(self.device, name="isis-key")
        mock_parser_cls.return_value.parse.assert_called_with(name="isis-key")
        self.assertEqual(result, _STATE_PARSED)

    @patch(f"{MOD}.ShowKeychain")
    def test_parse_keychain_state_schema_empty(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(_parse_keychain_state(self.device), {})

    @patch(f"{MOD}.ShowKeychain")
    def test_parse_keychain_state_subcommand_failure(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = SubCommandFailure("bad")
        self.assertEqual(_parse_keychain_state(self.device), {})

    @patch(f"{MOD}.ShowKeychain")
    def test_parse_keychain_state_unexpected_error(self, mock_parser_cls):
        mock_parser_cls.return_value.parse.side_effect = ValueError("boom")
        self.assertEqual(_parse_keychain_state(self.device), {})


class TestKeychainGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    keychain/get.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(keychain_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == keychain_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered keychain get functions: {missing}")

        print(
            f"\nKeychain get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
