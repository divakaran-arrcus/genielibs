#!/usr/bin/env python3
"""Unit tests for arcOS IPsec get APIs (full coverage).

genie.libs.sdk.apis.arcos.ipsec.get.get_ipsec_conn_entry instantiates
``genie.libs.parser.arcos.show_ipsec.ShowIpsecConnEntry`` directly and calls
``.parse(name=...)`` on it. Tests therefore patch the ``ShowIpsecConnEntry``
name as imported into the ``get`` module and return canned parser output
shaped like the real ``ShowIpsecConnEntry`` schema (``{"connections": {...}}``
keyed by connection name).
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.ipsec import get as ipsec_get
from genie.libs.sdk.apis.arcos.ipsec.get import get_ipsec_conn_entry

MOD = "genie.libs.sdk.apis.arcos.ipsec.get"

CANNED_OUTPUT = {
    "connections": {
        "vpn1": {
            "name": "vpn1",
            "version": "ikev2",
            "autostartup": "start",
            "authalg": "sha1",
            "encalg": "aes128",
            "dh-group": 14,
            "rekey-time": 3600,
            "spd-entries": {
                "spd1": {
                    "name": "spd1",
                    "local-subnets": ["10.0.1.0/24"],
                    "remote-subnets": ["10.0.2.0/24"],
                }
            },
        }
    }
}


class TestGetIpsec(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowIpsecConnEntry")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_ipsec_conn_entry_found(self):
        result = get_ipsec_conn_entry(self.device, "vpn1")
        self.assertEqual(result, CANNED_OUTPUT)
        self.mock_parser.return_value.parse.assert_called_with(name="vpn1")

    def test_get_ipsec_conn_entry_fields(self):
        result = get_ipsec_conn_entry(self.device, "vpn1")
        entry = result["connections"]["vpn1"]
        self.assertEqual(entry["version"], "ikev2")
        self.assertEqual(entry["authalg"], "sha1")
        self.assertEqual(entry["dh-group"], 14)
        self.assertEqual(
            entry["spd-entries"]["spd1"]["local-subnets"], ["10.0.1.0/24"]
        )


class TestGetIpsecDegrade(unittest.TestCase):
    """Parser raises -- get_ipsec_conn_entry should degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_get_ipsec_conn_entry_empty(self):
        with patch(f"{MOD}.ShowIpsecConnEntry") as mock_parser:
            mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
                "empty"
            )
            self.assertEqual(get_ipsec_conn_entry(self.device, "vpn1"), {})

    def test_get_ipsec_conn_entry_exception(self):
        with patch(f"{MOD}.ShowIpsecConnEntry") as mock_parser:
            mock_parser.return_value.parse.side_effect = RuntimeError("boom")
            self.assertEqual(get_ipsec_conn_entry(self.device, "vpn1"), {})


class TestIpsecGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    ipsec/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ipsec_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ipsec_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Uncovered IPsec get functions: {missing}"
        )

        print(f"\nIPsec get coverage: {len(names)} functions, 0 missing")


if __name__ == "__main__":
    unittest.main()
