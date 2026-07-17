#!/usr/bin/env python3
"""Unit tests for arcOS Network Instance get APIs (full coverage).

get.py builds a fresh ShowNetworkInstance parser instance per call
(``from genie.libs.parser.arcos.show_network_instance import
ShowNetworkInstance``) inside the private ``_parse_network_instance``
helper, so tests patch the class at its home module
(``genie.libs.parser.arcos.show_network_instance.ShowNetworkInstance``)
and script its ``.parse()`` return value / side effect. Canned data is
shaped like the *parsed* (flattened) output of
ShowNetworkInstance.parse(), matching the ShowNetworkInstanceSchema.
"""

import unittest
from unittest.mock import patch, Mock

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.network_instance.get import (
    get_network_instance,
    get_network_instance_interfaces,
    get_network_instance_fdb_mac_entries,
    get_network_instance_fdb_mac_count,
    get_network_instance_l2rib,
    is_network_instance_present,
)

_PARSER_TARGET = "genie.libs.parser.arcos.show_network_instance.ShowNetworkInstance"

_PARSED_VLAN100 = {
    "network-instance": {
        "vlan100": {
            "name": "vlan100",
            "interfaces": {
                "swp1.100": {"interface": "swp1", "subinterface": 100},
                "swp2.100": {"interface": "swp2", "subinterface": 100},
            },
            "fdb": {
                "mac-entries": {
                    "aa:bb:cc:dd:ee:ff": {"vlan": 100, "entry-type": "STATIC"},
                    "11:22:33:44:55:66": {"vlan": 100, "entry-type": "DYNAMIC"},
                }
            },
            "l2rib": {
                "id": 100,
                "name": "vlan100",
                "type": "L2VLAN",
                "vni": 100,
                "advertise-mac-routes": True,
                "mac-count": 2,
            },
        }
    }
}

_PARSED_EMPTY_ENTRY = {"network-instance": {}}


class _DummyDevice:
    """Minimal device stand-in; the parser class itself is patched out so
    this object never needs real .execute()/.parse() behavior."""

    def __init__(self):
        self.name = "rtr1"


def _patch_parser(return_value=None, side_effect=None):
    """Return a started patcher for ShowNetworkInstance whose instance's
    .parse() yields return_value or raises side_effect."""
    patcher = patch(_PARSER_TARGET)
    mock_cls = patcher.start()
    if side_effect is not None:
        mock_cls.return_value.parse.side_effect = side_effect
    else:
        mock_cls.return_value.parse.return_value = return_value
    return patcher


class TestGetNetworkInstancePresent(unittest.TestCase):
    """Happy-path: NI data present in parser output."""

    def setUp(self):
        self.device = _DummyDevice()
        self.patcher = _patch_parser(return_value=_PARSED_VLAN100)
        self.addCleanup(self.patcher.stop)

    def test_get_network_instance(self):
        result = get_network_instance(self.device, "vlan100")
        self.assertEqual(result["name"], "vlan100")
        self.assertIn("interfaces", result)

    def test_get_network_instance_interfaces(self):
        result = get_network_instance_interfaces(self.device, "vlan100")
        self.assertEqual(set(result), {"swp1.100", "swp2.100"})
        self.assertEqual(result["swp1.100"]["interface"], "swp1")

    def test_get_network_instance_fdb_mac_entries(self):
        result = get_network_instance_fdb_mac_entries(self.device, "vlan100")
        self.assertEqual(
            set(result), {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
        )
        self.assertEqual(result["aa:bb:cc:dd:ee:ff"]["entry-type"], "STATIC")

    def test_get_network_instance_fdb_mac_count(self):
        self.assertEqual(get_network_instance_fdb_mac_count(self.device, "vlan100"), 2)

    def test_get_network_instance_l2rib(self):
        result = get_network_instance_l2rib(self.device, "vlan100")
        self.assertEqual(result["type"], "L2VLAN")
        self.assertEqual(result["vni"], 100)
        self.assertTrue(result["advertise-mac-routes"])

    def test_is_network_instance_present_true(self):
        self.assertTrue(is_network_instance_present(self.device, "vlan100"))


class TestGetNetworkInstanceAbsentNi(unittest.TestCase):
    """NI container present but the requested NI name is not in it (e.g.
    parser returned data for a different instance, or an empty dict)."""

    def setUp(self):
        self.device = _DummyDevice()
        self.patcher = _patch_parser(return_value=_PARSED_EMPTY_ENTRY)
        self.addCleanup(self.patcher.stop)

    def test_get_network_instance_none(self):
        self.assertIsNone(get_network_instance(self.device, "vlan100"))

    def test_get_network_instance_interfaces_empty(self):
        self.assertEqual(
            get_network_instance_interfaces(self.device, "vlan100"), {}
        )

    def test_get_network_instance_fdb_mac_entries_empty(self):
        self.assertEqual(
            get_network_instance_fdb_mac_entries(self.device, "vlan100"), {}
        )

    def test_get_network_instance_fdb_mac_count_zero(self):
        self.assertEqual(
            get_network_instance_fdb_mac_count(self.device, "vlan100"), 0
        )

    def test_get_network_instance_l2rib_empty(self):
        self.assertEqual(get_network_instance_l2rib(self.device, "vlan100"), {})

    def test_is_network_instance_present_false(self):
        self.assertFalse(is_network_instance_present(self.device, "vlan100"))


class TestGetNetworkInstanceSchemaEmptyParserError(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -> _parse_network_instance
    swallows it and returns {} for every downstream helper."""

    def setUp(self):
        self.device = _DummyDevice()
        self.patcher = _patch_parser(
            side_effect=SchemaEmptyParserError("empty output")
        )
        self.addCleanup(self.patcher.stop)

    def test_get_network_instance_none(self):
        self.assertIsNone(get_network_instance(self.device, "vlan100"))

    def test_get_network_instance_interfaces_empty(self):
        self.assertEqual(
            get_network_instance_interfaces(self.device, "vlan100"), {}
        )

    def test_get_network_instance_fdb_mac_entries_empty(self):
        self.assertEqual(
            get_network_instance_fdb_mac_entries(self.device, "vlan100"), {}
        )

    def test_get_network_instance_fdb_mac_count_zero(self):
        self.assertEqual(
            get_network_instance_fdb_mac_count(self.device, "vlan100"), 0
        )

    def test_get_network_instance_l2rib_empty(self):
        self.assertEqual(get_network_instance_l2rib(self.device, "vlan100"), {})

    def test_is_network_instance_present_false(self):
        self.assertFalse(is_network_instance_present(self.device, "vlan100"))


class TestGetNetworkInstanceSubCommandFailure(unittest.TestCase):
    """Parser raises SubCommandFailure -> also swallowed, same degrade
    behavior as SchemaEmptyParserError."""

    def setUp(self):
        self.device = _DummyDevice()
        self.patcher = _patch_parser(
            side_effect=SubCommandFailure("device rejected command")
        )
        self.addCleanup(self.patcher.stop)

    def test_get_network_instance_none(self):
        self.assertIsNone(get_network_instance(self.device, "vlan100"))

    def test_is_network_instance_present_false(self):
        self.assertFalse(is_network_instance_present(self.device, "vlan100"))


class TestGetNetworkInstanceUnexpectedException(unittest.TestCase):
    """Parser raises a generic Exception -> caught by the broad except
    clause (logged as a warning), still degrades to {} / None / False."""

    def setUp(self):
        self.device = _DummyDevice()
        self.patcher = _patch_parser(side_effect=ValueError("boom"))
        self.addCleanup(self.patcher.stop)

    def test_get_network_instance_none(self):
        self.assertIsNone(get_network_instance(self.device, "vlan100"))

    def test_get_network_instance_interfaces_empty(self):
        self.assertEqual(
            get_network_instance_interfaces(self.device, "vlan100"), {}
        )

    def test_is_network_instance_present_false(self):
        self.assertFalse(is_network_instance_present(self.device, "vlan100"))


class TestGetNetworkInstanceCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    network_instance/get.py must be referenced by name somewhere in this
    test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect
        from genie.libs.sdk.apis.arcos.network_instance import get as ni_get

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ni_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ni_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Network Instance get/is functions: {missing}")

        print(
            f"\nNetwork Instance get/is coverage: "
            f"{len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
