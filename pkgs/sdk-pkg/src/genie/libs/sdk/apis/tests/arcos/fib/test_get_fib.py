#!/usr/bin/env python3
"""Unit tests for arcOS FIB get APIs (full coverage).

The FIB get helpers wrap ``device.parse("show network-instance ... fib ...")``
directly (no parser class is imported into ``get.py`` — unlike LDP/LAG, the
command string is built inline and handed to ``device.parse``), so a dummy
device whose ``.parse()`` returns canned parser output (matching the
``ShowFibPrefixEntries`` / ``ShowFibNexthopEntries`` / ``ShowFibLabelEntries``
schemas in ``genie.libs.parser.arcos.show_fib``) exercises them end to end.

Each of the three internal ``_parse_fib_*_entries`` helpers swallows three
distinct exception types (``SchemaEmptyParserError``, ``SubCommandFailure``,
and a defensive bare ``Exception``) and normalizes all of them to ``{}``.
Dedicated dummy devices drive each of those branches for every entry type.
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.fib.get import (
    get_fib_prefix_entries,
    get_fib_prefix_entry,
    get_fib_prefix_entry_count,
    is_prefix_in_fib,
    get_fib_nexthop_entries,
    get_fib_nexthop_entry,
    get_fib_nexthop_entry_count,
    get_fib_label_entries,
    get_fib_label_entry,
    get_fib_label_entry_count,
)

MOD = "genie.libs.sdk.apis.arcos.fib.get"

# ---------------------------------------------------------------------------
# Canned parser output (matches ShowFibPrefixEntries / ShowFibNexthopEntries
# / ShowFibLabelEntries schemas in genie.libs.parser.arcos.show_fib)
# ---------------------------------------------------------------------------

_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "prefix-entries": {
                "10.0.0.0/24": {
                    "prefix": "10.0.0.0/24",
                    "next-hop-id": 643,
                    "publish-type": "PUBLISH_ADD",
                    "publish-id": 1,
                },
                "5.5.5.5/32": {
                    "prefix": "5.5.5.5/32",
                    "next-hop-id": 650,
                    "publish-type": "PUBLISH_ADD",
                    "publish-id": 2,
                },
            },
            "nexthop-entries": {
                "643": {
                    "index": 643,
                    "eos0-nexthop-index": 643,
                    "level": 1,
                    "flags": "",
                    "paths": {
                        "0": {
                            "path-id": 0,
                            "path-type": "DIRECT",
                            "nh-type": "IPV4",
                            "next-hop": "192.168.1.1",
                            "interface": "ethernet-1/1",
                        }
                    },
                },
                "650": {
                    "index": 650,
                    "level": 1,
                    "flags": "",
                    "paths": {},
                },
            },
            "label-entries": {
                "10005": {
                    "local-label": 10005,
                    "vpn-table-id": 1,
                    "next-hop-id": 643,
                    "control-word": False,
                    "flow-label": False,
                },
                "10006": {
                    "local-label": 10006,
                    "vpn-table-id": 1,
                    "next-hop-id": 650,
                    "control-word": False,
                    "flow-label": False,
                    "domain-name": "vrf-a",
                },
            },
        }
    }
}

# Single-entry variants to exercise the "fallback to sole entry" branch in
# get_fib_prefix_entry / get_fib_nexthop_entry / get_fib_label_entry, where
# the parser returned exactly one (possibly normalized) entry that doesn't
# match the requested key by string equality.
_SINGLE_PREFIX_PARSED = {
    "network-instance": {
        "default": {
            "prefix-entries": {
                "192.168.0.0/16": {"prefix": "192.168.0.0/16", "next-hop-id": 700},
            },
        }
    }
}

_SINGLE_NEXTHOP_PARSED = {
    "network-instance": {
        "default": {
            "nexthop-entries": {
                "701": {"index": 701, "level": 2},
            },
        }
    }
}

_SINGLE_LABEL_PARSED = {
    "network-instance": {
        "default": {
            "label-entries": {
                "20001": {"local-label": 20001, "next-hop-id": 701},
            },
        }
    }
}


class _DummyDevice:
    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


# ---------------------------------------------------------------------------
# get_fib_prefix_entries / get_fib_prefix_entry / get_fib_prefix_entry_count
# / is_prefix_in_fib
# ---------------------------------------------------------------------------


class TestGetFibPrefixEntries(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_get_fib_prefix_entries_success(self):
        result = get_fib_prefix_entries(self.device)
        self.assertIn("10.0.0.0/24", result)
        self.assertIn("5.5.5.5/32", result)
        self.assertEqual(len(result), 2)

    def test_get_fib_prefix_entries_schema_empty_error(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertEqual(get_fib_prefix_entries(device), {})

    def test_get_fib_prefix_entries_subcommand_failure(self):
        device = _DummyDevice(raise_exc=SubCommandFailure("bad command"))
        self.assertEqual(get_fib_prefix_entries(device), {})

    def test_get_fib_prefix_entries_generic_exception(self):
        device = _DummyDevice(raise_exc=Exception("boom"))
        self.assertEqual(get_fib_prefix_entries(device), {})

    def test_get_fib_prefix_entries_ipv6(self):
        result = get_fib_prefix_entries(self.device, af="IPV6")
        self.assertEqual(len(result), 2)


class TestGetFibPrefixEntry(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_found(self):
        result = get_fib_prefix_entry(self.device, prefix="10.0.0.0/24")
        self.assertIsNotNone(result)
        self.assertEqual(result["prefix"], "10.0.0.0/24")
        self.assertEqual(result["next-hop-id"], 643)

    def test_not_found(self):
        result = get_fib_prefix_entry(self.device, prefix="99.99.99.99/32")
        self.assertIsNone(result)

    def test_fallback_single_entry(self):
        device = _DummyDevice(parsed=_SINGLE_PREFIX_PARSED)
        result = get_fib_prefix_entry(device, prefix="10.10.10.10/32")
        self.assertIsNotNone(result)
        self.assertEqual(result["prefix"], "192.168.0.0/16")

    def test_parser_error_returns_none(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertIsNone(get_fib_prefix_entry(device, prefix="10.0.0.0/24"))


class TestGetFibPrefixEntryCount(unittest.TestCase):
    def test_count(self):
        device = _DummyDevice(parsed=_PARSED)
        self.assertEqual(get_fib_prefix_entry_count(device), 2)

    def test_count_empty(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertEqual(get_fib_prefix_entry_count(device), 0)


class TestIsPrefixInFib(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_true(self):
        self.assertTrue(is_prefix_in_fib(self.device, prefix="10.0.0.0/24"))

    def test_false(self):
        self.assertFalse(is_prefix_in_fib(self.device, prefix="99.99.99.99/32"))

    def test_parser_error_is_false(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertFalse(is_prefix_in_fib(device, prefix="10.0.0.0/24"))


# ---------------------------------------------------------------------------
# get_fib_nexthop_entries / get_fib_nexthop_entry / get_fib_nexthop_entry_count
# ---------------------------------------------------------------------------


class TestGetFibNexthopEntries(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_success(self):
        result = get_fib_nexthop_entries(self.device)
        self.assertIn("643", result)
        self.assertIn("650", result)
        self.assertEqual(len(result), 2)

    def test_schema_empty_error(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertEqual(get_fib_nexthop_entries(device), {})

    def test_subcommand_failure(self):
        device = _DummyDevice(raise_exc=SubCommandFailure("bad command"))
        self.assertEqual(get_fib_nexthop_entries(device), {})

    def test_generic_exception(self):
        device = _DummyDevice(raise_exc=Exception("boom"))
        self.assertEqual(get_fib_nexthop_entries(device), {})


class TestGetFibNexthopEntry(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_found_by_int_index(self):
        result = get_fib_nexthop_entry(self.device, index=643)
        self.assertIsNotNone(result)
        self.assertEqual(result["index"], 643)

    def test_not_found(self):
        result = get_fib_nexthop_entry(self.device, index=99999)
        self.assertIsNone(result)

    def test_fallback_single_entry(self):
        device = _DummyDevice(parsed=_SINGLE_NEXTHOP_PARSED)
        result = get_fib_nexthop_entry(device, index=999)
        self.assertIsNotNone(result)
        self.assertEqual(result["index"], 701)

    def test_parser_error_returns_none(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertIsNone(get_fib_nexthop_entry(device, index=643))


class TestGetFibNexthopEntryCount(unittest.TestCase):
    def test_count(self):
        device = _DummyDevice(parsed=_PARSED)
        self.assertEqual(get_fib_nexthop_entry_count(device), 2)

    def test_count_empty(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertEqual(get_fib_nexthop_entry_count(device), 0)


# ---------------------------------------------------------------------------
# get_fib_label_entries / get_fib_label_entry / get_fib_label_entry_count
# ---------------------------------------------------------------------------


class TestGetFibLabelEntries(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_success(self):
        result = get_fib_label_entries(self.device)
        self.assertIn("10005", result)
        self.assertIn("10006", result)
        self.assertEqual(len(result), 2)

    def test_schema_empty_error(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertEqual(get_fib_label_entries(device), {})

    def test_subcommand_failure(self):
        device = _DummyDevice(raise_exc=SubCommandFailure("bad command"))
        self.assertEqual(get_fib_label_entries(device), {})

    def test_generic_exception(self):
        device = _DummyDevice(raise_exc=Exception("boom"))
        self.assertEqual(get_fib_label_entries(device), {})


class TestGetFibLabelEntry(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_found(self):
        result = get_fib_label_entry(self.device, label="10005")
        self.assertIsNotNone(result)
        self.assertEqual(result["local-label"], 10005)

    def test_not_found(self):
        result = get_fib_label_entry(self.device, label="99999")
        self.assertIsNone(result)

    def test_fallback_single_entry(self):
        device = _DummyDevice(parsed=_SINGLE_LABEL_PARSED)
        result = get_fib_label_entry(device, label="30000")
        self.assertIsNotNone(result)
        self.assertEqual(result["local-label"], 20001)

    def test_parser_error_returns_none(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertIsNone(get_fib_label_entry(device, label="10005"))


class TestGetFibLabelEntryCount(unittest.TestCase):
    def test_count(self):
        device = _DummyDevice(parsed=_PARSED)
        self.assertEqual(get_fib_label_entry_count(device), 2)

    def test_count_empty(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertEqual(get_fib_label_entry_count(device), 0)


# ---------------------------------------------------------------------------
# Machine-checked coverage
# ---------------------------------------------------------------------------


class TestFibGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    fib/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        from genie.libs.sdk.apis.arcos.fib import get as fib_get

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(fib_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == fib_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Uncovered FIB get functions: {missing}")

        print(f"\nFIB get coverage: {len(names)} total, 0 missing")


if __name__ == "__main__":
    unittest.main()
