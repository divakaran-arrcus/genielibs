#!/usr/bin/env python3
"""Unit tests for arcOS RIB get APIs (full coverage).

RIB is not a protocol — ``rib/get.py`` wraps ``device.parse("show
network-instance ... rib ...")`` directly (no protocol/network-instance
hierarchy beyond the network-instance itself), so a dummy device returning
canned parser output (shaped like ``_RibEntriesSchema`` /
``_RibLabelEntriesSchema`` from
``genie.libs.parser.arcos.show_rib``) exercises every function.

A module-alias import (``from ... import get as rib_get``) is used instead
of ``from ... import <function>`` for consistency with the functional test
classes below (module-level attribute lookups are resolved at call time,
not at import time).
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.rib import get as rib_get


# ---------------------------------------------------------------------------
# Canned parser output (shape returned by device.parse(), i.e. already
# post-processed by ShowRibEntries / ShowRibLabelEntries).
# ---------------------------------------------------------------------------

RIB_ENTRIES_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "entries": {
                "5.5.5.5/32": {
                    "prefix": "5.5.5.5/32",
                    "best-protocol": "ISIS",
                    "hw-update": {
                        "install-ack": True,
                        "status-code": 0,
                        "version": "v1",
                    },
                    "origins": {
                        "0": {
                            "origin-protocol": "ISIS",
                            "protocol-name": "isis1",
                            "metric": 20,
                            "pref": 115,
                            "route-type": "internal",
                            "nhid": "100",
                            "next-hops": {
                                "0": {
                                    "next-hop": "10.0.0.2",
                                    "interface": "swp1",
                                    "flags": "ATTACH",
                                },
                                "1": {
                                    "next-hop": "10.0.0.6",
                                    "interface": "swp2",
                                    "flags": "ATTACH,BACKUP,SR",
                                    "pushed-mpls-label-stack": [16005],
                                },
                            },
                        }
                    },
                },
                "10.0.0.0/24": {
                    "prefix": "10.0.0.0/24",
                    "best-protocol": "STATIC",
                    "origins": {
                        "0": {
                            "origin-protocol": "STATIC",
                            "metric": 1,
                            "next-hops": {
                                "0": {
                                    "interface": "swp3",
                                    "next-hop": "10.0.1.1",
                                    "flags": "ATTACH",
                                }
                            },
                        }
                    },
                },
                "6.6.6.6/32": {
                    # No "origins" key at all — exercises the
                    # (entry.get("origins") or {}) fallback in
                    # get_rib_backup_nexthops.
                    "prefix": "6.6.6.6/32",
                    "best-protocol": "BGP",
                },
            },
        }
    }
}

# Exactly one entry, keyed differently than the prefix a caller might pass —
# exercises the "len(entries) == 1" fallback in get_rib_entry.
RIB_SINGLE_ENTRY_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "entries": {
                "7.7.7.7/32": {
                    "prefix": "7.7.7.7/32",
                    "best-protocol": "ISIS",
                },
            },
        }
    }
}

RIB_LABEL_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "label-entries": {
                "10005": {
                    "label": 10005,
                    "label-type": "PREFIX-SID",
                    "protocol": "ISIS",
                    "fec": "5.5.5.5/32",
                    "nhid": "100",
                },
                "10010": {
                    "label": 10010,
                    "label-type": "PREFIX-SID",
                    "protocol": "STATIC",
                    "fec": "10.0.0.0/24",
                },
            },
        }
    }
}

# Exactly one label entry, keyed differently than the label a caller might
# pass — exercises the "len(label_entries) == 1" fallback in
# get_rib_label_entry.
RIB_SINGLE_LABEL_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "label-entries": {
                "20005": {
                    "label": 20005,
                    "protocol": "ISIS",
                    "fec": "8.8.8.8/32",
                },
            },
        }
    }
}


class _DummyDevice:
    """Minimal device stub exposing only ``.parse()``."""

    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


# ---------------------------------------------------------------------------
# Normal / populated data
# ---------------------------------------------------------------------------


class TestGetRib(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=RIB_ENTRIES_PARSED)
        self.label_device = _DummyDevice(parsed=RIB_LABEL_PARSED)
        self.single_device = _DummyDevice(parsed=RIB_SINGLE_ENTRY_PARSED)
        self.single_label_device = _DummyDevice(parsed=RIB_SINGLE_LABEL_PARSED)

    # -- get_rib_entries ------------------------------------------------

    def test_get_rib_entries(self):
        result = rib_get.get_rib_entries(self.device)
        self.assertEqual(
            set(result), {"5.5.5.5/32", "10.0.0.0/24", "6.6.6.6/32"}
        )

    def test_get_rib_entries_ipv6_ni(self):
        result = rib_get.get_rib_entries(self.device, af="IPV6", ni="default")
        self.assertIn("5.5.5.5/32", result)

    # -- get_rib_entry ----------------------------------------------------

    def test_get_rib_entry_found(self):
        entry = rib_get.get_rib_entry(self.device, "5.5.5.5/32")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["best-protocol"], "ISIS")

    def test_get_rib_entry_not_found(self):
        self.assertIsNone(rib_get.get_rib_entry(self.device, "99.99.99.99/32"))

    def test_get_rib_entry_single_fallback(self):
        # "7.7.7.7" is not a key in RIB_SINGLE_ENTRY_PARSED (the real key is
        # "7.7.7.7/32"), but since there's exactly one entry the fallback
        # kicks in and returns it anyway.
        entry = rib_get.get_rib_entry(self.single_device, "7.7.7.7")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["prefix"], "7.7.7.7/32")

    # -- get_route_best_protocol -------------------------------------------

    def test_get_route_best_protocol_found(self):
        self.assertEqual(
            rib_get.get_route_best_protocol(self.device, "10.0.0.0/24"), "STATIC"
        )

    def test_get_route_best_protocol_not_found(self):
        self.assertIsNone(
            rib_get.get_route_best_protocol(self.device, "9.9.9.9/32")
        )

    # -- is_route_in_rib ----------------------------------------------------

    def test_is_route_in_rib_true(self):
        self.assertTrue(rib_get.is_route_in_rib(self.device, "5.5.5.5/32"))

    def test_is_route_in_rib_false(self):
        self.assertFalse(rib_get.is_route_in_rib(self.device, "9.9.9.9/32"))

    # -- get_rib_entry_count --------------------------------------------

    def test_get_rib_entry_count(self):
        self.assertEqual(rib_get.get_rib_entry_count(self.device), 3)

    # -- get_rib_label_entries -----------------------------------------

    def test_get_rib_label_entries(self):
        result = rib_get.get_rib_label_entries(self.label_device)
        self.assertEqual(set(result), {"10005", "10010"})

    # -- get_rib_label_entry ------------------------------------------

    def test_get_rib_label_entry_found(self):
        entry = rib_get.get_rib_label_entry(self.label_device, "10005")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["fec"], "5.5.5.5/32")

    def test_get_rib_label_entry_not_found(self):
        self.assertIsNone(
            rib_get.get_rib_label_entry(self.label_device, "99999")
        )

    def test_get_rib_label_entry_single_fallback(self):
        entry = rib_get.get_rib_label_entry(self.single_label_device, "99999")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["label"], 20005)

    # -- get_rib_label_entry_count --------------------------------------

    def test_get_rib_label_entry_count(self):
        self.assertEqual(
            rib_get.get_rib_label_entry_count(self.label_device), 2
        )

    # -- get_rib_backup_nexthops -----------------------------------------

    def test_get_rib_backup_nexthops_found(self):
        backups = rib_get.get_rib_backup_nexthops(self.device, "5.5.5.5/32")
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0]["interface"], "swp2")

    def test_get_rib_backup_nexthops_no_backup_flag_match(self):
        # "10.0.0.0/24" has one next-hop, flags="ATTACH" only — no backup.
        backups = rib_get.get_rib_backup_nexthops(self.device, "10.0.0.0/24")
        self.assertEqual(backups, [])

    def test_get_rib_backup_nexthops_no_origins(self):
        # "6.6.6.6/32" has no "origins" key at all.
        backups = rib_get.get_rib_backup_nexthops(self.device, "6.6.6.6/32")
        self.assertEqual(backups, [])

    def test_get_rib_backup_nexthops_prefix_missing(self):
        backups = rib_get.get_rib_backup_nexthops(self.device, "9.9.9.9/32")
        self.assertEqual(backups, [])

    def test_get_rib_backup_nexthops_custom_flag(self):
        backups = rib_get.get_rib_backup_nexthops(
            self.device, "5.5.5.5/32", backup_flag="SR"
        )
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0]["interface"], "swp2")


# ---------------------------------------------------------------------------
# Degrade case: parser raised SchemaEmptyParserError (no data on device)
# ---------------------------------------------------------------------------


class TestGetRibEmpty(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_get_rib_entries_empty(self):
        self.assertEqual(rib_get.get_rib_entries(self.device), {})

    def test_get_rib_entry_none(self):
        self.assertIsNone(rib_get.get_rib_entry(self.device, "5.5.5.5/32"))

    def test_get_route_best_protocol_none(self):
        self.assertIsNone(
            rib_get.get_route_best_protocol(self.device, "5.5.5.5/32")
        )

    def test_is_route_in_rib_false(self):
        self.assertFalse(rib_get.is_route_in_rib(self.device, "5.5.5.5/32"))

    def test_get_rib_entry_count_zero(self):
        self.assertEqual(rib_get.get_rib_entry_count(self.device), 0)

    def test_get_rib_label_entries_empty(self):
        self.assertEqual(rib_get.get_rib_label_entries(self.device), {})

    def test_get_rib_label_entry_none(self):
        self.assertIsNone(rib_get.get_rib_label_entry(self.device, "10005"))

    def test_get_rib_label_entry_count_zero(self):
        self.assertEqual(rib_get.get_rib_label_entry_count(self.device), 0)

    def test_get_rib_backup_nexthops_empty(self):
        self.assertEqual(
            rib_get.get_rib_backup_nexthops(self.device, "5.5.5.5/32"), []
        )


# ---------------------------------------------------------------------------
# Degrade case: device.parse() raised SubCommandFailure (CLI error)
# ---------------------------------------------------------------------------


class TestGetRibSubCommandFailure(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(raise_exc=SubCommandFailure("boom"))

    def test_get_rib_entries_empty(self):
        self.assertEqual(rib_get.get_rib_entries(self.device), {})

    def test_get_rib_label_entries_empty(self):
        self.assertEqual(rib_get.get_rib_label_entries(self.device), {})


if __name__ == "__main__":
    unittest.main()
