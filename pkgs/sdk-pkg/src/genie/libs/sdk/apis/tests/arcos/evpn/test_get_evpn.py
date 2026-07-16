#!/usr/bin/env python3
"""Unit tests for arcOS EVPN get APIs (full coverage).

Every get_* helper in genie.libs.sdk.apis.arcos.evpn.get routes through the
module-private ``_parse_evpn(device)``, which does a *local* import of
``genie.libs.parser.arcos.show_evpn.ShowEvpn`` and calls
``ShowEvpn(device=device).parse()``. Because the import happens inside the
function body on every call, patching the class at its origin
(``genie.libs.parser.arcos.show_evpn.ShowEvpn``) is sufficient to intercept
every get_* call.
"""

import unittest
from unittest.mock import patch, MagicMock

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.evpn import get as evpn_get
from genie.libs.sdk.apis.arcos.evpn.get import (
    get_evpn_state,
    get_evpn_anycast_gateway_mac,
    get_evpn_df_election_time,
    get_evpn_duplicate_mac_detection,
    get_evpn_arp_nd_suppression_counters,
)

SHOW_EVPN = "genie.libs.parser.arcos.show_evpn.ShowEvpn"

_FULL = {
    "anycast-gateway-mac": "aa:bb:cc:01:02:03",
    "df-election-time": 15,
    "router-ip-selected": "10.0.0.1",
    "esi-info": {
        "esi-pruned-pkts": 10,
        "esi-pruned-octets": 640,
    },
    "duplicate-mac-detection": {
        "window": 180,
        "threshold": 5,
        "auto-recovery-time": 0,
    },
    "arp-nd-suppression-counters": {
        "arp-suppression-counters": 3,
        "nd-suppression-counters": 4,
    },
}


def _mock_show_evpn(return_value=None, side_effect=None):
    """Build a MagicMock standing in for the ShowEvpn class."""
    mock_cls = MagicMock()
    if side_effect is not None:
        mock_cls.return_value.parse.side_effect = side_effect
    else:
        mock_cls.return_value.parse.return_value = return_value
    return mock_cls


class TestGetEvpnState(unittest.TestCase):
    """get_evpn_state"""

    def test_full_state(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value=_FULL)):
            self.assertEqual(get_evpn_state(object()), _FULL)

    def test_empty_on_schema_empty(self):
        with patch(
            SHOW_EVPN,
            _mock_show_evpn(side_effect=SchemaEmptyParserError("empty")),
        ):
            self.assertEqual(get_evpn_state(object()), {})

    def test_empty_on_subcommand_failure(self):
        with patch(
            SHOW_EVPN,
            _mock_show_evpn(side_effect=SubCommandFailure("boom")),
        ):
            self.assertEqual(get_evpn_state(object()), {})

    def test_empty_on_unexpected_exception(self):
        with patch(
            SHOW_EVPN,
            _mock_show_evpn(side_effect=ValueError("unexpected")),
        ):
            self.assertEqual(get_evpn_state(object()), {})


class TestGetEvpnAnycastGatewayMac(unittest.TestCase):
    """get_evpn_anycast_gateway_mac"""

    def test_configured(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value=_FULL)):
            self.assertEqual(
                get_evpn_anycast_gateway_mac(object()),
                "aa:bb:cc:01:02:03",
            )

    def test_not_configured(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value={})):
            self.assertIsNone(get_evpn_anycast_gateway_mac(object()))

    def test_none_on_error(self):
        with patch(
            SHOW_EVPN,
            _mock_show_evpn(side_effect=SchemaEmptyParserError("empty")),
        ):
            self.assertIsNone(get_evpn_anycast_gateway_mac(object()))


class TestGetEvpnDfElectionTime(unittest.TestCase):
    """get_evpn_df_election_time"""

    def test_int_value(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value=_FULL)):
            self.assertEqual(get_evpn_df_election_time(object()), 15)

    def test_string_int_value_coerced(self):
        data = dict(_FULL, **{"df-election-time": "20"})
        with patch(SHOW_EVPN, _mock_show_evpn(return_value=data)):
            result = get_evpn_df_election_time(object())
            self.assertEqual(result, 20)
            self.assertIsInstance(result, int)

    def test_non_numeric_value_returned_as_is(self):
        data = dict(_FULL, **{"df-election-time": "not-a-number"})
        with patch(SHOW_EVPN, _mock_show_evpn(return_value=data)):
            self.assertEqual(
                get_evpn_df_election_time(object()), "not-a-number"
            )

    def test_not_configured_returns_none(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value={})):
            self.assertIsNone(get_evpn_df_election_time(object()))

    def test_none_on_error(self):
        with patch(
            SHOW_EVPN,
            _mock_show_evpn(side_effect=SubCommandFailure("boom")),
        ):
            self.assertIsNone(get_evpn_df_election_time(object()))


class TestGetEvpnDuplicateMacDetection(unittest.TestCase):
    """get_evpn_duplicate_mac_detection"""

    def test_configured(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value=_FULL)):
            self.assertEqual(
                get_evpn_duplicate_mac_detection(object()),
                {"window": 180, "threshold": 5, "auto-recovery-time": 0},
            )

    def test_not_configured_returns_empty_dict(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value={})):
            self.assertEqual(
                get_evpn_duplicate_mac_detection(object()), {}
            )

    def test_empty_on_error(self):
        with patch(
            SHOW_EVPN,
            _mock_show_evpn(side_effect=SchemaEmptyParserError("empty")),
        ):
            self.assertEqual(
                get_evpn_duplicate_mac_detection(object()), {}
            )


class TestGetEvpnArpNdSuppressionCounters(unittest.TestCase):
    """get_evpn_arp_nd_suppression_counters"""

    def test_configured(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value=_FULL)):
            self.assertEqual(
                get_evpn_arp_nd_suppression_counters(object()),
                {"arp-suppression-counters": 3, "nd-suppression-counters": 4},
            )

    def test_not_configured_returns_empty_dict(self):
        with patch(SHOW_EVPN, _mock_show_evpn(return_value={})):
            self.assertEqual(
                get_evpn_arp_nd_suppression_counters(object()), {}
            )

    def test_empty_on_error(self):
        with patch(
            SHOW_EVPN,
            _mock_show_evpn(side_effect=Exception("unexpected")),
        ):
            self.assertEqual(
                get_evpn_arp_nd_suppression_counters(object()), {}
            )


class TestEvpnGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_* function in
    evpn/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(evpn_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == evpn_get.__name__
            and name.startswith("get_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered EVPN get functions: {missing}")

        print(
            f"\nEVPN get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
