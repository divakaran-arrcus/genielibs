#!/usr/bin/env python3
"""Unit tests for arcOS SR-Policy get APIs (full coverage).

get.py instantiates the ArcOS SR-Policy parsers directly
(``ShowSrPolicySegmentList``, ``ShowSrPolicyPolicy``,
``ShowSrPolicyDatabasePolicy``) and calls ``parser.parse()``. Tests patch
those parser classes at the get module's import site with a fake parser
factory that returns canned data (matching the parser schema in
genie.libs.parser.arcos.show_sr_policy) or raises SchemaEmptyParserError.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.sr_policy.get import (
    get_sr_policy_segment_lists,
    get_sr_policy_segment_list,
    get_sr_policy_policies,
    get_sr_policy_policy,
    get_sr_policy_db_policies,
    get_sr_policy_db_oper_state,
    get_sr_policy_policy_count,
)

_SEGMENT_LISTS = {
    "segment-lists": {
        "sl1": {
            "name": "sl1",
            "index": 1,
            "segments": {
                "1": {
                    "index": 1,
                    "type": "MPLS_LABEL",
                    "mpls-label": 100000,
                    "validate": True,
                },
                "2": {
                    "index": 2,
                    "type": "MPLS_LABEL",
                    "mpls-label": 100001,
                },
            },
        },
        "sl2": {
            "name": "sl2",
            "segments": {
                "1": {
                    "index": 1,
                    "type": "SRV6_SID",
                    "srv6-sid": "2001:db8::1",
                },
            },
        },
    }
}

_POLICIES = {
    "policies": {
        "2.2.2.2 100": {
            "endpoint": "2.2.2.2",
            "color": 100,
            "name": "test-pol",
            "enabled": True,
            "priority": 10,
            "candidate-paths": {
                "10": {
                    "discriminator": 10,
                    "preference": 200,
                    "type": "EXPLICIT_SEGMENT_LIST",
                    "explicit-segment-lists": ["sl1"],
                },
            },
        },
    }
}

_DB_POLICIES = {
    "policies": {
        "2.2.2.2 100": {
            "endpoint": "2.2.2.2",
            "color": 100,
            "oper-state": "UP",
            "transition-count": 3,
            "candidate-paths": {
                "bgp:1.1.1.1:10": {
                    "protocol-origin": "bgp",
                    "originator": "1.1.1.1",
                    "discriminator": 10,
                    "best-candidate-path": True,
                    "valid": True,
                },
            },
        },
        "3.3.3.3 200": {
            "endpoint": "3.3.3.3",
            "color": 200,
            "oper-state": "DOWN",
        },
    }
}


def _make_parser_factory(result=None, exc=None):
    """Build a fake parser "class" whose parse() returns/raises as given."""

    class _FakeParser:
        def __init__(self, device=None, **kwargs):
            self.device = device

        def parse(self, **kwargs):
            if exc is not None:
                raise exc
            return result

    return _FakeParser


class TestGetSrPolicySegmentLists(unittest.TestCase):
    """get_sr_policy_segment_lists / get_sr_policy_segment_list"""

    def test_get_segment_lists(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicySegmentList",
            _make_parser_factory(result=_SEGMENT_LISTS),
        ):
            result = get_sr_policy_segment_lists(device=object())
        self.assertEqual(set(result), {"sl1", "sl2"})
        self.assertEqual(result["sl1"]["segments"]["1"]["mpls-label"], 100000)

    def test_get_segment_lists_empty_on_schema_empty(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicySegmentList",
            _make_parser_factory(exc=SchemaEmptyParserError("empty")),
        ):
            result = get_sr_policy_segment_lists(device=object())
        self.assertEqual(result, {})

    def test_get_segment_lists_empty_on_generic_exception(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicySegmentList",
            _make_parser_factory(exc=RuntimeError("boom")),
        ):
            result = get_sr_policy_segment_lists(device=object())
        self.assertEqual(result, {})

    def test_get_segment_list_found(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicySegmentList",
            _make_parser_factory(result=_SEGMENT_LISTS),
        ):
            result = get_sr_policy_segment_list(device=object(), name="sl2")
        self.assertEqual(result["name"], "sl2")

    def test_get_segment_list_not_found(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicySegmentList",
            _make_parser_factory(result=_SEGMENT_LISTS),
        ):
            result = get_sr_policy_segment_list(device=object(), name="sl9")
        self.assertIsNone(result)

    def test_get_segment_list_none_when_degraded(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicySegmentList",
            _make_parser_factory(exc=SchemaEmptyParserError("empty")),
        ):
            result = get_sr_policy_segment_list(device=object(), name="sl1")
        self.assertIsNone(result)


class TestGetSrPolicyPolicies(unittest.TestCase):
    """get_sr_policy_policies / get_sr_policy_policy / get_sr_policy_policy_count"""

    def test_get_policies(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyPolicy",
            _make_parser_factory(result=_POLICIES),
        ):
            result = get_sr_policy_policies(device=object())
        self.assertIn("2.2.2.2 100", result)

    def test_get_policies_empty_on_schema_empty(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyPolicy",
            _make_parser_factory(exc=SchemaEmptyParserError("empty")),
        ):
            result = get_sr_policy_policies(device=object())
        self.assertEqual(result, {})

    def test_get_policy_found(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyPolicy",
            _make_parser_factory(result=_POLICIES),
        ):
            result = get_sr_policy_policy(
                device=object(), endpoint="2.2.2.2", color=100
            )
        self.assertEqual(result["name"], "test-pol")
        self.assertEqual(
            result["candidate-paths"]["10"]["explicit-segment-lists"],
            ["sl1"],
        )

    def test_get_policy_not_found(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyPolicy",
            _make_parser_factory(result=_POLICIES),
        ):
            result = get_sr_policy_policy(
                device=object(), endpoint="9.9.9.9", color=999
            )
        self.assertIsNone(result)

    def test_get_policy_count(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyPolicy",
            _make_parser_factory(result=_POLICIES),
        ):
            count = get_sr_policy_policy_count(device=object())
        self.assertEqual(count, 1)

    def test_get_policy_count_zero_when_empty(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyPolicy",
            _make_parser_factory(exc=SchemaEmptyParserError("empty")),
        ):
            count = get_sr_policy_policy_count(device=object())
        self.assertEqual(count, 0)


class TestGetSrPolicyDbPolicies(unittest.TestCase):
    """get_sr_policy_db_policies / get_sr_policy_db_oper_state"""

    def test_get_db_policies(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyDatabasePolicy",
            _make_parser_factory(result=_DB_POLICIES),
        ):
            result = get_sr_policy_db_policies(device=object())
        self.assertEqual(set(result), {"2.2.2.2 100", "3.3.3.3 200"})

    def test_get_db_policies_empty_on_schema_empty(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyDatabasePolicy",
            _make_parser_factory(exc=SchemaEmptyParserError("empty")),
        ):
            result = get_sr_policy_db_policies(device=object())
        self.assertEqual(result, {})

    def test_get_db_oper_state_up(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyDatabasePolicy",
            _make_parser_factory(result=_DB_POLICIES),
        ):
            state = get_sr_policy_db_oper_state(
                device=object(), endpoint="2.2.2.2", color=100
            )
        self.assertEqual(state, "UP")

    def test_get_db_oper_state_down(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyDatabasePolicy",
            _make_parser_factory(result=_DB_POLICIES),
        ):
            state = get_sr_policy_db_oper_state(
                device=object(), endpoint="3.3.3.3", color=200
            )
        self.assertEqual(state, "DOWN")

    def test_get_db_oper_state_not_found(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyDatabasePolicy",
            _make_parser_factory(result=_DB_POLICIES),
        ):
            state = get_sr_policy_db_oper_state(
                device=object(), endpoint="9.9.9.9", color=999
            )
        self.assertIsNone(state)

    def test_get_db_oper_state_none_when_degraded(self):
        with patch(
            "genie.libs.sdk.apis.arcos.sr_policy.get.ShowSrPolicyDatabasePolicy",
            _make_parser_factory(exc=SchemaEmptyParserError("empty")),
        ):
            state = get_sr_policy_db_oper_state(
                device=object(), endpoint="2.2.2.2", color=100
            )
        self.assertIsNone(state)


class TestSrPolicyGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_* function in
    sr_policy/get.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect
        from genie.libs.sdk.apis.arcos.sr_policy import get as sr_policy_get

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sr_policy_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sr_policy_get.__name__
            and name.startswith("get_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Untested get functions: {missing}"
        )

        print(
            f"\nSR-Policy get coverage: {len(names)} get_* functions, "
            f"0 missing"
        )


if __name__ == "__main__":
    unittest.main()
