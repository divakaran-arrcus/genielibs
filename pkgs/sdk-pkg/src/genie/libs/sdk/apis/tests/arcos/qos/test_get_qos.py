#!/usr/bin/env python3
"""Unit tests for arcOS QoS get APIs (full coverage).

genie.libs.sdk.apis.arcos.qos.get imports
genie.libs.parser.arcos.show_qos.ShowQosPolicy at module load time
(`from ... import ShowQosPolicy`), so the patch target is the name bound
in the API module itself: genie.libs.sdk.apis.arcos.qos.get.ShowQosPolicy

Canned data matches the ShowQosPolicySchema:
    {"policies": {<name>: {"name", "classifiers": {<name>: {"name",
                                                     "description", "actions"}}}}}
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

import genie.libs.sdk.apis.arcos.qos.get as get_module
from genie.libs.sdk.apis.arcos.qos.get import (
    get_qos_policies,
    get_qos_policy,
    is_qos_policy_present,
    get_qos_policy_count,
)

PARSER_PATCH_TARGET = "genie.libs.sdk.apis.arcos.qos.get.ShowQosPolicy"

_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


get_qos_policies = _track("get_qos_policies", get_qos_policies)
get_qos_policy = _track("get_qos_policy", get_qos_policy)
is_qos_policy_present = _track("is_qos_policy_present", is_qos_policy_present)
get_qos_policy_count = _track("get_qos_policy_count", get_qos_policy_count)


PARSED = {
    "policies": {
        "ingress-pol": {
            "name": "ingress-pol",
            "classifiers": {
                "voice": {
                    "name": "voice",
                    "description": "voice traffic",
                    "actions": [
                        {"type": "POLICE", "rate_value": 500, "rate_unit": "mbps"},
                    ],
                },
            },
        },
    },
}

PARSED_MULTI = {
    "policies": {
        "pol-a": {"name": "pol-a"},
        "pol-b": {"name": "pol-b"},
    },
}


class TestGetQosPolicies(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _patch_parser(self, return_value=None, side_effect=None):
        patcher = patch(PARSER_PATCH_TARGET)
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    def test_get_qos_policies(self):
        self._patch_parser(return_value=PARSED)
        result = get_qos_policies(self.device)
        self.assertIn("ingress-pol", result)
        self.assertEqual(
            result["ingress-pol"]["classifiers"]["voice"]["description"],
            "voice traffic",
        )

    def test_get_qos_policies_empty(self):
        self._patch_parser(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_qos_policies(self.device), {})

    def test_get_qos_policies_unexpected_exception(self):
        self._patch_parser(side_effect=ValueError("weird"))
        self.assertEqual(get_qos_policies(self.device), {})

    def test_get_qos_policy_found_by_name(self):
        self._patch_parser(return_value=PARSED)
        result = get_qos_policy(self.device, "ingress-pol")
        self.assertEqual(result["name"], "ingress-pol")

    def test_get_qos_policy_single_result_fallback(self):
        """When the requested name isn't a key but exactly one policy was
        returned (e.g. arcOS ignored the name filter), fall back to it."""
        self._patch_parser(return_value=PARSED)
        result = get_qos_policy(self.device, "some-other-name")
        self.assertEqual(result["name"], "ingress-pol")

    def test_get_qos_policy_not_found_multi(self):
        self._patch_parser(return_value=PARSED_MULTI)
        self.assertIsNone(get_qos_policy(self.device, "pol-missing"))

    def test_get_qos_policy_not_found_empty(self):
        self._patch_parser(side_effect=SchemaEmptyParserError("empty"))
        self.assertIsNone(get_qos_policy(self.device, "ingress-pol"))

    def test_is_qos_policy_present_true(self):
        self._patch_parser(return_value=PARSED)
        self.assertTrue(is_qos_policy_present(self.device, "ingress-pol"))

    def test_is_qos_policy_present_false(self):
        self._patch_parser(side_effect=SchemaEmptyParserError("empty"))
        self.assertFalse(is_qos_policy_present(self.device, "ingress-pol"))

    def test_get_qos_policy_count(self):
        self._patch_parser(return_value=PARSED_MULTI)
        self.assertEqual(get_qos_policy_count(self.device), 2)

    def test_get_qos_policy_count_empty(self):
        self._patch_parser(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_qos_policy_count(self.device), 0)


class TestQosGetCoverage(unittest.TestCase):
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in get.py must
        have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(get_module, inspect.isfunction)
            if obj.__module__ == get_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in qos/get.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
