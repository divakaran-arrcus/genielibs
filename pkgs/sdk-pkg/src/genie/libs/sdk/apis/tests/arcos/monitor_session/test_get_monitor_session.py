#!/usr/bin/env python3
"""Unit tests for arcOS Monitor Session (SPAN) get APIs (full coverage).

genie.libs.sdk.apis.arcos.monitor_session.get.get_monitor_sessions
instantiates genie.libs.parser.arcos.show_monitor_session.ShowMonitorSession(
device=device) and calls .parse() on it. The import is a module-level
`from ... import ShowMonitorSession` in get.py, so the name is bound into
get.py's own namespace at import time; tests must patch it at that usage
site (genie.libs.sdk.apis.arcos.monitor_session.get.ShowMonitorSession),
not at its original definition module, or the patch has no effect. Canned
parsed output matches the ShowMonitorSession schema:

    {"sessions": {"<name>": {"name": ..., "enabled": bool (optional),
                              "source-interfaces": {...} (optional),
                              "destination": str (optional)}}}

A machine coverage check (test_zzz_all_functions_covered) asserts every
public get_*/is_* function in the module was exercised.
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from unicon.core.errors import SubCommandFailure
from genie.metaparser.util.exceptions import SchemaEmptyParserError

import genie.libs.sdk.apis.arcos.monitor_session.get as get_module
from genie.libs.sdk.apis.arcos.monitor_session.get import (
    get_monitor_sessions,
    is_monitor_session_present,
)

PARSER_PATCH_TARGET = (
    "genie.libs.sdk.apis.arcos.monitor_session.get.ShowMonitorSession"
)

_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


get_monitor_sessions = _track("get_monitor_sessions", get_monitor_sessions)
is_monitor_session_present = _track(
    "is_monitor_session_present", is_monitor_session_present
)


PARSED = {
    "sessions": {
        "span1": {
            "name": "span1",
            "enabled": True,
            "source-interfaces": {
                "swp1": {"name": "swp1", "direction": "INGRESS"},
            },
            "destination": "swp10",
        },
        "span2": {  # minimal entry - no optional fields
            "name": "span2",
        },
    }
}


class TestGetMonitorSessions(unittest.TestCase):
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

    def test_get_monitor_sessions(self):
        self._patch_parser(return_value=PARSED)
        result = get_monitor_sessions(self.device)
        self.assertEqual(set(result), {"span1", "span2"})

    def test_get_monitor_sessions_fields(self):
        self._patch_parser(return_value=PARSED)
        result = get_monitor_sessions(self.device)
        self.assertTrue(result["span1"]["enabled"])
        self.assertEqual(result["span1"]["destination"], "swp10")
        self.assertIn("swp1", result["span1"]["source-interfaces"])

    def test_is_monitor_session_present_true(self):
        self._patch_parser(return_value=PARSED)
        self.assertTrue(is_monitor_session_present(self.device, "span1"))

    def test_is_monitor_session_present_false(self):
        self._patch_parser(return_value=PARSED)
        self.assertFalse(is_monitor_session_present(self.device, "span99"))


class TestGetMonitorSessionsEmptyAndErrors(unittest.TestCase):
    """Exercise every except branch of get_monitor_sessions."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _patch_parser(self, side_effect):
        patcher = patch(PARSER_PATCH_TARGET)
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        mock_cls.return_value.parse.side_effect = side_effect
        return mock_cls

    def test_get_monitor_sessions_schema_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertEqual(get_monitor_sessions(self.device), {})

    def test_get_monitor_sessions_subcommand_failure(self):
        self._patch_parser(SubCommandFailure("boom"))
        self.assertEqual(get_monitor_sessions(self.device), {})

    def test_get_monitor_sessions_unexpected_exception(self):
        self._patch_parser(ValueError("weird"))
        self.assertEqual(get_monitor_sessions(self.device), {})

    def test_is_monitor_session_present_false_when_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertFalse(is_monitor_session_present(self.device, "span1"))


class TestGetMonitorSessionCoverage(unittest.TestCase):
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
            f"Untested public functions in monitor_session/get.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
