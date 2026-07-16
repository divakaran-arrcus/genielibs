#!/usr/bin/env python3
"""Unit tests for arcOS SR-Policy configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.sr_policy.configure builds an arcOS CLI config
list (typically starting with the `network-instance default sr-policy ...`
context) and calls device.configure(config). Tests mock device.configure and
assert on a distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.sr_policy import configure as sr_policy_configure
from genie.libs.sdk.apis.arcos.sr_policy.configure import (
    configure_sr_policy_segment_list,
    unconfigure_sr_policy_segment_list,
    configure_sr_policy_dynamic_color,
    unconfigure_sr_policy_dynamic_color,
    configure_sr_policy_policy,
    unconfigure_sr_policy_policy,
    configure_sr_policy_enabled,
    unconfigure_sr_policy_enabled,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestSegmentListConfigureApis(unittest.TestCase):
    """configure_sr_policy_segment_list / unconfigure_sr_policy_segment_list"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_segment_list_basic(self):
        configure_sr_policy_segment_list(self.d, "sl1", [
            {"index": 1, "type": "MPLS_LABEL", "mpls_label": 100000},
            {"index": 2, "type": "MPLS_LABEL", "mpls_label": 100001},
        ])
        c = self.d.cfg()
        self.assertIn("network-instance default sr-policy segment-list sl1", c)
        self.assertIn("segment 1", c)
        self.assertIn("type MPLS_LABEL", c)
        self.assertIn("mpls-label 100000", c)
        self.assertIn("segment 2", c)
        self.assertIn("mpls-label 100001", c)

    def test_segment_list_srv6_and_validate(self):
        configure_sr_policy_segment_list(self.d, "sl2", [
            {
                "index": 1,
                "type": "SRV6_SID",
                "srv6_sid": "2001:db8::1",
                "validate": True,
            },
        ])
        c = self.d.cfg()
        self.assertIn("segment 1", c)
        self.assertIn("type SRV6_SID", c)
        self.assertIn("srv6-sid 2001:db8::1", c)
        self.assertIn("validate true", c)

    def test_segment_list_validate_false(self):
        configure_sr_policy_segment_list(self.d, "sl3", [
            {"index": 1, "validate": False},
        ])
        c = self.d.cfg()
        self.assertIn("validate false", c)

    def test_segment_list_skips_segment_without_index(self):
        configure_sr_policy_segment_list(self.d, "sl4", [
            {"type": "MPLS_LABEL", "mpls_label": 100000},
        ])
        c = self.d.cfg()
        self.assertNotIn("segment ", c)

    def test_unconfigure_segment_list(self):
        unconfigure_sr_policy_segment_list(self.d, "sl1")
        self.assertIn(
            "no network-instance default sr-policy segment-list sl1",
            self.d.cfg(),
        )


class TestDynamicColorConfigureApis(unittest.TestCase):
    """configure_sr_policy_dynamic_color / unconfigure_sr_policy_dynamic_color"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_dynamic_color(self):
        configure_sr_policy_dynamic_color(self.d, 100, 128)
        c = self.d.cfg()
        self.assertIn(
            "network-instance default sr-policy dynamic-policy-color 100", c
        )
        self.assertIn(
            "dynamic constraints segment-rules sid-algorithm 128", c
        )

    def test_unconfigure_dynamic_color(self):
        unconfigure_sr_policy_dynamic_color(self.d, 100)
        self.assertIn(
            "no network-instance default sr-policy dynamic-policy-color 100",
            self.d.cfg(),
        )


class TestPolicyConfigureApis(unittest.TestCase):
    """configure_sr_policy_policy / unconfigure_sr_policy_policy"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_policy_basic(self):
        configure_sr_policy_policy(self.d, "2.2.2.2", 100)
        c = self.d.cfg()
        self.assertIn("network-instance default sr-policy policy 2.2.2.2 100", c)
        self.assertIn("enabled true", c)
        self.assertNotIn("name ", c)

    def test_policy_with_name(self):
        configure_sr_policy_policy(self.d, "2.2.2.2", 100, name="test-pol")
        self.assertIn("name test-pol", self.d.cfg())

    def test_policy_with_explicit_candidate_path(self):
        configure_sr_policy_policy(self.d, "2.2.2.2", 100, name="test-pol",
                                    candidate_paths=[{
                                        "discriminator": 10,
                                        "preference": 200,
                                        "type": "EXPLICIT_SEGMENT_LIST",
                                        "explicit_segment_list": "sl1",
                                    }])
        c = self.d.cfg()
        self.assertIn("candidate-path 10", c)
        self.assertIn("preference 200", c)
        self.assertIn("type EXPLICIT_SEGMENT_LIST", c)
        self.assertIn("explicit segment-list sl1", c)

    def test_policy_with_dynamic_candidate_path(self):
        configure_sr_policy_policy(self.d, "3.3.3.3", 200,
                                    candidate_paths=[{
                                        "discriminator": 20,
                                        "type": "DYNAMIC",
                                        "dynamic_dataplane": "MPLS",
                                        "dynamic_sid_algorithm": 128,
                                    }])
        c = self.d.cfg()
        self.assertIn("candidate-path 20", c)
        self.assertIn("dynamic dataplane MPLS", c)
        self.assertIn(
            "dynamic constraints segment-rules sid-algorithm 128", c
        )

    def test_policy_skips_candidate_path_without_discriminator(self):
        configure_sr_policy_policy(self.d, "2.2.2.2", 100,
                                    candidate_paths=[{"preference": 100}])
        self.assertNotIn("candidate-path", self.d.cfg())

    def test_unconfigure_policy(self):
        unconfigure_sr_policy_policy(self.d, "2.2.2.2", 100)
        self.assertIn(
            "no network-instance default sr-policy policy 2.2.2.2 100",
            self.d.cfg(),
        )


class TestPolicyEnabledConfigureApis(unittest.TestCase):
    """configure_sr_policy_enabled / unconfigure_sr_policy_enabled"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_enabled_true(self):
        configure_sr_policy_enabled(self.d, "2.2.2.2", 100)
        c = self.d.cfg()
        self.assertIn("network-instance default sr-policy policy 2.2.2.2 100", c)
        self.assertIn("enabled true", c)

    def test_enabled_false(self):
        configure_sr_policy_enabled(self.d, "2.2.2.2", 100, enabled=False)
        self.assertIn("enabled false", self.d.cfg())

    def test_unconfigure_enabled(self):
        unconfigure_sr_policy_enabled(self.d, "2.2.2.2", 100)
        c = self.d.cfg()
        self.assertIn("network-instance default sr-policy policy 2.2.2.2 100", c)
        self.assertIn("no enabled", c)


class TestSrPolicyConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in sr_policy/configure.py must be referenced by name somewhere
    in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sr_policy_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sr_policy_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Untested configure/unconfigure functions: {missing}"
        )

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nSR-Policy configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
