#!/usr/bin/env python3
"""Unit tests for arcOS CoPP configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.copp.configure builds a `copp ...` /
`control-plane ...` CLI config list and calls `device.configure(config)`.
Tests mock device.configure and assert on a distinctive substring of the
emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.copp import configure as copp_configure
from genie.libs.sdk.apis.arcos.copp.configure import (
    configure_copp_classifier,
    unconfigure_copp_classifier,
    configure_copp_policy,
    unconfigure_copp_policy,
    configure_copp_service_policy,
    unconfigure_copp_service_policy,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureCoppClassifier(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_classifier_acl(self):
        configure_copp_classifier(
            self.d, "MY-COPP", "ACL", acl_type="ACL_IPV4", acl_name="v4-acl"
        )
        c = self.d.cfg()
        self.assertIn("copp classifier MY-COPP", c)
        self.assertIn("filter ACL acl-type ACL_IPV4 acl-name v4-acl", c)

    def test_classifier_exception(self):
        configure_copp_classifier(
            self.d, "EXC-COPP", "EXCEPTION", exception_type="TTL_EXPIRY"
        )
        c = self.d.cfg()
        self.assertIn("copp classifier EXC-COPP", c)
        self.assertIn("filter EXCEPTION TTL_EXPIRY", c)

    def test_classifier_no_filter(self):
        configure_copp_classifier(self.d, "BARE-COPP", "ACL")
        c = self.d.cfg()
        self.assertIn("copp classifier BARE-COPP", c)
        self.assertNotIn("filter", c)

    def test_unconfigure_classifier(self):
        unconfigure_copp_classifier(self.d, "MY-COPP")
        self.assertIn("no copp classifier MY-COPP", self.d.cfg())


class TestConfigureCoppPolicy(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_policy_police_action(self):
        configure_copp_policy(
            self.d, "MY-POLICY",
            [{"classifier": "MY-COPP", "action_type": "POLICE",
              "rate": 5000, "burst": 1000}],
        )
        c = self.d.cfg()
        self.assertIn("copp policy MY-POLICY", c)
        self.assertIn("classifier MY-COPP", c)
        self.assertIn("action POLICE committed rate value 5000", c)
        self.assertIn("action POLICE committed burst value 1000", c)

    def test_policy_police_default_rate_no_burst(self):
        configure_copp_policy(
            self.d, "DEF-POLICY",
            [{"classifier": "C1", "action_type": "POLICE"}],
        )
        c = self.d.cfg()
        self.assertIn("action POLICE committed rate value 1000", c)
        self.assertNotIn("burst", c)

    def test_policy_mark_action(self):
        configure_copp_policy(
            self.d, "MARK-POLICY",
            [{"classifier": "C2", "action_type": "MARK", "local_tc": 3}],
        )
        c = self.d.cfg()
        self.assertIn("action MARK marking local-tc 3", c)

    def test_policy_mark_default_tc(self):
        configure_copp_policy(
            self.d, "MARK-DEF",
            [{"classifier": "C3", "action_type": "MARK"}],
        )
        self.assertIn("action MARK marking local-tc 7", self.d.cfg())

    def test_policy_drop_action(self):
        configure_copp_policy(
            self.d, "DROP-POLICY",
            [{"classifier": "C4", "action_type": "DROP"}],
        )
        self.assertIn("action DROP", self.d.cfg())

    def test_policy_multiple_classifier_actions(self):
        configure_copp_policy(
            self.d, "MULTI-POLICY",
            [
                {"classifier": "C1", "action_type": "POLICE", "rate": 2000},
                {"classifier": "C2", "action_type": "DROP"},
            ],
        )
        c = self.d.cfg()
        self.assertIn("classifier C1", c)
        self.assertIn("classifier C2", c)
        self.assertIn("action DROP", c)

    def test_unconfigure_policy(self):
        unconfigure_copp_policy(self.d, "MY-POLICY")
        self.assertIn("no copp policy MY-POLICY", self.d.cfg())


class TestConfigureCoppServicePolicy(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_service_policy(self):
        configure_copp_service_policy(self.d, "MY-POLICY")
        self.assertIn(
            "control-plane service-policy INGRESS name MY-POLICY", self.d.cfg()
        )

    def test_unconfigure_service_policy(self):
        unconfigure_copp_service_policy(self.d)
        self.assertIn("no control-plane service-policy INGRESS", self.d.cfg())


class TestConfigureCoppErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context."""

    def setUp(self):
        self.d = _CfgDevice()

    def _fail(self):
        from unicon.core.errors import SubCommandFailure
        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))

    def test_configure_copp_classifier_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_copp_classifier(self.d, "MY-COPP", "ACL")

    def test_unconfigure_copp_classifier_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_copp_classifier(self.d, "MY-COPP")

    def test_configure_copp_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_copp_policy(self.d, "MY-POLICY", [])

    def test_unconfigure_copp_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_copp_policy(self.d, "MY-POLICY")

    def test_configure_copp_service_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_copp_service_policy(self.d, "MY-POLICY")

    def test_unconfigure_copp_service_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_copp_service_policy(self.d)


class TestCoppConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in copp/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(copp_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == copp_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered CoPP configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nCoPP configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
