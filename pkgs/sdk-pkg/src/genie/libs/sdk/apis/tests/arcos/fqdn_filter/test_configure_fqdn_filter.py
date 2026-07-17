#!/usr/bin/env python3
"""Unit tests for arcOS FQDN Filter configure/unconfigure APIs (full
coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.fqdn_filter.configure builds a top-level
`fqdn-filter ...` CLI config list and calls `device.configure(config)`.
Tests mock device.configure and assert on a distinctive substring of the
emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.fqdn_filter import configure as fqdn_configure
from genie.libs.sdk.apis.arcos.fqdn_filter.configure import (
    configure_fqdn_filter,
    unconfigure_fqdn_filter,
    configure_fqdn_policy,
    unconfigure_fqdn_policy,
    configure_fqdn_active_policies,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureFqdnFilter(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_fqdn_filter_defaults(self):
        configure_fqdn_filter(self.d)
        c = self.d.cfg()
        self.assertIn("fqdn-filter zero-trust-enabled true", c)
        self.assertIn("fqdn-filter enable-fqdn-discovery true", c)
        self.assertNotIn("trusted-dns-servers", c)

    def test_configure_fqdn_filter_disabled(self):
        configure_fqdn_filter(self.d, zero_trust=False, discovery=False)
        c = self.d.cfg()
        self.assertIn("fqdn-filter zero-trust-enabled false", c)
        self.assertIn("fqdn-filter enable-fqdn-discovery false", c)

    def test_configure_fqdn_filter_dns_list(self):
        configure_fqdn_filter(
            self.d, trusted_dns_servers=["8.8.8.8", "1.1.1.1"]
        )
        c = self.d.cfg()
        self.assertIn(
            "fqdn-filter trusted-dns-servers [ 8.8.8.8 1.1.1.1 ]", c
        )

    def test_configure_fqdn_filter_dns_string(self):
        configure_fqdn_filter(self.d, trusted_dns_servers="9.9.9.9")
        c = self.d.cfg()
        self.assertIn("fqdn-filter trusted-dns-servers [ 9.9.9.9 ]", c)

    def test_unconfigure_fqdn_filter(self):
        unconfigure_fqdn_filter(self.d)
        self.assertIn("no fqdn-filter", self.d.cfg())


class TestConfigureFqdnPolicy(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_fqdn_policy_list(self):
        configure_fqdn_policy(self.d, "POL1", ["example.com", "arrcus.com"])
        c = self.d.cfg()
        self.assertIn(
            "fqdn-filter fqdn-policy POL1 fqdns [ example.com arrcus.com ]", c
        )

    def test_configure_fqdn_policy_string(self):
        configure_fqdn_policy(self.d, "POL2", "single.com")
        c = self.d.cfg()
        self.assertIn(
            "fqdn-filter fqdn-policy POL2 fqdns [ single.com ]", c
        )

    def test_unconfigure_fqdn_policy(self):
        unconfigure_fqdn_policy(self.d, "POL1")
        self.assertIn("no fqdn-filter fqdn-policy POL1", self.d.cfg())


class TestConfigureFqdnActivePolicies(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_fqdn_active_policies_list(self):
        configure_fqdn_active_policies(self.d, ["POL1", "POL2"])
        c = self.d.cfg()
        self.assertIn(
            "fqdn-filter active-fqdn-policies [ POL1 POL2 ]", c
        )

    def test_configure_fqdn_active_policies_string(self):
        configure_fqdn_active_policies(self.d, "POL1")
        c = self.d.cfg()
        self.assertIn("fqdn-filter active-fqdn-policies [ POL1 ]", c)


class TestConfigureFqdnFilterErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context."""

    def setUp(self):
        self.d = _CfgDevice()

    def _fail(self):
        from unicon.core.errors import SubCommandFailure
        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))

    def test_configure_fqdn_filter_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_fqdn_filter(self.d)

    def test_unconfigure_fqdn_filter_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_fqdn_filter(self.d)

    def test_configure_fqdn_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_fqdn_policy(self.d, "POL1", ["a.com"])

    def test_unconfigure_fqdn_policy_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            unconfigure_fqdn_policy(self.d, "POL1")

    def test_configure_fqdn_active_policies_failure(self):
        from unicon.core.errors import SubCommandFailure
        self._fail()
        with self.assertRaises(SubCommandFailure):
            configure_fqdn_active_policies(self.d, ["POL1"])


class TestFqdnFilterConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in fqdn_filter/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(fqdn_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == fqdn_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered FQDN Filter configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nFQDN Filter configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
