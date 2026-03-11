"""Unit tests for ArcOS routing-policy configure APIs."""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.route_policy.configure import (
    configure_prefix_set,
    unconfigure_prefix_set,
    configure_prefix_set_entry,
    unconfigure_prefix_set_entry,
    configure_routing_policy,
    unconfigure_routing_policy,
)


class TestConfigurePrefixSet(unittest.TestCase):
    """Test configure_prefix_set and unconfigure_prefix_set."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_configure_prefix_set_single_prefix(self):
        """Test creating a prefix-set with one prefix."""
        configure_prefix_set(
            self.device,
            set_name="MY-SET",
            prefixes=[{"prefix": "10.0.0.0/8", "masklength_range": "exact"}],
        )
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertIn("routing-policy defined-sets prefix-set MY-SET", config)
        self.assertIn("prefix 10.0.0.0/8 exact", config)

    def test_configure_prefix_set_multiple_prefixes(self):
        """Test creating a prefix-set with multiple prefixes."""
        configure_prefix_set(
            self.device,
            set_name="LEAK-SET",
            prefixes=[
                {"prefix": "6.6.6.6/32", "masklength_range": "exact"},
                {"prefix": "10.0.0.0/8", "masklength_range": "8..24"},
            ],
        )
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertIn("prefix 6.6.6.6/32 exact", config)
        self.assertIn("prefix 10.0.0.0/8 8..24", config)

    def test_configure_prefix_set_failure(self):
        """Test failure raises SubCommandFailure."""
        self.device.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            configure_prefix_set(
                self.device,
                set_name="BAD-SET",
                prefixes=[{"prefix": "1.2.3.0/24", "masklength_range": "exact"}],
            )

    def test_unconfigure_prefix_set(self):
        """Test removing a prefix-set."""
        unconfigure_prefix_set(self.device, set_name="MY-SET")
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertIn("no routing-policy defined-sets prefix-set MY-SET", config)


class TestConfigurePrefixSetEntry(unittest.TestCase):
    """Test configure_prefix_set_entry and unconfigure_prefix_set_entry."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_configure_prefix_set_entry_default_mask(self):
        """Test adding a single prefix with default masklength_range."""
        configure_prefix_set_entry(self.device, "MY-SET", "10.0.0.0/8")
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertIn("prefix 10.0.0.0/8 exact", config)

    def test_configure_prefix_set_entry_custom_mask(self):
        """Test adding a single prefix with custom masklength_range."""
        configure_prefix_set_entry(
            self.device, "MY-SET", "10.0.0.0/8", masklength_range="8..24"
        )
        config = self.device.configure.call_args[0][0]
        self.assertIn("prefix 10.0.0.0/8 8..24", config)

    def test_unconfigure_prefix_set_entry(self):
        """Test removing a single prefix entry."""
        unconfigure_prefix_set_entry(self.device, "MY-SET", "10.0.0.0/8")
        config = self.device.configure.call_args[0][0]
        self.assertIn("no prefix 10.0.0.0/8 exact", config)


class TestConfigureRoutingPolicy(unittest.TestCase):
    """Test configure_routing_policy and unconfigure_routing_policy."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_configure_routing_policy_simple_accept(self):
        """Test creating a simple accept-all policy."""
        configure_routing_policy(
            self.device, policy_name="ALLOW-ALL", action="accept-route"
        )
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertIn("routing-policy policy-definition ALLOW-ALL", config)
        self.assertIn("statement pass-all", config)
        self.assertIn("actions accept-route", config)

    def test_configure_routing_policy_with_prefix_match(self):
        """Test creating a policy with prefix-set match condition."""
        configure_routing_policy(
            self.device,
            policy_name="MATCH-LEAKED",
            action="accept-route",
            statement_name="10",
            match_prefix_set="LEAK-PREFIXES",
            match_set_options="ANY",
        )
        config = self.device.configure.call_args[0][0]
        self.assertIn("statement 10", config)
        self.assertIn(
            "conditions match-prefix-set prefix-set LEAK-PREFIXES", config
        )
        self.assertIn(
            "conditions match-prefix-set match-set-options ANY", config
        )
        self.assertIn("actions accept-route", config)

    def test_configure_routing_policy_reject(self):
        """Test creating a reject policy."""
        configure_routing_policy(
            self.device,
            policy_name="DENY-ALL",
            action="reject-route",
            statement_name="deny",
        )
        config = self.device.configure.call_args[0][0]
        self.assertIn("actions reject-route", config)

    def test_configure_routing_policy_failure(self):
        """Test failure raises SubCommandFailure."""
        self.device.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            configure_routing_policy(self.device, policy_name="BAD-POLICY")

    def test_unconfigure_routing_policy(self):
        """Test removing a policy definition."""
        unconfigure_routing_policy(self.device, policy_name="ALLOW-ALL")
        config = self.device.configure.call_args[0][0]
        self.assertIn(
            "no routing-policy policy-definition ALLOW-ALL", config
        )


if __name__ == "__main__":
    unittest.main()
