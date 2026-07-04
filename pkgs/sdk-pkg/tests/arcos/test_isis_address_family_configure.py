"""Unit tests for ArcOS ISIS global (instance-level) address-family configure APIs.

Covers:
  - configure_isis_address_family   (ipv4/ipv6, enabled True/False)
  - unconfigure_isis_address_family (ipv4/ipv6)

in ``genie.libs.sdk.apis.arcos.isis.configure``.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.isis.configure import (
    configure_isis_address_family,
    unconfigure_isis_address_family,
)


class TestConfigureIsisAddressFamily(unittest.TestCase):
    """Test configure_isis_address_family."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_ipv4_enabled_true(self):
        configure_isis_address_family(self.device, af="ipv4", enabled=True)
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "global af IPV4 UNICAST",
            "enabled true",
            "exit",
            "!",
        ])

    def test_ipv6_enabled_false(self):
        configure_isis_address_family(self.device, af="ipv6", enabled=False)
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "global af IPV6 UNICAST",
            "enabled false",
            "exit",
            "!",
        ])

    def test_case_insensitive_af(self):
        configure_isis_address_family(self.device, af="IPv4", enabled=True)
        config = self.device.configure.call_args[0][0]
        self.assertIn("global af IPV4 UNICAST", config)

    def test_custom_instance(self):
        configure_isis_address_family(
            self.device, af="ipv4", enabled=True,
            network_instance="red", protocol_instance="isis1",
        )
        config = self.device.configure.call_args[0][0]
        self.assertEqual(
            config[0], "network-instance red protocol ISIS isis1"
        )

    def test_invalid_af_raises(self):
        with self.assertRaises(ValueError):
            configure_isis_address_family(self.device, af="ipv7")

    def test_failure_raises(self):
        self.device.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            configure_isis_address_family(self.device, af="ipv4")


class TestUnconfigureIsisAddressFamily(unittest.TestCase):
    """Test unconfigure_isis_address_family."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_ipv4(self):
        unconfigure_isis_address_family(self.device, af="ipv4")
        self.device.configure.assert_called_once()
        config = self.device.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "no global af IPV4 UNICAST",
            "!",
        ])

    def test_ipv6(self):
        unconfigure_isis_address_family(self.device, af="ipv6")
        config = self.device.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "no global af IPV6 UNICAST",
            "!",
        ])

    def test_custom_instance(self):
        unconfigure_isis_address_family(
            self.device, af="ipv6",
            network_instance="red", protocol_instance="isis1",
        )
        config = self.device.configure.call_args[0][0]
        self.assertEqual(
            config[0], "network-instance red protocol ISIS isis1"
        )

    def test_invalid_af_raises(self):
        with self.assertRaises(ValueError):
            unconfigure_isis_address_family(self.device, af="bogus")

    def test_failure_raises(self):
        self.device.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            unconfigure_isis_address_family(self.device, af="ipv4")


if __name__ == "__main__":
    unittest.main()
