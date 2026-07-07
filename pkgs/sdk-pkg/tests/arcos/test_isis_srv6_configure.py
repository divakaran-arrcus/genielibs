"""Unit tests for ArcOS ISIS global (instance-level) SRv6 configure APIs.

Covers:
  - configure_isis_srv6          (enabled True/False)
  - unconfigure_isis_srv6
  - configure_isis_srv6_locator
  - unconfigure_isis_srv6_locator

in ``genie.libs.sdk.apis.arcos.isis.configure``.
"""

from unittest import TestCase
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.isis.configure import (
    configure_isis_srv6, unconfigure_isis_srv6,
    configure_isis_srv6_locator, unconfigure_isis_srv6_locator,
)


class TestConfigureIsisSrv6(TestCase):
    def setUp(self):
        self.dev = Mock()
        self.dev.name = "test_device"

    def test_enable(self):
        configure_isis_srv6(self.dev, enabled=True)
        self.dev.configure.assert_called_once()
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "global srv6 enabled true",
            "!",
        ])

    def test_disable(self):
        configure_isis_srv6(self.dev, enabled=False)
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "global srv6 enabled false",
            "!",
        ])

    def test_custom_instance(self):
        configure_isis_srv6(self.dev, network_instance='vrf1', protocol_instance='1')
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance vrf1 protocol ISIS 1",
            "global srv6 enabled true",
            "!",
        ])

    def test_failure_raises(self):
        self.dev.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            configure_isis_srv6(self.dev, enabled=True)


class TestUnconfigureIsisSrv6(TestCase):
    def setUp(self):
        self.dev = Mock()
        self.dev.name = "test_device"

    def test_unconfigure(self):
        unconfigure_isis_srv6(self.dev)
        self.dev.configure.assert_called_once()
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "no global srv6 enabled",
            "!",
        ])

    def test_custom_instance(self):
        unconfigure_isis_srv6(self.dev, network_instance='vrf1', protocol_instance='1')
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance vrf1 protocol ISIS 1",
            "no global srv6 enabled",
            "!",
        ])

    def test_failure_raises(self):
        self.dev.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            unconfigure_isis_srv6(self.dev)


class TestConfigureIsisSrv6Locator(TestCase):
    def setUp(self):
        self.dev = Mock()
        self.dev.name = "test_device"

    def test_bind_locator(self):
        configure_isis_srv6_locator(self.dev, locator='LOC_R1_ALG128')
        self.dev.configure.assert_called_once()
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "global srv6 locator LOC_R1_ALG128",
            "!",
        ])

    def test_custom_instance(self):
        configure_isis_srv6_locator(
            self.dev, locator='LOC_R1_ALG128',
            network_instance='vrf1', protocol_instance='1',
        )
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance vrf1 protocol ISIS 1",
            "global srv6 locator LOC_R1_ALG128",
            "!",
        ])

    def test_failure_raises(self):
        self.dev.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            configure_isis_srv6_locator(self.dev, locator='LOC_R1_ALG128')


class TestUnconfigureIsisSrv6Locator(TestCase):
    def setUp(self):
        self.dev = Mock()
        self.dev.name = "test_device"

    def test_unbind_locator(self):
        unconfigure_isis_srv6_locator(self.dev, locator='LOC_R1_ALG128')
        self.dev.configure.assert_called_once()
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance default protocol ISIS default",
            "no global srv6 locator LOC_R1_ALG128",
            "!",
        ])

    def test_custom_instance(self):
        unconfigure_isis_srv6_locator(
            self.dev, locator='LOC_R1_ALG128',
            network_instance='vrf1', protocol_instance='1',
        )
        config = self.dev.configure.call_args[0][0]
        self.assertEqual(config, [
            "network-instance vrf1 protocol ISIS 1",
            "no global srv6 locator LOC_R1_ALG128",
            "!",
        ])

    def test_failure_raises(self):
        self.dev.configure.side_effect = SubCommandFailure("error")
        with self.assertRaises(SubCommandFailure):
            unconfigure_isis_srv6_locator(self.dev, locator='LOC_R1_ALG128')


if __name__ == "__main__":
    import unittest
    unittest.main()
