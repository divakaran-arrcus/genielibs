"""Unit tests for ArcOS Keychains configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.keychains.arcos.keychains import Keychains


class TestKeychains(TestCase):
    """Unit tests for Keychains configuration object."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_keychain_basic(self):
        """Test basic keychain with name, tolerance, and one key."""
        dev_attr = Keychains.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.keychain_name = "isis-key"
        dev_attr.tolerance = 300
        dev_attr.keys = {
            "1": {
                "secret_key": "mypassword",
                "crypto_algorithm": "HMAC_SHA_256",
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("keychain isis-key", output)
        self.assertIn("tolerance 300", output)
        self.assertIn("key 1", output)
        self.assertIn("secret-key mypassword", output)
        self.assertIn("crypto-algorithm HMAC_SHA_256", output)

    def test_keychain_unconfig(self):
        """Test keychain unconfiguration generates 'no keychain <name>'."""
        dev_attr = Keychains.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.keychain_name = "isis-key"
        dev_attr.tolerance = 300

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no keychain isis-key", output)

    def test_keychain_no_name(self):
        """Test keychain with no name generates empty config."""
        dev_attr = Keychains.DeviceAttributes()
        dev_attr.device = self.device

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config).strip()

        self.assertEqual(output, "")

    def test_keychain_multiple_keys(self):
        """Test keychain with multiple key entries."""
        dev_attr = Keychains.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.keychain_name = "multi-key"
        dev_attr.keys = {
            "1": {
                "secret_key": "first-secret",
                "crypto_algorithm": "HMAC_SHA_1",
            },
            "2": {
                "secret_key": "second-secret",
                "crypto_algorithm": "HMAC_SHA_256",
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("keychain multi-key", output)
        self.assertIn("key 1", output)
        self.assertIn("secret-key first-secret", output)
        self.assertIn("crypto-algorithm HMAC_SHA_1", output)
        self.assertIn("key 2", output)
        self.assertIn("secret-key second-secret", output)
        self.assertIn("crypto-algorithm HMAC_SHA_256", output)

    def test_keychain_send_lifetime(self):
        """Test keychain key with send_lifetime_always=True."""
        dev_attr = Keychains.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.keychain_name = "lifetime-key"
        dev_attr.keys = {
            "10": {
                "secret_key": "lifetime-pass",
                "crypto_algorithm": "HMAC_SHA_256",
                "send_lifetime_always": True,
            },
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("keychain lifetime-key", output)
        self.assertIn("key 10", output)
        self.assertIn("secret-key lifetime-pass", output)
        self.assertIn("send-lifetime always true", output)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
