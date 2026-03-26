"""Unit tests for ArcOS Keychains configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.keychains.arcos.keychains import Keychains


class TestKeychains(TestCase):
    """Unit tests for Keychains configuration object."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = 'test-device'
        self.device.custom = {'instance_name': 'default'}

    def _make_conf(self, **kwargs):
        """Create a Keychains.DeviceAttributes instance with given attrs."""
        obj = Keychains.DeviceAttributes.__new__(
            Keychains.DeviceAttributes)
        obj.device = self.device
        for k, v in kwargs.items():
            setattr(obj, k, v)
        return obj

    def test_basic_keychain_config(self):
        """Test basic keychain with one key generates expected CLI."""
        conf = self._make_conf(
            keychain_name='isis-key',
            tolerance=None,
            keys={
                10: {
                    'secret_key': 'MyPassword123',
                    'crypto_algorithm': 'HMAC_SHA_1',
                    'send_lifetime_always': True,
                },
            },
        )

        result = conf.build_config(apply=False)
        cli = str(result.cli_config)

        self.assertIn('keychain isis-key', cli)
        self.assertIn('key 10', cli)
        self.assertIn('secret-key MyPassword123', cli)
        self.assertIn('crypto-algorithm HMAC_SHA_1', cli)
        self.assertIn('send-lifetime always true', cli)

    def test_keychain_with_tolerance(self):
        """Test keychain with tolerance generates correct CLI."""
        conf = self._make_conf(
            keychain_name='mykeychain',
            tolerance=90,
            keys={
                10: {
                    'secret_key': 'Pass1',
                    'crypto_algorithm': 'HMAC_SHA_224',
                    'send_lifetime_always': True,
                },
            },
        )

        result = conf.build_config(apply=False)
        cli = str(result.cli_config)

        self.assertIn('keychain mykeychain', cli)
        self.assertIn('tolerance 90', cli)

    def test_keychain_with_lifetime_times(self):
        """Test keychain with start/end times."""
        conf = self._make_conf(
            keychain_name='timed-key',
            tolerance=None,
            keys={
                20: {
                    'secret_key': 'TimedPass',
                    'crypto_algorithm': 'HMAC_SHA_256',
                    'send_lifetime_always': None,
                    'send_lifetime_start_time': '2026-01-01T00:00:00',
                    'send_lifetime_end_time': '2026-12-31T23:59:59',
                },
            },
        )

        result = conf.build_config(apply=False)
        cli = str(result.cli_config)

        self.assertIn('send-lifetime start-time 2026-01-01T00:00:00', cli)
        self.assertIn('send-lifetime end-time 2026-12-31T23:59:59', cli)
        self.assertNotIn('send-lifetime always', cli)

    def test_keychain_multiple_keys(self):
        """Test keychain with multiple key entries."""
        conf = self._make_conf(
            keychain_name='multi-key',
            tolerance=None,
            keys={
                10: {
                    'secret_key': 'Key1Pass',
                    'crypto_algorithm': 'HMAC_SHA_1',
                    'send_lifetime_always': True,
                },
                20: {
                    'secret_key': 'Key2Pass',
                    'crypto_algorithm': 'HMAC_SHA_256',
                    'send_lifetime_always': True,
                },
            },
        )

        result = conf.build_config(apply=False)
        cli = str(result.cli_config)

        self.assertIn('key 10', cli)
        self.assertIn('key 20', cli)
        # Key 10 should appear before key 20 (sorted)
        self.assertLess(cli.index('key 10'), cli.index('key 20'))

    def test_keychain_unconfig(self):
        """Test keychain unconfiguration generates 'no keychain' CLI."""
        conf = self._make_conf(
            keychain_name='isis-key',
            tolerance=None,
            keys=None,
        )

        result = conf.build_unconfig(apply=False)
        cli = str(result.cli_config)

        self.assertIn('no keychain isis-key', cli)

    def test_empty_keychain_name(self):
        """Test with no keychain_name set returns empty config."""
        conf = self._make_conf(
            keychain_name=None,
            tolerance=None,
            keys=None,
        )

        result = conf.build_config(apply=False)
        cli = str(result.cli_config)
        self.assertEqual(cli.strip(), '')
