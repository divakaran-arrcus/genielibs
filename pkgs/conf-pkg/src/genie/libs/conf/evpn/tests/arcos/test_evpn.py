"""Unit tests for ArcOS EVPN configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.evpn.arcos.evpn import Evpn


class TestEvpn(TestCase):
    """Unit tests for Evpn configuration object."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def test_evpn_basic_config(self):
        """Test basic EVPN configuration generates expected CLI."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.anycast_gateway_mac = "aa:bb:cc:01:02:03"
        dev_attr.df_election_time = 15
        dev_attr.duplicate_mac_window = 60
        dev_attr.duplicate_mac_threshold = 7
        dev_attr.duplicate_mac_auto_recovery_time = 5
        dev_attr.overlay_ltep_id = 0
        dev_attr.overlay_ltep_source_interface = "loopback0"
        dev_attr.esi_interfaces = {
            "bond0": {"esi": "00:01:02:03:04:05:06:07:08:09"},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("evpn anycast-gateway-mac aa:bb:cc:01:02:03", output)
        self.assertIn("evpn df-election-time 15", output)
        self.assertIn("evpn duplicate-mac-detection window 60", output)
        self.assertIn("evpn duplicate-mac-detection threshold 7", output)
        self.assertIn("evpn duplicate-mac-detection auto-recovery-time 5", output)
        self.assertIn("overlay local-tunnel-endpoint 0", output)
        self.assertIn("source-interface loopback0", output)
        self.assertIn("interface bond0", output)
        self.assertIn("evpn esi 00:01:02:03:04:05:06:07:08:09", output)

    def test_evpn_unconfig(self):
        """Test EVPN unconfiguration generates expected 'no' CLI."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.anycast_gateway_mac = "aa:bb:cc:01:02:03"
        dev_attr.df_election_time = 15
        dev_attr.overlay_ltep_id = 0
        dev_attr.esi_interfaces = {
            "bond0": {"esi": "00:01:02:03:04:05:06:07:08:09"},
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no evpn anycast-gateway-mac", output)
        self.assertIn("no evpn df-election-time", output)
        self.assertIn("no overlay local-tunnel-endpoint 0", output)
        self.assertIn("no interface bond0 evpn esi", output)

    def test_evpn_empty_config(self):
        """Test EVPN with no attributes generates empty config."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config).strip()

        self.assertEqual(output, "")

    def test_evpn_ltep_only(self):
        """Test EVPN with only LTEP config."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.overlay_ltep_id = 0
        dev_attr.overlay_ltep_source_interface = "loopback0"

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("overlay local-tunnel-endpoint 0", output)
        self.assertIn("source-interface loopback0", output)
        self.assertNotIn("evpn anycast-gateway-mac", output)

    def test_evpn_multiple_esi(self):
        """Test EVPN with multiple ESI interfaces."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.esi_interfaces = {
            "bond0": {"esi": "00:01:02:03:04:05:06:07:08:09"},
            "bond1": {"esi": "00:aa:bb:cc:dd:ee:ff:00:00:01"},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertIn("evpn esi 00:01:02:03:04:05:06:07:08:09", output)
        self.assertIn("interface bond1", output)
        self.assertIn("evpn esi 00:aa:bb:cc:dd:ee:ff:00:00:01", output)

    def test_evpn_duplicate_mac_only(self):
        """Test EVPN with only duplicate MAC detection config."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.duplicate_mac_window = 180
        dev_attr.duplicate_mac_threshold = 5
        dev_attr.duplicate_mac_auto_recovery_time = 0

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("evpn duplicate-mac-detection window 180", output)
        self.assertIn("evpn duplicate-mac-detection threshold 5", output)
        self.assertIn("evpn duplicate-mac-detection auto-recovery-time 0", output)
        self.assertNotIn("overlay", output)
        self.assertNotIn("interface", output)

    def test_evpn_ltep_without_source_interface(self):
        """Test LTEP with only the id (no source-interface) hits the
        'else' branch that emits a bare overlay LTEP line."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.overlay_ltep_id = 0

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("overlay local-tunnel-endpoint 0", output)
        self.assertNotIn("source-interface", output)

    def test_evpn_esi_interfaces_skips_blank_entries(self):
        """Entries with a falsy interface name or None attrs are skipped
        (the 'continue' branch) on the config side."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.esi_interfaces = {
            "": {"esi": "00:01:02:03:04:05:06:07:08:09"},
            "bond2": None,
            "bond0": {"esi": "00:01:02:03:04:05:06:07:08:09"},
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond0", output)
        self.assertNotIn("bond2", output)

    def test_evpn_esi_interfaces_non_dict_attrs(self):
        """intf_attrs need not be a dict — a plain object with an 'esi'
        attribute is read via the getattr() fallback branch."""

        class _EsiAttrs:
            esi = "00:aa:bb:cc:dd:ee:ff:00:00:02"

        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.esi_interfaces = {"bond3": _EsiAttrs()}

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("interface bond3", output)
        self.assertIn("evpn esi 00:aa:bb:cc:dd:ee:ff:00:00:02", output)

    def test_evpn_unconfig_duplicate_mac_detection(self):
        """Unconfig side of duplicate-mac-detection window/threshold/
        auto-recovery-time (each independently gated)."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.duplicate_mac_window = 180
        dev_attr.duplicate_mac_threshold = 5
        dev_attr.duplicate_mac_auto_recovery_time = 0

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no evpn duplicate-mac-detection window", output)
        self.assertIn("no evpn duplicate-mac-detection threshold", output)
        self.assertIn(
            "no evpn duplicate-mac-detection auto-recovery-time", output
        )

    def test_evpn_unconfig_esi_interfaces_skips_blank_entries(self):
        """Unconfig side also skips falsy-name / None-attrs ESI entries."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.esi_interfaces = {
            "bond2": None,
            "bond0": {"esi": "00:01:02:03:04:05:06:07:08:09"},
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no interface bond0 evpn esi", output)
        self.assertNotIn("bond2", output)

    def test_evpn_build_config_apply_true_calls_device_configure(self):
        """apply=True (the default) renders the config and calls
        device.configure(str(config), fail_invalid=True) instead of
        returning a CliConfig."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.anycast_gateway_mac = "aa:bb:cc:01:02:03"

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("evpn anycast-gateway-mac aa:bb:cc:01:02:03", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))

    def test_evpn_build_config_apply_true_empty_config_skips_configure(self):
        """apply=True with no attributes set produces an empty CliConfig,
        so device.configure() must not be called."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_not_called()

    def test_evpn_build_unconfig_apply_true_calls_device_configure(self):
        """build_unconfig(apply=True) also dispatches to device.configure()
        with the 'no ...' lines."""
        dev_attr = Evpn.DeviceAttributes()
        dev_attr.device = self.device

        dev_attr.df_election_time = 15

        result = dev_attr.build_unconfig(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("no evpn df-election-time", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))


class TestEvpnConfCoverage(TestCase):
    """Machine-checked coverage: every public method on
    Evpn.DeviceAttributes must be referenced by name somewhere in this
    test file's source.
    """

    def test_all_public_methods_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name in vars(Evpn.DeviceAttributes)
            if not name.startswith("_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Evpn.DeviceAttributes methods: {missing}")

        print(
            f"\nEVPN conf coverage: {len(names)} public methods, 0 missing"
        )
