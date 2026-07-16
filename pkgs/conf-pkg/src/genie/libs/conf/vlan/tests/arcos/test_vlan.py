"""Unit tests for ArcOS VLAN configuration object."""

from unittest import TestCase
from unittest.mock import Mock, patch

from genie.libs.conf.vlan.arcos.vlan import Vlan

MOD = "genie.libs.conf.vlan.arcos.vlan"


class TestVlanAttributes(TestCase):
    """Unit tests for Vlan.DeviceAttributes.VlanAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"

    def test_vlan_basic_config(self):
        """Test basic VLAN config generates vlan name and vlan-id."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "VLAN100"
        attr.vlan_id = 100

        result = attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("vlan VLAN100", output)
        self.assertIn("vlan-id 100", output)

    def test_vlan_unconfig(self):
        """Test VLAN unconfiguration generates 'no vlan <name>'."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "VLAN100"
        attr.vlan_id = 100

        result = attr.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn("no vlan VLAN100", output)
        # Unconfig should NOT contain vlan-id sub-command
        self.assertNotIn("vlan-id", output)

    def test_vlan_config_without_vlan_id(self):
        """Test VLAN config with no vlan_id produces empty submode (cancel_empty)."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "VLAN200"
        # Deliberately do not set vlan_id

        result = attr.build_config(apply=False)
        output = str(result.cli_config).strip()

        # cancel_empty=True means no output when submode body is empty
        self.assertEqual(output, "")

    def test_vlan_unconfig_without_vlan_id(self):
        """Test VLAN unconfig works even when vlan_id is not set."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "MGMT-VLAN"

        result = attr.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn("no vlan MGMT-VLAN", output)

    def test_vlan_different_names(self):
        """Test VLAN config with various name formats."""
        for name, vid in [("DATA", 10), ("voice-vlan", 20), ("VLAN_999", 999)]:
            attr = Vlan.DeviceAttributes.VlanAttributes()
            attr.device = self.device
            attr.vlan_name = name
            attr.vlan_id = vid

            result = attr.build_config(apply=False)
            output = str(result.cli_config)

            self.assertIn(f"vlan {name}", output)
            self.assertIn(f"vlan-id {vid}", output)

    def test_vlan_build_unconfig_wrapper(self):
        """VlanAttributes.build_unconfig() delegates to build_config(unconfig=True)."""
        attr = Vlan.DeviceAttributes.VlanAttributes()
        attr.device = self.device
        attr.vlan_name = "VLAN300"
        attr.vlan_id = 300

        result = attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no vlan VLAN300", output)


class TestDeviceAttributesBuildConfig(TestCase):
    """Unit tests for Vlan.DeviceAttributes.build_config()/build_unconfig().

    This mixin is a bare ABC (not wired through the genie Device/Testbed
    factory), so DeviceAttributes.build_config() drives
    attributes.mapping_values("vlan_attr", keys=self.vlans, ...) directly.
    AttributesHelper is patched to control the (sub, vlan_attributes) pairs
    it yields without needing a full genie Testbed/Device object graph.
    """

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"
        self.device.configure = Mock(return_value=True)

    def _make_device_attr(self, vlans):
        dev_attr = Vlan.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.vlans = vlans
        return dev_attr

    @patch(f"{MOD}.AttributesHelper")
    def test_build_config_apply_false_returns_cli_config(self, mock_helper_cls):
        dev_attr = self._make_device_attr(["VLAN100"])

        sub = Mock()
        sub.build_config.return_value = "vlan VLAN100\n vlan-id 100\n!"
        mock_helper = mock_helper_cls.return_value
        mock_helper.mapping_values.return_value = [(sub, Mock(name="vlan_attrs"))]

        result = dev_attr.build_config(apply=False)

        mock_helper.mapping_values.assert_called_once_with(
            "vlan_attr", keys=["VLAN100"], sort=True
        )
        sub.build_config.assert_called_once()
        self.assertIn("vlan VLAN100", str(result.cli_config))
        self.device.configure.assert_not_called()

    @patch(f"{MOD}.AttributesHelper")
    def test_build_config_apply_true_configures_device(self, mock_helper_cls):
        dev_attr = self._make_device_attr(["VLAN200"])

        sub = Mock()
        sub.build_config.return_value = "vlan VLAN200\n vlan-id 200\n!"
        mock_helper = mock_helper_cls.return_value
        mock_helper.mapping_values.return_value = [(sub, Mock())]

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        self.assertIn("vlan VLAN200", self.device.configure.call_args[0][0])

    @patch(f"{MOD}.AttributesHelper")
    def test_build_config_apply_true_no_vlans_skips_configure(self, mock_helper_cls):
        """Empty vlan set -> configurations stays falsy -> no device.configure()."""
        dev_attr = self._make_device_attr([])

        mock_helper = mock_helper_cls.return_value
        mock_helper.mapping_values.return_value = []

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_not_called()

    @patch(f"{MOD}.AttributesHelper")
    def test_build_config_falsy_sub_config_not_appended(self, mock_helper_cls):
        """A sub.build_config() that returns an empty/falsy block is skipped."""
        dev_attr = self._make_device_attr(["VLAN300"])

        sub = Mock()
        sub.build_config.return_value = ""
        mock_helper = mock_helper_cls.return_value
        mock_helper.mapping_values.return_value = [(sub, Mock())]

        result = dev_attr.build_config(apply=False)

        self.assertEqual(str(result.cli_config).strip(), "")

    @patch(f"{MOD}.AttributesHelper")
    def test_build_unconfig_wrapper(self, mock_helper_cls):
        """DeviceAttributes.build_unconfig() delegates to build_config(unconfig=True)."""
        dev_attr = self._make_device_attr(["VLAN100"])

        sub = Mock()
        sub.build_config.return_value = "no vlan VLAN100"
        mock_helper = mock_helper_cls.return_value
        mock_helper.mapping_values.return_value = [(sub, Mock())]

        result = dev_attr.build_unconfig(apply=False)

        # unconfig=True must have been forwarded down to the sub-attribute build
        _, kwargs = sub.build_config.call_args
        self.assertTrue(kwargs["unconfig"])
        self.assertIn("no vlan VLAN100", str(result.cli_config))
