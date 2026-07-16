"""Unit tests for ArcOS SR-Policy configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.sr_policy.arcos.sr_policy import SrPolicy

_NI = 'network-instance default'


class TestSrPolicySegmentListAttributes(TestCase):
    """Unit tests for SrPolicy.DeviceAttributes.SegmentListAttributes
    build_config()/build_unconfig()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_sl(self, name, **attrs):
        sl = SrPolicy.DeviceAttributes.SegmentListAttributes()
        sl.device = self.device
        sl.segment_list_name = name
        for key, value in attrs.items():
            setattr(sl, key, value)
        return sl

    def test_segment_list_mpls(self):
        sl = self._make_sl(
            "sl1",
            segments=[
                {"index": 1, "type": "MPLS_LABEL", "mpls_label": 100000},
                {"index": 2, "type": "MPLS_LABEL", "mpls_label": 100001},
            ],
        )

        result = sl.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy segment-list sl1", output)
        self.assertIn("segment 1", output)
        self.assertIn("type MPLS_LABEL", output)
        self.assertIn("mpls-label 100000", output)
        self.assertIn("segment 2", output)
        self.assertIn("mpls-label 100001", output)

    def test_segment_list_srv6_and_validate(self):
        sl = self._make_sl(
            "sl2",
            segments=[
                {
                    "index": 1,
                    "type": "SRV6_SID",
                    "srv6_sid": "2001:db8::1",
                    "validate": True,
                },
            ],
        )

        result = sl.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn("segment 1", output)
        self.assertIn("type SRV6_SID", output)
        self.assertIn("srv6-sid 2001:db8::1", output)
        self.assertIn("validate true", output)

    def test_segment_list_validate_false(self):
        sl = self._make_sl(
            "sl3",
            segments=[{"index": 1, "validate": False}],
        )

        result = sl.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn("validate false", output)

    def test_segment_list_skips_segment_without_index(self):
        sl = self._make_sl(
            "sl4",
            segments=[{"type": "MPLS_LABEL", "mpls_label": 100000}],
        )

        result = sl.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertNotIn("segment 1", output)

    def test_segment_list_no_segments_empty_config(self):
        sl = self._make_sl("sl5")

        result = sl.build_config(apply=False, ni_prefix=_NI)
        self.assertEqual(str(result.cli_config), "")

    def test_segment_list_unconfig(self):
        sl = self._make_sl(
            "sl1",
            segments=[{"index": 1, "type": "MPLS_LABEL", "mpls_label": 100000}],
        )

        result = sl.build_unconfig(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy segment-list sl1", output)
        self.assertIn("no type MPLS_LABEL", output)
        self.assertIn("no mpls-label 100000", output)

    def test_segment_list_build_config_unconfig_true(self):
        sl = self._make_sl(
            "sl1",
            segments=[{"index": 1, "type": "MPLS_LABEL", "mpls_label": 100000}],
        )

        result = sl.build_config(apply=False, unconfig=True, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy segment-list sl1", output)
        self.assertIn("no mpls-label 100000", output)


class TestSrPolicyDynamicPolicyColorAttributes(TestCase):
    """Unit tests for
    SrPolicy.DeviceAttributes.DynamicPolicyColorAttributes
    build_config()/build_unconfig()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_dpc(self, color, **attrs):
        dpc = SrPolicy.DeviceAttributes.DynamicPolicyColorAttributes()
        dpc.device = self.device
        dpc.color_id = color
        for key, value in attrs.items():
            setattr(dpc, key, value)
        return dpc

    def test_dynamic_color(self):
        dpc = self._make_dpc(100, sid_algorithm=128)

        result = dpc.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy dynamic-policy-color 100", output)
        self.assertIn(
            "dynamic constraints segment-rules sid-algorithm 128", output
        )

    def test_dynamic_color_no_algorithm_empty_config(self):
        dpc = self._make_dpc(100)

        result = dpc.build_config(apply=False, ni_prefix=_NI)
        self.assertEqual(str(result.cli_config), "")

    def test_dynamic_color_unconfig(self):
        dpc = self._make_dpc(100, sid_algorithm=128)

        result = dpc.build_unconfig(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy dynamic-policy-color 100", output)
        self.assertIn(
            "no dynamic constraints segment-rules sid-algorithm 128", output
        )


class TestSrPolicyPolicyAttributes(TestCase):
    """Unit tests for SrPolicy.DeviceAttributes.PolicyAttributes
    build_config()/build_unconfig()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_policy(self, policy_key, **attrs):
        pol = SrPolicy.DeviceAttributes.PolicyAttributes()
        pol.device = self.device
        pol.policy_key = policy_key
        for key, value in attrs.items():
            setattr(pol, key, value)
        return pol

    def test_policy_basic(self):
        pol = self._make_policy(
            "2.2.2.2 100",
            policy_name="test-pol",
            enabled=True,
            priority=10,
        )

        result = pol.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy policy 2.2.2.2 100", output)
        self.assertIn("name test-pol", output)
        self.assertIn("enabled true", output)
        self.assertIn("priority 10", output)

    def test_policy_description_and_disabled(self):
        pol = self._make_policy(
            "2.2.2.2 100",
            description="test policy",
            enabled=False,
        )

        result = pol.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn('description "test policy"', output)
        self.assertIn("enabled false", output)

    def test_policy_with_explicit_candidate_path(self):
        pol = self._make_policy(
            "2.2.2.2 100",
            candidate_paths=[{
                "discriminator": 10,
                "preference": 200,
                "name": "cp1",
                "description": "primary path",
                "type": "EXPLICIT_SEGMENT_LIST",
                "explicit_segment_list": "sl1",
            }],
        )

        result = pol.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn("candidate-path 10", output)
        self.assertIn("preference 200", output)
        self.assertIn("name cp1", output)
        self.assertIn('description "primary path"', output)
        self.assertIn("type EXPLICIT_SEGMENT_LIST", output)
        self.assertIn("explicit segment-list sl1", output)

    def test_policy_with_dynamic_candidate_path(self):
        pol = self._make_policy(
            "3.3.3.3 200",
            candidate_paths=[{
                "discriminator": 20,
                "type": "DYNAMIC",
                "dynamic_dataplane": "MPLS",
                "dynamic_sid_algorithm": 128,
                "dynamic_metric_type": "TE",
                "dynamic_affinities": {
                    "include_any": ["red", "blue"],
                    "exclude_any": ["green"],
                },
                "dynamic_upper_bounds": {
                    "cumulative_metric": 100,
                    "max_hops": 5,
                    "max_segments": 8,
                },
            }],
        )

        result = pol.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn("candidate-path 20", output)
        self.assertIn("dynamic dataplane MPLS", output)
        self.assertIn(
            "dynamic constraints segment-rules sid-algorithm 128", output
        )
        self.assertIn(
            "dynamic constraints path-calculation metric-type TE", output
        )
        self.assertIn(
            "dynamic constraints affinities include-any [ red blue ]", output
        )
        self.assertIn(
            "dynamic constraints affinities exclude-any [ green ]", output
        )
        self.assertIn(
            "dynamic constraints upper-bounds cumulative-metric "
            "PATH_CALCULATION_METRIC",
            output,
        )
        self.assertIn("metric 100", output)
        self.assertIn(
            "dynamic constraints upper-bounds maximum-hop-count 5", output
        )
        self.assertIn(
            "dynamic constraints upper-bounds maximum-segments 8", output
        )

    def test_policy_skips_candidate_path_without_discriminator(self):
        pol = self._make_policy(
            "2.2.2.2 100",
            candidate_paths=[{"preference": 100}],
        )

        result = pol.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertNotIn("candidate-path", output)

    def test_policy_no_attributes_still_emits_policy_block(self):
        pol = self._make_policy("2.2.2.2 100")

        result = pol.build_config(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy policy 2.2.2.2 100", output)
        self.assertNotIn("name ", output)
        self.assertNotIn("enabled", output)

    def test_policy_unconfig(self):
        pol = self._make_policy(
            "2.2.2.2 100",
            policy_name="test-pol",
            enabled=True,
        )

        result = pol.build_unconfig(apply=False, ni_prefix=_NI)
        output = str(result.cli_config)

        self.assertIn(f"{_NI} sr-policy policy 2.2.2.2 100", output)
        self.assertIn("no name test-pol", output)
        self.assertIn("no enabled true", output)


class TestSrPolicyDeviceAttributes(TestCase):
    """Unit tests for SrPolicy.DeviceAttributes.build_config()/
    build_unconfig() (device-level dispatch to segment-list, dynamic
    policy color, and policy children via mapping_values)."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test-device"

    def _make_sl(self, name, **attrs):
        sl = SrPolicy.DeviceAttributes.SegmentListAttributes()
        sl.device = self.device
        sl.segment_list_name = name
        for key, value in attrs.items():
            setattr(sl, key, value)
        return sl

    def _make_dpc(self, color, **attrs):
        dpc = SrPolicy.DeviceAttributes.DynamicPolicyColorAttributes()
        dpc.device = self.device
        dpc.color_id = color
        for key, value in attrs.items():
            setattr(dpc, key, value)
        return dpc

    def _make_policy(self, policy_key, **attrs):
        pol = SrPolicy.DeviceAttributes.PolicyAttributes()
        pol.device = self.device
        pol.policy_key = policy_key
        for key, value in attrs.items():
            setattr(pol, key, value)
        return pol

    def test_device_build_config_delegates_to_all_children(self):
        dev_attr = SrPolicy.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.segment_list_attr = {
            "sl1": self._make_sl(
                "sl1",
                segments=[{"index": 1, "type": "MPLS_LABEL", "mpls_label": 100000}],
            ),
        }
        dev_attr.dynamic_color_attr = {
            "100": self._make_dpc(100, sid_algorithm=128),
        }
        dev_attr.policy_attr = {
            "2.2.2.2 100": self._make_policy(
                "2.2.2.2 100", policy_name="test-pol", enabled=True
            ),
        }

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("sr-policy segment-list sl1", output)
        self.assertIn("sr-policy dynamic-policy-color 100", output)
        self.assertIn("sr-policy policy 2.2.2.2 100", output)
        self.assertIn("name test-pol", output)

    def test_device_build_config_empty_attrs(self):
        dev_attr = SrPolicy.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.segment_list_attr = {}
        dev_attr.dynamic_color_attr = {}
        dev_attr.policy_attr = {}

        result = dev_attr.build_config(apply=False)
        self.assertEqual(str(result.cli_config), "")

    def test_device_build_config_apply_true_calls_device_configure(self):
        dev_attr = SrPolicy.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.segment_list_attr = {}
        dev_attr.dynamic_color_attr = {}
        dev_attr.policy_attr = {
            "2.2.2.2 100": self._make_policy("2.2.2.2 100", enabled=True),
        }

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("sr-policy policy 2.2.2.2 100", args[0])
        self.assertTrue(kwargs.get("fail_invalid"))

    def test_device_build_unconfig_delegates(self):
        dev_attr = SrPolicy.DeviceAttributes()
        dev_attr.device = self.device
        dev_attr.segment_list_attr = {}
        dev_attr.dynamic_color_attr = {}
        dev_attr.policy_attr = {
            "2.2.2.2 100": self._make_policy("2.2.2.2 100", enabled=True),
        }

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("sr-policy policy 2.2.2.2 100", output)
        self.assertIn("no enabled true", output)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
