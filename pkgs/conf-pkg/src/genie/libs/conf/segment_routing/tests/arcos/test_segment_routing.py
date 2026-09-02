"""Unit tests for ArcOS Segment Routing (SRv6 / SR-MPLS) configuration object."""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.segment_routing.arcos.segment_routing import SegmentRouting


class TestSegmentRoutingDeviceAttributes(TestCase):
    """Unit tests for SegmentRouting.DeviceAttributes build_config()."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        # build_config uses device.custom as a real dict (calls .get())
        self.device.custom = {"instance_name": "default"}

    def _make_dev_attr(self, **attrs):
        """Helper: create a DeviceAttributes instance with given attributes."""
        dev_attr = SegmentRouting.DeviceAttributes()
        dev_attr.device = self.device
        for key, value in attrs.items():
            setattr(dev_attr, key, value)
        return dev_attr

    # ------------------------------------------------------------------ #
    # 1. SRv6 encapsulation source address only
    # ------------------------------------------------------------------ #

    def test_sr_srv6_encap_source(self):
        """Test SRv6 encapsulation source-address CLI generation."""
        dev_attr = self._make_dev_attr(
            srv6_encap_source_address="2001:db8::1",
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("srv6 encapsulation source-address 2001:db8::1", output)

    # ------------------------------------------------------------------ #
    # 2. SRv6 locator with prefix and node_length
    # ------------------------------------------------------------------ #

    def test_sr_srv6_locator(self):
        """Test SRv6 locator generates prefix and locator-node-length."""
        dev_attr = self._make_dev_attr(
            srv6_locators={
                "loc1": {
                    "prefix": "2001:db8:aaaa::/48",
                    "locator_node_length": 24,
                    "function_length": 16,
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("srv6 locator loc1", output)
        self.assertIn("prefix 2001:db8:aaaa::/48", output)
        self.assertIn("locator-node-length 24", output)
        self.assertIn("function-length 16", output)

    # ------------------------------------------------------------------ #
    # 3. SRv6 locator with algorithm
    # ------------------------------------------------------------------ #

    def test_sr_srv6_locator_with_algorithm(self):
        """Test SRv6 locator with optional algorithm parameter."""
        dev_attr = self._make_dev_attr(
            srv6_locators={
                "loc-algo": {
                    "prefix": "2001:db8:bbbb::/48",
                    "locator_node_length": 24,
                    "function_length": 16,
                    "algorithm": 128,
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("srv6 locator loc-algo", output)
        self.assertIn("prefix 2001:db8:bbbb::/48", output)
        self.assertIn("algorithm 128", output)

    # ------------------------------------------------------------------ #
    # 4. SR-MPLS reserved label block
    # ------------------------------------------------------------------ #

    def test_sr_mpls_label_block(self):
        """Test MPLS reserved label block CLI generation."""
        dev_attr = self._make_dev_attr(
            mpls_reserved_label_blocks={
                "srgb": {
                    "lower_bound": 16000,
                    "upper_bound": 23999,
                    "usage": "ISIS_SRGB",
                    "protocol_identifier": "ISIS",
                    "protocol_name": "default",
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("mpls global reserved-label-block srgb", output)
        self.assertIn("lower-bound", output)
        self.assertIn("16000", output)
        self.assertIn("upper-bound", output)
        self.assertIn("23999", output)
        self.assertIn("SRGB", output)
        self.assertIn("protocol-identifier ISIS", output)
        self.assertIn("protocol-name", output)

    # ------------------------------------------------------------------ #
    # 5. SRMS mapping with IPv4 prefixes
    # ------------------------------------------------------------------ #

    def test_sr_srms_mapping(self):
        """Test SRMS mapping with IPv4 prefix entries."""
        dev_attr = self._make_dev_attr(
            srms_mappings={
                "map1": {
                    "local_id": "100",
                    "ipv4_prefixes": [
                        {"prefix": "10.0.0.0/24", "sid": 1000, "range": 10},
                        {"prefix": "10.0.1.0/24", "sid": 1010, "range": 5},
                    ],
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("segment-routing srms mapping map1", output)
        self.assertIn("local-id 100", output)
        self.assertIn("ipv4 prefix 10.0.0.0/24", output)
        self.assertIn("sid   1000", output)
        self.assertIn("range 10", output)
        self.assertIn("ipv4 prefix 10.0.1.0/24", output)
        self.assertIn("sid   1010", output)
        self.assertIn("range 5", output)

    # ------------------------------------------------------------------ #
    # 6. Full config: encap + locator + MPLS block together
    # ------------------------------------------------------------------ #

    def test_sr_full_config(self):
        """Test combined SRv6 encap + locator + MPLS label block."""
        dev_attr = self._make_dev_attr(
            srv6_encap_source_address="2001:db8:ffff::1",
            srv6_locators={
                "main-loc": {
                    "prefix": "2001:db8:aaaa::/48",
                    "locator_node_length": 24,
                    "function_length": 16,
                },
            },
            mpls_reserved_label_blocks={
                "srgb": {
                    "lower_bound": 16000,
                    "upper_bound": 23999,
                    "usage": "ISIS_SRGB",
                    "protocol_identifier": "ISIS",
                    "protocol_name": "default",
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        # SRv6 encap
        self.assertIn("srv6 encapsulation source-address 2001:db8:ffff::1", output)

        # SRv6 locator
        self.assertIn("srv6 locator main-loc", output)
        self.assertIn("prefix 2001:db8:aaaa::/48", output)

        # MPLS label block
        self.assertIn("mpls global reserved-label-block srgb", output)
        self.assertIn("16000", output)
        self.assertIn("23999", output)

        # All under the same network-instance
        self.assertIn("network-instance default", output)

    # ------------------------------------------------------------------ #
    # 7. Unconfig (unconfig=True / build_unconfig())
    # ------------------------------------------------------------------ #

    def test_sr_unconfig_via_build_config_unconfig_true(self):
        """Test build_config(unconfig=True) emits the single 'no
        network-instance <ni> srv6' unconfig stanza."""
        dev_attr = self._make_dev_attr(
            srv6_encap_source_address="2001:db8::1",
        )

        result = dev_attr.build_config(apply=False, unconfig=True)
        output = str(result.cli_config)

        self.assertIn("no network-instance default srv6", output)

    def test_sr_unconfig_via_build_unconfig_method(self):
        """Test build_unconfig() delegates to build_config(unconfig=True)."""
        dev_attr = self._make_dev_attr(
            srv6_encap_source_address="2001:db8::1",
        )

        result = dev_attr.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn("no network-instance default srv6", output)

    # ------------------------------------------------------------------ #
    # 8. Skip invalid locator / block / mapping entries (falsy key or
    #    None attrs)
    # ------------------------------------------------------------------ #

    def test_sr_srv6_locator_skips_invalid_entries(self):
        """Locators with a falsy name or None attrs are skipped."""
        dev_attr = self._make_dev_attr(
            srv6_locators={
                "": {"prefix": "2001:db8:dead::/48"},
                "loc-none": None,
                "loc-good": {
                    "prefix": "2001:db8:aaaa::/48",
                    "locator_node_length": 24,
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("srv6 locator loc-good", output)
        self.assertNotIn("2001:db8:dead::/48", output)

    def test_sr_mpls_label_block_skips_invalid_entries(self):
        """MPLS label blocks with a falsy id or None attrs are skipped."""
        dev_attr = self._make_dev_attr(
            mpls_reserved_label_blocks={
                "": {"lower_bound": 1, "upper_bound": 2},
                "block-none": None,
                "srgb": {
                    "lower_bound": 16000,
                    "upper_bound": 23999,
                    "usage": "ISIS_SRGB",
                    "protocol_identifier": "ISIS",
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("mpls global reserved-label-block srgb", output)
        self.assertNotIn("reserved-label-block \n", output)

    def test_sr_srms_mapping_skips_invalid_entries(self):
        """SRMS mappings with a falsy id or None attrs are skipped."""
        dev_attr = self._make_dev_attr(
            srms_mappings={
                "": {"local_id": "999"},
                "map-none": None,
                "map1": {
                    "local_id": "100",
                    "ipv4_prefixes": [
                        {"prefix": "10.0.0.0/24", "sid": 1000, "range": 10},
                    ],
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("segment-routing srms mapping map1", output)
        self.assertNotIn("999", output)

    # ------------------------------------------------------------------ #
    # 9. Attribute-style (non-dict) locator / block / mapping / prefix
    #    entries (exercise the getattr() fallback branches)
    # ------------------------------------------------------------------ #

    def test_sr_srv6_locator_object_style_attrs(self):
        """Locator attrs supplied as an attribute-style object (not a
        dict) are read via getattr()."""
        dev_attr = self._make_dev_attr(
            srv6_locators={
                "loc-obj": SimpleNamespace(
                    prefix="fcbb:bb00:9::/48",
                    locator_node_length=24,
                    function_length=16,
                    algorithm=5,
                ),
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("srv6 locator loc-obj", output)
        self.assertIn("prefix fcbb:bb00:9::/48", output)
        self.assertIn("locator-node-length 24", output)
        self.assertIn("function-length 16", output)
        self.assertIn("algorithm 5", output)

    def test_sr_mpls_label_block_object_style_attrs(self):
        """MPLS label block attrs supplied as an attribute-style object
        (not a dict) are read via getattr()."""
        dev_attr = self._make_dev_attr(
            mpls_reserved_label_blocks={
                "srgb-obj": SimpleNamespace(
                    lower_bound=16000,
                    upper_bound=23999,
                    usage="ISIS_SRGB",
                    protocol_identifier="ISIS",
                    protocol_name="default",
                ),
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("mpls global reserved-label-block srgb-obj", output)
        self.assertIn("16000", output)
        self.assertIn("23999", output)
        self.assertIn("SRGB", output)

    def test_sr_srms_mapping_object_style_attrs_with_ipv4_and_ipv6(self):
        """SRMS mapping attrs (and its ipv4/ipv6 prefix entries) supplied
        as attribute-style objects (not dicts) are read via getattr()."""
        dev_attr = self._make_dev_attr(
            srms_mappings={
                "map-obj": SimpleNamespace(
                    local_id="200",
                    ipv4_prefixes=[
                        SimpleNamespace(
                            prefix="10.1.0.0/24", sid=2000, range=50,
                        ),
                    ],
                    ipv6_prefixes=[
                        SimpleNamespace(
                            prefix="2001:db8:1::/32", sid=3000, range=50,
                        ),
                    ],
                ),
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("segment-routing srms mapping map-obj", output)
        self.assertIn("local-id 200", output)
        self.assertIn("ipv4 prefix 10.1.0.0/24", output)
        self.assertIn("sid   2000", output)
        self.assertIn("ipv6 prefix 2001:db8:1::/32", output)
        self.assertIn("sid   3000", output)

    # ------------------------------------------------------------------ #
    # 10. SRMS mapping IPv6 prefixes (dict-style) -- separate from IPv4
    # ------------------------------------------------------------------ #

    def test_sr_srms_mapping_ipv6_prefix_dict_style(self):
        """Test SRMS mapping with dict-style IPv6 prefix entries."""
        dev_attr = self._make_dev_attr(
            srms_mappings={
                "map-v6": {
                    "local_id": "300",
                    "ipv6_prefixes": [
                        {"prefix": "2001:db8:2::/32", "sid": 4000, "range": 20},
                        {"prefix": "2001:db8:3::/32", "sid": 4020, "range": 10},
                    ],
                },
            },
        )

        result = dev_attr.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("segment-routing srms mapping map-v6", output)
        self.assertIn("local-id 300", output)
        self.assertIn("ipv6 prefix 2001:db8:2::/32", output)
        self.assertIn("sid   4000", output)
        self.assertIn("range 20", output)
        self.assertIn("ipv6 prefix 2001:db8:3::/32", output)
        self.assertIn("sid   4020", output)
        self.assertIn("range 10", output)

    # ------------------------------------------------------------------ #
    # 11. apply=True dispatches to device.configure()
    # ------------------------------------------------------------------ #

    def test_sr_build_config_apply_true_calls_device_configure(self):
        """apply=True should render the config and call
        device.configure() with the rendered string."""
        dev_attr = self._make_dev_attr(
            srv6_encap_source_address="2001:db8::1",
        )

        result = dev_attr.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, _ = self.device.configure.call_args
        self.assertIn("srv6 encapsulation source-address 2001:db8::1", args[0])


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
