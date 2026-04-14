"""Unit tests for ArcOS Segment Routing (SRv6 / SR-MPLS) configuration object."""

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
                    "usage": "SRGB",
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
                    "usage": "SRGB",
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


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
