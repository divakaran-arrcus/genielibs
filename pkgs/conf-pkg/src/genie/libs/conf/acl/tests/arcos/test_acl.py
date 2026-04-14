"""Unit tests for ArcOS ACL configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.acl.arcos.acl import Acl


class TestAcl(TestCase):
    """Unit tests for Acl AclSetAttributes configuration object."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = "test-device"
        self.device.custom = {"instance_name": "default"}

    def _build(self, acl_set_key, description=None, acl_entries=None):
        """Helper: create an AclSetAttributes, set fields, return CLI string."""
        attr = Acl.DeviceAttributes.AclSetAttributes()
        attr.device = self.device
        attr.acl_set_key = acl_set_key
        if description is not None:
            attr.description = description
        if acl_entries is not None:
            attr.acl_entries = acl_entries
        result = attr.build_config(apply=False)
        return str(result.cli_config)

    # ------------------------------------------------------------------
    # 1. Basic IPv4 ACL: description + one ACE with source + ACCEPT
    # ------------------------------------------------------------------
    def test_acl_ipv4_basic(self):
        """Test ACL set with description and one basic IPv4 ACE."""
        output = self._build(
            acl_set_key="test-acl ACL_IPV4",
            description="basic ipv4 filter",
            acl_entries={
                10: {
                    "ipv4_source_address": "10.0.0.0/8",
                    "forwarding_action": "ACCEPT",
                },
            },
        )

        self.assertIn("acl acl-set test-acl ACL_IPV4", output)
        self.assertIn("description basic ipv4 filter", output)
        self.assertIn("acl-entry 10", output)
        self.assertIn("ipv4 source-address 10.0.0.0/8", output)
        self.assertIn("actions forwarding-action ACCEPT", output)

    # ------------------------------------------------------------------
    # 2. Full IPv4 ACE: source, dest, protocol, transport ports, log
    # ------------------------------------------------------------------
    def test_acl_ipv4_full(self):
        """Test ACL entry with all IPv4 and transport fields."""
        output = self._build(
            acl_set_key="full-acl ACL_IPV4",
            acl_entries={
                100: {
                    "description": "permit web traffic",
                    "ipv4_source_address": "192.168.1.0/24",
                    "ipv4_destination_address": "10.10.0.0/16",
                    "ipv4_protocol": "TCP",
                    "transport_source_port": 12345,
                    "transport_destination_port": 443,
                    "forwarding_action": "ACCEPT",
                    "log_action": "LOG_SYSLOG",
                },
            },
        )

        self.assertIn("acl acl-set full-acl ACL_IPV4", output)
        self.assertIn("acl-entry 100", output)
        self.assertIn("description permit web traffic", output)
        self.assertIn("ipv4 source-address 192.168.1.0/24", output)
        self.assertIn("ipv4 destination-address 10.10.0.0/16", output)
        self.assertIn("ipv4 protocol TCP", output)
        self.assertIn("transport source-port 12345", output)
        self.assertIn("transport destination-port 443", output)
        self.assertIn("actions forwarding-action ACCEPT", output)
        self.assertIn("actions log-action LOG_SYSLOG", output)

    # ------------------------------------------------------------------
    # 3. IPv6 ACE
    # ------------------------------------------------------------------
    def test_acl_ipv6(self):
        """Test ACL entry with IPv6 source and destination."""
        output = self._build(
            acl_set_key="v6-filter ACL_IPV6",
            acl_entries={
                10: {
                    "ipv6_source_address": "2001:db8::/32",
                    "ipv6_destination_address": "2001:db8:1::/48",
                    "forwarding_action": "DROP",
                },
            },
        )

        self.assertIn("acl acl-set v6-filter ACL_IPV6", output)
        self.assertIn("acl-entry 10", output)
        self.assertIn("ipv6 source-address 2001:db8::/32", output)
        self.assertIn("ipv6 destination-address 2001:db8:1::/48", output)
        self.assertIn("actions forwarding-action DROP", output)
        # Ensure no IPv4 lines leaked
        self.assertNotIn("ipv4 source-address", output)
        self.assertNotIn("ipv4 destination-address", output)

    # ------------------------------------------------------------------
    # 4. L2 ACE with source-mac
    # ------------------------------------------------------------------
    def test_acl_l2(self):
        """Test ACL entry with L2 source-mac match."""
        output = self._build(
            acl_set_key="mac-filter ACL_L2",
            acl_entries={
                5: {
                    "l2_source_mac": "aa:bb:cc:dd:ee:ff",
                    "forwarding_action": "DROP",
                },
            },
        )

        self.assertIn("acl acl-set mac-filter ACL_L2", output)
        self.assertIn("acl-entry 5", output)
        self.assertIn("l2 source-mac aa:bb:cc:dd:ee:ff", output)
        self.assertIn("actions forwarding-action DROP", output)

    # ------------------------------------------------------------------
    # 5. REDIRECT action with redirect_next_hop
    # ------------------------------------------------------------------
    def test_acl_redirect(self):
        """Test ACL entry with REDIRECT action and next-hop."""
        output = self._build(
            acl_set_key="redir-acl ACL_IPV4",
            acl_entries={
                20: {
                    "ipv4_source_address": "172.16.0.0/12",
                    "forwarding_action": "REDIRECT",
                    "redirect_next_hop": "10.0.0.1",
                    "redirect_network_instance": "vrf-red",
                },
            },
        )

        self.assertIn("acl acl-set redir-acl ACL_IPV4", output)
        self.assertIn("acl-entry 20", output)
        self.assertIn("ipv4 source-address 172.16.0.0/12", output)
        self.assertIn("actions forwarding-action REDIRECT", output)
        self.assertIn("actions ipv4-redirect next-hop 10.0.0.1", output)
        self.assertIn("actions ipv4-redirect network-instance vrf-red", output)

    # ------------------------------------------------------------------
    # 6. Multiple ACEs: verify both rendered and sorted by seq ID
    # ------------------------------------------------------------------
    def test_acl_multiple_entries(self):
        """Test ACL set with multiple entries are rendered in seq order."""
        output = self._build(
            acl_set_key="multi-acl ACL_IPV4",
            description="multi-entry acl",
            acl_entries={
                30: {
                    "ipv4_source_address": "10.30.0.0/16",
                    "forwarding_action": "DROP",
                },
                10: {
                    "ipv4_source_address": "10.10.0.0/16",
                    "forwarding_action": "ACCEPT",
                },
            },
        )

        self.assertIn("acl acl-set multi-acl ACL_IPV4", output)
        self.assertIn("description multi-entry acl", output)

        # Both entries present
        self.assertIn("acl-entry 10", output)
        self.assertIn("ipv4 source-address 10.10.0.0/16", output)
        self.assertIn("acl-entry 30", output)
        self.assertIn("ipv4 source-address 10.30.0.0/16", output)

        # Verify ordering: seq 10 appears before seq 30
        pos_10 = output.index("acl-entry 10")
        pos_30 = output.index("acl-entry 30")
        self.assertLess(pos_10, pos_30,
                        "ACE seq 10 should appear before seq 30")


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
