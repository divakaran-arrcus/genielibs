"""Unit tests for ArcOS ACL Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.acl.arcos.acl import Acl

MOD = "genie.libs.ops.acl.arcos.acl"

ACL_IPV4_OUTPUT = {
    "acl-sets": {
        "BLOCK-HTTP ACL_IPV4": {
            "name": "BLOCK-HTTP",
            "type": "ACL_IPV4",
            "acl-entries": {
                "10": {
                    "sequence-id": 10,
                    "ipv4-source-address": "10.0.0.0/8",
                    "ipv4-destination-address": "192.168.1.0/24",
                    "forwarding-action": "DROP",
                    "log-action": "LOG_SYSLOG",
                    "protocol": "TCP",
                    "transport-source-port": 0,
                    "transport-destination-port": 80,
                },
                "20": {
                    "sequence-id": 20,
                    "ipv4-source-address": "0.0.0.0/0",
                    "ipv4-destination-address": "0.0.0.0/0",
                    "forwarding-action": "ACCEPT",
                },
            },
        },
        "ALLOW-DNS ACL_IPV4": {
            "name": "ALLOW-DNS",
            "type": "ACL_IPV4",
            "acl-entries": {
                "10": {
                    "sequence-id": 10,
                    "ipv4-source-address": "0.0.0.0/0",
                    "ipv4-destination-address": "8.8.8.8/32",
                    "forwarding-action": "ACCEPT",
                    "protocol": "UDP",
                    "transport-destination-port": 53,
                },
            },
        },
    }
}

ACL_IPV6_OUTPUT = {
    "acl-sets": {
        "DENY-ALL-V6 ACL_IPV6": {
            "name": "DENY-ALL-V6",
            "type": "ACL_IPV6",
            "acl-entries": {
                "10": {
                    "sequence-id": 10,
                    "ipv6-source-address": "2001:db8::/32",
                    "ipv6-destination-address": "2001:db8:1::/48",
                    "forwarding-action": "DROP",
                    "protocol": "TCP",
                    "transport-source-port": 1024,
                    "transport-destination-port": 443,
                },
                "100": {
                    "sequence-id": 100,
                    "ipv6-source-address": "::/0",
                    "ipv6-destination-address": "::/0",
                    "forwarding-action": "ACCEPT",
                },
            },
        }
    }
}


class TestAclOps(unittest.TestCase):
    """Test ACL Ops model learn()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowAclSet")
    def test_learn_basic(self, mock_parser):
        """Test basic ACL learn with IPv4 ACLs."""
        mock_parser.return_value.parse.return_value = ACL_IPV4_OUTPUT

        ops = Acl(device=self.device)
        ops.learn()

        self.assertIsInstance(ops.info, dict)
        self.assertIn("acls", ops.info)
        acls = ops.info["acls"]

        # Two ACLs parsed
        self.assertIn("BLOCK-HTTP", acls)
        self.assertIn("ALLOW-DNS", acls)

        # BLOCK-HTTP ACL
        block_http = acls["BLOCK-HTTP"]
        self.assertEqual(block_http["name"], "BLOCK-HTTP")
        self.assertEqual(block_http["type"], "ACL_IPV4")
        self.assertIn("aces", block_http)

        # ACE 10 -- DROP rule
        ace10 = block_http["aces"]["10"]
        self.assertEqual(ace10["name"], "10")
        self.assertEqual(ace10["actions"]["forwarding"], "deny")

        # L3 IPv4 matches
        ipv4_match = ace10["matches"]["l3"]["ipv4"]
        self.assertEqual(ipv4_match["source_ipv4_network"], "10.0.0.0/8")
        self.assertEqual(ipv4_match["destination_ipv4_network"], "192.168.1.0/24")
        self.assertEqual(ipv4_match["protocol"], "TCP")

        # L4 transport matches
        l4_match = ace10["matches"]["l4"]["tcp"]
        self.assertEqual(l4_match["source_port"], 0)
        self.assertEqual(l4_match["destination_port"], 80)

        # ACE 20 -- ACCEPT rule
        ace20 = block_http["aces"]["20"]
        self.assertEqual(ace20["name"], "20")
        self.assertEqual(ace20["actions"]["forwarding"], "permit")

        # ALLOW-DNS ACL
        allow_dns = acls["ALLOW-DNS"]
        self.assertEqual(allow_dns["name"], "ALLOW-DNS")
        ace_dns = allow_dns["aces"]["10"]
        self.assertEqual(ace_dns["actions"]["forwarding"], "permit")
        self.assertEqual(
            ace_dns["matches"]["l4"]["udp"]["destination_port"], 53
        )

    @patch(f"{MOD}.ShowAclSet")
    def test_learn_empty(self, mock_parser):
        """Parser fails -- info should be empty dict."""
        mock_parser.return_value.parse.side_effect = Exception("No data")

        ops = Acl(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowAclSet")
    def test_learn_ipv6_acl(self, mock_parser):
        """Test IPv6 ACL learn populates l3.ipv6 matches."""
        mock_parser.return_value.parse.return_value = ACL_IPV6_OUTPUT

        ops = Acl(device=self.device)
        ops.learn()

        self.assertIn("acls", ops.info)
        acls = ops.info["acls"]
        self.assertIn("DENY-ALL-V6", acls)

        acl = acls["DENY-ALL-V6"]
        self.assertEqual(acl["name"], "DENY-ALL-V6")
        self.assertEqual(acl["type"], "ACL_IPV6")

        # ACE 10 -- IPv6 DROP with TCP
        ace10 = acl["aces"]["10"]
        self.assertEqual(ace10["name"], "10")
        self.assertEqual(ace10["actions"]["forwarding"], "deny")

        # L3 IPv6 matches
        ipv6_match = ace10["matches"]["l3"]["ipv6"]
        self.assertEqual(ipv6_match["source_ipv6_network"], "2001:db8::/32")
        self.assertEqual(ipv6_match["destination_ipv6_network"], "2001:db8:1::/48")
        self.assertEqual(ipv6_match["protocol"], "TCP")

        # L4 TCP matches
        tcp_match = ace10["matches"]["l4"]["tcp"]
        self.assertEqual(tcp_match["source_port"], 1024)
        self.assertEqual(tcp_match["destination_port"], 443)

        # ACE 100 -- ACCEPT all
        ace100 = acl["aces"]["100"]
        self.assertEqual(ace100["name"], "100")
        self.assertEqual(ace100["actions"]["forwarding"], "permit")

        # ACE 100 has IPv6 matches but no transport
        ipv6_match_100 = ace100["matches"]["l3"]["ipv6"]
        self.assertEqual(ipv6_match_100["source_ipv6_network"], "::/0")
        self.assertNotIn("l4", ace100["matches"])

    @patch(f"{MOD}.ShowAclSet")
    def test_learn_empty_acl_sets(self, mock_parser):
        """Parser returns empty acl-sets -- info should be empty dict."""
        mock_parser.return_value.parse.return_value = {"acl-sets": {}}

        ops = Acl(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})


if __name__ == "__main__":
    unittest.main()
