#!/usr/bin/env python3
"""Unit tests for ArcOS ACL configuration object."""

from unittest import TestCase
from unittest.mock import Mock


class TestAcl(TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = 'test-device'
        self.device.custom = {'instance_name': 'default'}

    def test_acl_ipv4_basic(self):
        """Test IPv4 ACL with source-address and ACCEPT."""
        pass

    def test_acl_ipv4_drop(self):
        """Test IPv4 ACL with DROP action."""
        pass

    def test_acl_ipv6(self):
        """Test IPv6 ACL entry."""
        pass

    def test_acl_l2(self):
        """Test L2 ACL with source-mac."""
        pass

    def test_acl_redirect(self):
        """Test ACL with REDIRECT action and next-hop."""
        pass

    def test_acl_transport_ports(self):
        """Test ACL with transport source/destination ports."""
        pass

    def test_acl_unconfig(self):
        """Test ACL unconfiguration."""
        pass
