#!/usr/bin/env python3
"""Unit tests for ArcOS System Configuration object."""

from unittest import TestCase
from unittest.mock import Mock


class TestSystemConfig(TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = 'test-device'
        self.device.custom = {'instance_name': 'default'}

    def test_hostname(self):
        pass

    def test_ntp_servers(self):
        pass

    def test_ssh_server(self):
        pass

    def test_dns_servers(self):
        pass

    def test_aaa_server_group(self):
        pass

    def test_aaa_auth_methods(self):
        pass

    def test_unconfig(self):
        pass
