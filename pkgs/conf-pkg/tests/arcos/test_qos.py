#!/usr/bin/env python3
"""Unit tests for ArcOS QoS configuration object."""

from unittest import TestCase
from unittest.mock import Mock


class TestQos(TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = 'test-device'
        self.device.custom = {'instance_name': 'default'}

    def test_qos_tablemap(self):
        """Test tablemap generates expected CLI."""
        pass

    def test_qos_classifier_dscp(self):
        """Test DSCP classifier."""
        pass

    def test_qos_classifier_local_tc(self):
        """Test LOCAL_TC classifier."""
        pass

    def test_qos_policy_police(self):
        """Test policy with POLICE action."""
        pass

    def test_qos_policy_priority(self):
        """Test policy with PRIORITY action."""
        pass

    def test_qos_interface_binding(self):
        """Test interface service-policy binding."""
        pass

    def test_qos_unconfig(self):
        """Test QoS unconfiguration."""
        pass
