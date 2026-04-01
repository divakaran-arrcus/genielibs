#!/usr/bin/env python3
"""Unit tests for ArcOS LDP configuration object."""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.ldp import Ldp


class TestLdp(TestCase):
    """Unit tests for Ldp configuration object."""

    def setUp(self):
        """Set up test fixtures."""
        self.device = Mock()
        self.device.name = 'test-device'
        self.device.custom = {'instance_name': 'default'}

    def test_ldp_global_config(self):
        """Test LDP global config generates expected CLI."""
        # TODO: Create LDP object, set lsr_id, enable, php_type, etc.
        # TODO: Call build_config(apply=False)
        # TODO: Assert expected CLI lines
        pass

    def test_ldp_interface_config(self):
        """Test per-interface LDP config generates expected CLI."""
        # TODO: Create LDP object, set interface link-hello + address-family
        # TODO: Assert 'interface-attributes interface swp11' in output
        pass

    def test_ldp_targeted_config(self):
        """Test targeted hello config generates expected CLI."""
        # TODO: Set targeted_hello_accept, hello_holdtime, hello_interval
        # TODO: Assert targeted lines in output
        pass

    def test_ldp_neighbor_config(self):
        """Test per-neighbor LDP config generates expected CLI."""
        # TODO: Create neighbor '1.1.1.1 0' with auth + targeted IPV4
        # TODO: Assert neighbor submode lines in output
        pass

    def test_ldp_unconfig(self):
        """Test LDP unconfiguration generates expected CLI."""
        # TODO: Create LDP with attributes, call build_unconfig(apply=False)
        # TODO: Assert 'no' prefixed CLI lines
        pass

    def test_ldp_empty_config(self):
        """Test LDP with no attributes generates empty config."""
        # TODO: No attributes set, verify config is empty
        pass

    def test_ldp_full_sample_config(self):
        """Test full sample config matching the LDP.adoc example."""
        # TODO: Replicate the sample config from the CLI docs
        # TODO: Verify all lines present
        pass
