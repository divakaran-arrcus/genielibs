#!/usr/bin/env python3
"""Unit tests for arcOS Interface configure APIs (representative sample)."""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.interface.configure import (
    configure_interface_mtu,
    configure_interface_description,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def last_config(self):
        self.configure.assert_called()
        cfg = self.configure.call_args[0][0]
        return "\n".join(cfg) if isinstance(cfg, (list, tuple)) else str(cfg)


class TestConfigureInterface(unittest.TestCase):
    def setUp(self):
        self.device = _CfgDevice()

    def test_mtu(self):
        configure_interface_mtu(self.device, "swp1", 9000)
        cfg = self.device.last_config()
        self.assertIn("interface swp1", cfg)
        self.assertIn("mtu 9000", cfg)

    def test_description(self):
        configure_interface_description(self.device, "swp1", "Uplink to spine")
        cfg = self.device.last_config()
        self.assertIn("interface swp1", cfg)
        self.assertIn("Uplink to spine", cfg)


if __name__ == "__main__":
    unittest.main()
