from unittest import TestCase
from unittest.mock import Mock
from genie.libs.sdk.apis.arcos.isis.configure import (
    configure_isis_srv6, unconfigure_isis_srv6,
    configure_isis_srv6_locator, unconfigure_isis_srv6_locator,
)


class TestConfigureIsisSrv6(TestCase):
    def setUp(self):
        self.dev = Mock()
        self.dev.configure = Mock()

    def test_enable(self):
        configure_isis_srv6(self.dev, enabled=True)
        cfg = self.dev.configure.call_args[0][0]
        joined = "\n".join(cfg) if isinstance(cfg, (list, tuple)) else cfg
        self.assertIn('network-instance default protocol ISIS default', joined)
        self.assertIn('global srv6 enabled true', joined)

    def test_disable(self):
        configure_isis_srv6(self.dev, enabled=False)
        cfg = self.dev.configure.call_args[0][0]
        joined = "\n".join(cfg) if isinstance(cfg, (list, tuple)) else cfg
        self.assertIn('global srv6 enabled false', joined)

    def test_unconfigure(self):
        unconfigure_isis_srv6(self.dev)
        cfg = self.dev.configure.call_args[0][0]
        joined = "\n".join(cfg) if isinstance(cfg, (list, tuple)) else cfg
        self.assertIn('global srv6 enabled false', joined)

    def test_custom_instance(self):
        configure_isis_srv6(self.dev, network_instance='vrf1', protocol_instance='1')
        cfg = self.dev.configure.call_args[0][0]
        joined = "\n".join(cfg) if isinstance(cfg, (list, tuple)) else cfg
        self.assertIn('network-instance vrf1 protocol ISIS 1', joined)

    def test_bind_locator(self):
        configure_isis_srv6_locator(self.dev, locator='LOC_R1_ALG128')
        cfg = self.dev.configure.call_args[0][0]
        joined = "\n".join(cfg) if isinstance(cfg, (list, tuple)) else cfg
        self.assertIn('network-instance default protocol ISIS default', joined)
        self.assertIn('global srv6 locator LOC_R1_ALG128', joined)

    def test_unbind_locator(self):
        unconfigure_isis_srv6_locator(self.dev, locator='LOC_R1_ALG128')
        cfg = self.dev.configure.call_args[0][0]
        joined = "\n".join(cfg) if isinstance(cfg, (list, tuple)) else cfg
        self.assertIn('no global srv6 locator LOC_R1_ALG128', joined)
