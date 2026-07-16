#!/usr/bin/env python3
"""Unit tests for arcOS SRv6 Mobile (MUP) configure/unconfigure APIs
(full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.srv6_mobile.configure builds an arcOS CLI
config list (starting with the `system pfcp-proxy <instance_id>`
context) and calls device.configure(config). Tests mock
device.configure and assert on a distinctive substring of the emitted
CLI.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.srv6_mobile import configure as srv6_mobile_configure
from genie.libs.sdk.apis.arcos.srv6_mobile.configure import (
    configure_pfcp_proxy,
    unconfigure_pfcp_proxy,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigurePfcpProxy(unittest.TestCase):
    """configure_pfcp_proxy"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_pfcp_proxy_all_params(self):
        configure_pfcp_proxy(
            self.d, 1, "10.0.0.1", 2,
            smf_ip="10.0.0.2", smf_port=8806,
            upf_ip="10.0.0.3", upf_port=8807,
            network_instance="mgmt", passthrough=True, enable_nat=True,
            interface="ethernet-1/1", buffer_size=65536, worker=4,
        )
        c = self.d.cfg()
        self.assertIn("system pfcp-proxy 1", c)
        self.assertIn("pfcp 10.0.0.1", c)
        self.assertIn("pid 2", c)
        self.assertIn("smf 10.0.0.2", c)
        self.assertIn("smf-port 8806", c)
        self.assertIn("upf 10.0.0.3", c)
        self.assertIn("upf-port 8807", c)
        self.assertIn("network-instance mgmt", c)
        self.assertIn("passthrough true", c)
        self.assertIn("enable-nat true", c)
        self.assertIn("interface ethernet-1/1", c)
        self.assertIn("buffer-size 65536", c)
        self.assertIn("worker 4", c)

    def test_pfcp_proxy_minimal(self):
        configure_pfcp_proxy(
            self.d, 3, "10.0.1.1", 5,
            smf_ip="10.0.1.2", smf_port=8810,
            upf_ip="10.0.1.3", upf_port=8811,
        )
        c = self.d.cfg()
        self.assertIn("system pfcp-proxy 3", c)
        self.assertIn("pfcp 10.0.1.1", c)
        self.assertIn("pid 5", c)
        self.assertIn("smf 10.0.1.2", c)
        self.assertIn("smf-port 8810", c)
        self.assertIn("upf 10.0.1.3", c)
        self.assertIn("upf-port 8811", c)
        self.assertIn("network-instance default", c)
        self.assertNotIn("passthrough", c)
        self.assertNotIn("enable-nat", c)
        self.assertNotIn("interface ethernet", c)
        self.assertNotIn("buffer-size", c)
        self.assertNotIn("worker", c)

    def test_pfcp_proxy_worker_zero(self):
        # worker=0 must still be emitted (explicit `is not None` check)
        configure_pfcp_proxy(
            self.d, 7, "10.0.2.1", 8,
            smf_ip="10.0.2.2", smf_port=8820,
            upf_ip="10.0.2.3", upf_port=8821,
            worker=0,
        )
        self.assertIn("worker 0", self.d.cfg())


class TestUnconfigurePfcpProxy(unittest.TestCase):
    """unconfigure_pfcp_proxy"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_unconfigure_pfcp_proxy(self):
        unconfigure_pfcp_proxy(self.d, 1)
        self.assertIn("no system pfcp-proxy 1", self.d.cfg())


class TestSrv6MobileConfigureSubCommandFailure(unittest.TestCase):
    """Every configure_*/unconfigure_* helper catches SubCommandFailure
    from device.configure() and re-raises a SubCommandFailure wrapping it.
    Table-driven so every function's raise path gets real coverage.
    """

    # (function, args, kwargs)
    CASES = [
        (configure_pfcp_proxy,
         (1, "10.0.0.1", 2),
         {"smf_ip": "10.0.0.2", "smf_port": 8806,
          "upf_ip": "10.0.0.3", "upf_port": 8807}),
        (unconfigure_pfcp_proxy, (1,), {}),
    ]

    def test_subcommandfailure_reraised(self):
        for func, args, kwargs in self.CASES:
            with self.subTest(func=func.__name__):
                device = _CfgDevice()
                device.configure = Mock(side_effect=SubCommandFailure("nope"))
                with self.assertRaises(SubCommandFailure):
                    func(device, *args, **kwargs)


class TestSrv6MobileConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in srv6_mobile/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(srv6_mobile_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == srv6_mobile_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Untested public functions in srv6_mobile/configure.py: "
            f"{missing}"
        )

        configure_count = sum(
            1 for n in names if n.startswith("configure_")
        )
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_")
        )
        print(
            f"\nSRv6 Mobile configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
