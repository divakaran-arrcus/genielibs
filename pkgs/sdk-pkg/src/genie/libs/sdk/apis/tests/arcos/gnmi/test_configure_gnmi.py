#!/usr/bin/env python3
"""Unit tests for arcOS gNMI (gRPC) server configure/unconfigure APIs (full
coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.gnmi.configure builds an arcOS CLI config list
under the `system grpc-server` context (global settings or a
`connections <vrf>` sub-context) and calls `device.configure(config)`.
Tests mock `device.configure` and assert on a distinctive substring of the
emitted CLI, plus the SubCommandFailure wrap path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.gnmi import configure as gnmi_configure
from genie.libs.sdk.apis.arcos.gnmi.configure import (
    configure_gnmi_server,
    unconfigure_gnmi_server,
    configure_gnmi_connection,
    unconfigure_gnmi_connection,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class _FailingDevice:
    """Device whose .configure() always raises SubCommandFailure."""

    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(side_effect=SubCommandFailure("boom"))


class TestConfigureGnmiServer(unittest.TestCase):
    """configure_gnmi_server / unconfigure_gnmi_server"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_server_default_enabled(self):
        configure_gnmi_server(self.d)
        c = self.d.cfg()
        self.assertIn("system grpc-server", c)
        self.assertIn("enable true", c)

    def test_server_disabled(self):
        configure_gnmi_server(self.d, enabled=False)
        c = self.d.cfg()
        self.assertIn("enable false", c)

    def test_server_with_tls(self):
        configure_gnmi_server(
            self.d, transport_security=True,
            cert_file="/etc/certs/gnmi.pem", key_file="/etc/certs/gnmi.key",
        )
        c = self.d.cfg()
        self.assertIn("transport-security true", c)
        self.assertIn("tls certificate-file /etc/certs/gnmi.pem", c)
        self.assertIn("tls key-file /etc/certs/gnmi.key", c)

    def test_server_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_gnmi_server(d)

    def test_unconfigure_server(self):
        unconfigure_gnmi_server(self.d)
        c = self.d.cfg()
        self.assertIn("system grpc-server", c)
        self.assertIn("enable false", c)

    def test_unconfigure_server_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_gnmi_server(d)


class TestConfigureGnmiConnection(unittest.TestCase):
    """configure_gnmi_connection / unconfigure_gnmi_connection"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_connection_all_params_list_addresses(self):
        configure_gnmi_connection(
            self.d, "default", listen_addresses=["10.0.0.1", "10.0.0.2"],
            port=57400, listen_interface="loopback0",
        )
        c = self.d.cfg()
        self.assertIn("system grpc-server connections default", c)
        self.assertIn("listen-addresses [ 10.0.0.1 10.0.0.2 ]", c)
        self.assertIn("port 57400", c)
        self.assertIn("listen-interface loopback0", c)

    def test_connection_single_address(self):
        configure_gnmi_connection(self.d, "default", listen_addresses="10.0.0.1")
        c = self.d.cfg()
        self.assertIn("listen-addresses [ 10.0.0.1 ]", c)

    def test_connection_minimal(self):
        configure_gnmi_connection(self.d, "default")
        c = self.d.cfg()
        self.assertIn("system grpc-server connections default", c)
        self.assertNotIn("listen-addresses", c)
        self.assertNotIn("port", c)
        self.assertNotIn("listen-interface", c)

    def test_connection_configure_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_gnmi_connection(d, "default")

    def test_unconfigure_connection(self):
        unconfigure_gnmi_connection(self.d, "default")
        self.assertIn(
            "no system grpc-server connections default", self.d.cfg()
        )

    def test_unconfigure_connection_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_gnmi_connection(d, "default")


class TestGnmiConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in gnmi/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(gnmi_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == gnmi_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered gNMI configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\ngNMI configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
