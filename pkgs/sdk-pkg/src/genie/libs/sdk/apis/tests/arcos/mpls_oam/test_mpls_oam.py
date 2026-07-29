#!/usr/bin/env python3
"""Unit tests for arcOS MPLS OAM (LSP ping/traceroute) APIs (full coverage).

mpls_lsp_ping / mpls_lsp_traceroute are operational exec-action helpers
(not configure_*/unconfigure_* named) that build a CLI command string
and call device.execute(cmd, timeout=...), returning the output verbatim.
Both swallow any exception raised by device.execute and return str(exc)
instead of raising -- so the "failure path" for each is asserted as a
returned string, not a raised exception.

Since these functions don't follow the configure_/unconfigure_ naming
convention, the machine-checked coverage test below scans the module for
all public top-level callables and asserts each is referenced by name in
this file's own source, rather than filtering by name prefix.
"""

import inspect
import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.mpls_oam import configure as mpls_oam_configure
from genie.libs.sdk.apis.arcos.mpls_oam.configure import (
    mpls_lsp_ping,
    mpls_lsp_traceroute,
)


class _DummyDevice:
    def __init__(self, output=None, raise_exc=None):
        self.name = "rtr1"
        self._output = output
        self._raise = raise_exc
        self.execute = Mock(side_effect=self._execute)

    def _execute(self, cmd, timeout=None):
        if self._raise is not None:
            raise self._raise
        return self._output


class TestMplsLspPing(unittest.TestCase):
    def test_basic_command_and_return_value(self):
        device = _DummyDevice(output="!!!!! 5 packets sent, 5 received")
        result = mpls_lsp_ping(device, "2.2.2.2/32")

        device.execute.assert_called_once_with(
            "ping mpls 2.2.2.2/32 fec-type ldp -c 5 -t 2", timeout=5 * 2 + 30
        )
        self.assertEqual(result, "!!!!! 5 packets sent, 5 received")

    def test_fec_type_count_timeout_variants(self):
        device = _DummyDevice(output="ok")
        mpls_lsp_ping(
            device, "3.3.3.3/32", fec_type="bgp", count=3, timeout=1
        )
        device.execute.assert_called_once_with(
            "ping mpls 3.3.3.3/32 fec-type bgp -c 3 -t 1", timeout=3 * 1 + 30
        )

    def test_optional_src_ip_ttl_size_verbose(self):
        device = _DummyDevice(output="ok")
        mpls_lsp_ping(
            device,
            "2.2.2.2/32",
            fec_type="sr-isis",
            count=2,
            timeout=1,
            src_ip="10.0.0.1",
            ttl=64,
            size=100,
            verbose=True,
        )
        cmd = device.execute.call_args[0][0]
        self.assertEqual(
            cmd,
            "ping mpls 2.2.2.2/32 fec-type sr-isis -c 2 -t 1 "
            "-S 10.0.0.1 -T 64 -s 100 -v",
        )

    def test_ttl_zero_is_included(self):
        # ttl=0 must still be appended (explicit `is not None` check).
        device = _DummyDevice(output="ok")
        mpls_lsp_ping(device, "2.2.2.2/32", ttl=0)
        cmd = device.execute.call_args[0][0]
        self.assertIn("-T 0", cmd)

    def test_execute_failure_returns_str_exc(self):
        device = _DummyDevice(raise_exc=RuntimeError("connection lost"))
        result = mpls_lsp_ping(device, "2.2.2.2/32")
        self.assertEqual(result, "connection lost")


class TestMplsLspTraceroute(unittest.TestCase):
    def test_basic_command_and_return_value(self):
        device = _DummyDevice(output="1 10.0.0.1 1 ms")
        result = mpls_lsp_traceroute(device, "2.2.2.2/32")

        device.execute.assert_called_once_with(
            "traceroute mpls 2.2.2.2/32 fec-type ldp -T 30 -t 2",
            timeout=30 * 2 + 30,
        )
        self.assertEqual(result, "1 10.0.0.1 1 ms")

    def test_fec_type_max_ttl_timeout_variants(self):
        device = _DummyDevice(output="ok")
        mpls_lsp_traceroute(
            device, "3.3.3.3/32", fec_type="generic", max_ttl=10, timeout=1
        )
        device.execute.assert_called_once_with(
            "traceroute mpls 3.3.3.3/32 fec-type generic -T 10 -t 1",
            timeout=10 * 1 + 30,
        )

    def test_optional_src_ip_verbose(self):
        device = _DummyDevice(output="ok")
        mpls_lsp_traceroute(
            device,
            "2.2.2.2/32",
            fec_type="bgp",
            max_ttl=5,
            timeout=1,
            src_ip="10.0.0.1",
            verbose=True,
        )
        cmd = device.execute.call_args[0][0]
        self.assertEqual(
            cmd,
            "traceroute mpls 2.2.2.2/32 fec-type bgp -T 5 -t 1 "
            "-S 10.0.0.1 -v",
        )

    def test_execute_failure_returns_str_exc(self):
        device = _DummyDevice(raise_exc=RuntimeError("connection lost"))
        result = mpls_lsp_traceroute(device, "2.2.2.2/32")
        self.assertEqual(result, "connection lost")


class TestMplsOamCoverage(unittest.TestCase):
    """Machine-checked coverage: every public top-level callable in
    mpls_oam/configure.py must be referenced by name somewhere in this
    test file's source. These helpers are exec-action functions (not
    configure_*/unconfigure_* named), so a name-prefix scan is not used --
    instead every public function defined in the module is required.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(mpls_oam_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == mpls_oam_configure.__name__
            and not name.startswith("_")
        ]

        self.assertEqual(
            sorted(names), ["mpls_lsp_ping", "mpls_lsp_traceroute"]
        )

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered mpls_oam functions: {missing}")

        print(
            f"\nMPLS OAM coverage: {len(names)} public functions "
            f"({', '.join(sorted(names))}), 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
