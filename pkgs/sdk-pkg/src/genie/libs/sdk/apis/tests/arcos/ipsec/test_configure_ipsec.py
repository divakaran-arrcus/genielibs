#!/usr/bin/env python3
"""Unit tests for arcOS IPsec configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under the `ipsec-ike` context
(pad entry, conn-entry, or conn-entry/spd sub-context) and calls
device.configure(list). Tests mock device.configure and assert the emitted
CLI. A machine coverage check
(TestIpsecConfigureCoverage.test_zzz_all_functions_covered) asserts that
every public configure_*/unconfigure_* function in the module was exercised
by some test in this file.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.ipsec.configure as configure_module
from genie.libs.sdk.apis.arcos.ipsec.configure import (
    configure_ipsec_pad_entry,
    unconfigure_ipsec_pad_entry,
    configure_ipsec_conn_entry,
    unconfigure_ipsec_conn_entry,
    configure_ipsec_spd_entry,
    unconfigure_ipsec_spd_entry,
)

# ---------------------------------------------------------------------------
# Machine coverage tracking: wrap each imported function so calling it during
# a test records its name. The final test asserts every public function in
# the module was called at least once.
# ---------------------------------------------------------------------------
_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


configure_ipsec_pad_entry = _track(
    "configure_ipsec_pad_entry", configure_ipsec_pad_entry
)
unconfigure_ipsec_pad_entry = _track(
    "unconfigure_ipsec_pad_entry", unconfigure_ipsec_pad_entry
)
configure_ipsec_conn_entry = _track(
    "configure_ipsec_conn_entry", configure_ipsec_conn_entry
)
unconfigure_ipsec_conn_entry = _track(
    "unconfigure_ipsec_conn_entry", unconfigure_ipsec_conn_entry
)
configure_ipsec_spd_entry = _track(
    "configure_ipsec_spd_entry", configure_ipsec_spd_entry
)
unconfigure_ipsec_spd_entry = _track(
    "unconfigure_ipsec_spd_entry", unconfigure_ipsec_spd_entry
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureIpsecPadEntry(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_ipsec_pad_entry_local(self):
        configure_ipsec_pad_entry(self.d, "local", "10.0.0.1", "s3cr3t")
        c = self.d.cfg()
        self.assertIn("ipsec-ike pad pad-entry local", c)
        self.assertIn("ipv4-address 10.0.0.1", c)
        self.assertIn("peer-authentication pre-shared secret s3cr3t", c)

    def test_configure_ipsec_pad_entry_remote(self):
        configure_ipsec_pad_entry(self.d, "remote", "10.0.0.2", "s3cr3t2")
        c = self.d.cfg()
        self.assertIn("ipsec-ike pad pad-entry remote", c)
        self.assertIn("ipv4-address 10.0.0.2", c)

    def test_unconfigure_ipsec_pad_entry(self):
        unconfigure_ipsec_pad_entry(self.d, "local")
        self.assertIn("no ipsec-ike pad pad-entry local", self.d.cfg())


class TestConfigureIpsecConnEntry(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_ipsec_conn_entry_defaults(self):
        configure_ipsec_conn_entry(self.d, "vpn1")
        c = self.d.cfg()
        self.assertIn("ipsec-ike conn-entry vpn1", c)
        self.assertIn("autostartup start", c)
        self.assertIn("version ikev2", c)
        self.assertNotIn("authalg", c)
        self.assertNotIn("encalg", c)
        self.assertNotIn("dh-group", c)

    def test_configure_ipsec_conn_entry_all_options(self):
        configure_ipsec_conn_entry(
            self.d, "vpn1", version="ikev1", autostartup="start",
            authalg="sha1", encalg="aes128", dh_group=14, rekey_time=3600,
        )
        c = self.d.cfg()
        self.assertIn("ipsec-ike conn-entry vpn1", c)
        self.assertIn("version ikev1", c)
        self.assertIn("ike-sa-lifetime-soft rekey-time 3600", c)
        self.assertIn("authalg [ sha1 ]", c)
        self.assertIn("encalg [ aes128 ]", c)
        self.assertIn("dh-group 14", c)

    def test_unconfigure_ipsec_conn_entry(self):
        unconfigure_ipsec_conn_entry(self.d, "vpn1")
        self.assertIn("no ipsec-ike conn-entry vpn1", self.d.cfg())


class TestConfigureIpsecSpdEntry(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_ipsec_spd_entry_list_subnets(self):
        configure_ipsec_spd_entry(
            self.d, "vpn1", "spd1",
            local_subnets=["10.0.1.0/24"], remote_subnets=["10.0.2.0/24"],
            tunnel_local="1.1.1.1", tunnel_remote="2.2.2.2", spd_mark=10,
        )
        c = self.d.cfg()
        self.assertIn("ipsec-ike conn-entry vpn1 spd spd-entry spd1", c)
        self.assertIn("traffic-selector local-subnets [ 10.0.1.0/24 ]", c)
        self.assertIn("traffic-selector remote-subnets [ 10.0.2.0/24 ]", c)
        self.assertIn("processing-info action protect", c)
        self.assertIn("ipsec-sa-cfg mode tunnel", c)
        self.assertIn("ipsec-sa-cfg tunnel local 1.1.1.1", c)
        self.assertIn("ipsec-sa-cfg tunnel remote 2.2.2.2", c)
        self.assertIn("spd-mark mark 10", c)

    def test_configure_ipsec_spd_entry_string_subnets(self):
        configure_ipsec_spd_entry(
            self.d, "vpn1", "spd2",
            local_subnets="10.0.3.0/24", remote_subnets="10.0.4.0/24",
        )
        c = self.d.cfg()
        self.assertIn("traffic-selector local-subnets [ 10.0.3.0/24 ]", c)
        self.assertIn("traffic-selector remote-subnets [ 10.0.4.0/24 ]", c)
        self.assertNotIn("tunnel local", c)
        self.assertNotIn("spd-mark", c)

    def test_unconfigure_ipsec_spd_entry(self):
        unconfigure_ipsec_spd_entry(self.d, "vpn1", "spd1")
        c = self.d.cfg()
        self.assertIn("ipsec-ike conn-entry vpn1", c)
        self.assertIn("no spd spd-entry spd1", c)


class TestConfigureIpsecFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_ipsec_pad_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_ipsec_pad_entry(self.d, "local", "10.0.0.1", "s3cr3t")

    def test_unconfigure_ipsec_pad_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_ipsec_pad_entry(self.d, "local")

    def test_configure_ipsec_conn_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_ipsec_conn_entry(self.d, "vpn1")

    def test_unconfigure_ipsec_conn_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_ipsec_conn_entry(self.d, "vpn1")

    def test_configure_ipsec_spd_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_ipsec_spd_entry(
                self.d, "vpn1", "spd1",
                local_subnets=["10.0.1.0/24"], remote_subnets=["10.0.2.0/24"],
            )

    def test_unconfigure_ipsec_spd_entry_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_ipsec_spd_entry(self.d, "vpn1", "spd1")


class TestIpsecConfigureCoverage(unittest.TestCase):
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in configure.py
        must have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(configure_module, inspect.isfunction)
            if obj.__module__ == configure_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in ipsec/configure.py: {sorted(missing)}",
        )

        configure_count = sum(1 for n in public_fns if n.startswith("configure_"))
        unconfigure_count = sum(1 for n in public_fns if n.startswith("unconfigure_"))
        print(
            f"\nIPsec configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(public_fns)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
