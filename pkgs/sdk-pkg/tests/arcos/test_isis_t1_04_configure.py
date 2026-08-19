"""Unit tests for ArcOS ISIS configure APIs added by missing-API batch T1-04.

Source: ``arcos_pyats_sanity/docs/config-coverage/01-isis-sr-srv6.md`` — knobs the
config-coverage audit found with no genie API. Proposal:
``orchestrator/proposals/pending/isis_api_t1_04_missing_knobs.md``.

Covers the 7 configure/unconfigure pairs:
  - configure/unconfigure_isis_timers_fast_reroute_interval
  - configure/unconfigure_isis_graceful_restart_helper_only
  - configure/unconfigure_isis_interface_mpls_ldp_sync
  - configure/unconfigure_isis_interface_ipv4_fast_reroute_ip
  - configure/unconfigure_isis_interface_ipv6_fast_reroute_ip
  - configure/unconfigure_isis_interface_csnp_enabled
  - configure/unconfigure_isis_interface_level_enabled

in ``genie.libs.sdk.apis.arcos.isis.configure``.

These tests assert the CLI list each API *emits*. That every one of those lists is
also ACCEPTED by arcOS, and that each unconfigure actually removes the leaf, was
confirmed separately on rtr1 (arcOS docker, 2026-08-17) by commit + running-config
read-back in both directions — see the proposal's verification table.

The audit's 8th knob, ``default-metric``, has no API and no test: the leaf does not
exist on this arcOS build (the ISIS context offers only global/interface/level).
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.isis.configure import (
    configure_isis_timers_fast_reroute_interval,
    unconfigure_isis_timers_fast_reroute_interval,
    configure_isis_graceful_restart_helper_only,
    unconfigure_isis_graceful_restart_helper_only,
    configure_isis_interface_mpls_ldp_sync,
    unconfigure_isis_interface_mpls_ldp_sync,
    configure_isis_interface_ipv4_fast_reroute_ip,
    unconfigure_isis_interface_ipv4_fast_reroute_ip,
    configure_isis_interface_ipv6_fast_reroute_ip,
    unconfigure_isis_interface_ipv6_fast_reroute_ip,
    configure_isis_interface_csnp_enabled,
    unconfigure_isis_interface_csnp_enabled,
    configure_isis_interface_level_enabled,
    unconfigure_isis_interface_level_enabled,
)

CTX = "network-instance default protocol ISIS default"
INTF_CTX = "network-instance default protocol ISIS default interface swp1"


class ArcosIsisConfigureTestCase(unittest.TestCase):
    """Shared mock device setup."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        """Return the config list passed to device.configure."""
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestIsisTimersFastRerouteInterval(ArcosIsisConfigureTestCase):

    def test_configure(self):
        configure_isis_timers_fast_reroute_interval(self.device, interval=100)
        self.assertEqual(
            self.emitted(),
            [CTX, "global timers fast-reroute-interval 100", "!"],
        )

    def test_unconfigure(self):
        unconfigure_isis_timers_fast_reroute_interval(self.device)
        self.assertEqual(
            self.emitted(),
            [CTX, "no global timers fast-reroute-interval", "!"],
        )

    def test_unconfigure_failure_propagates(self):
        self.device.configure.side_effect = SubCommandFailure("nope")
        with self.assertRaises(SubCommandFailure):
            unconfigure_isis_timers_fast_reroute_interval(self.device)


class TestIsisGracefulRestartHelperOnly(ArcosIsisConfigureTestCase):

    def test_configure_enabled(self):
        configure_isis_graceful_restart_helper_only(self.device, enabled=True)
        self.assertEqual(
            self.emitted(),
            [CTX, "global graceful-restart helper-only true", "!"],
        )

    def test_configure_disabled(self):
        configure_isis_graceful_restart_helper_only(self.device, enabled=False)
        self.assertEqual(
            self.emitted(),
            [CTX, "global graceful-restart helper-only false", "!"],
        )

    def test_unconfigure(self):
        unconfigure_isis_graceful_restart_helper_only(self.device)
        self.assertEqual(
            self.emitted(),
            [CTX, "no global graceful-restart helper-only", "!"],
        )


class TestIsisInterfaceMplsLdpSync(ArcosIsisConfigureTestCase):

    def test_configure_enabled(self):
        configure_isis_interface_mpls_ldp_sync(
            self.device, interface="swp1", enabled=True)
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "mpls igp-ldp-sync enabled true", "!"],
        )

    def test_configure_disabled(self):
        configure_isis_interface_mpls_ldp_sync(
            self.device, interface="swp1", enabled=False)
        self.assertIn("mpls igp-ldp-sync enabled false", self.emitted())

    def test_unconfigure(self):
        unconfigure_isis_interface_mpls_ldp_sync(self.device, interface="swp1")
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "no mpls igp-ldp-sync", "!"],
        )


class TestIsisInterfaceIpv4FastRerouteIp(ArcosIsisConfigureTestCase):

    def test_configure(self):
        configure_isis_interface_ipv4_fast_reroute_ip(
            self.device, interface="swp1", enabled=True)
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "af IPV4 UNICAST", "fast-reroute ip enabled true",
             "exit", "!"],
        )

    def test_configure_disabled(self):
        """H4: enabled=False was never exercised. Forcing a literal `true` in
        both IP-FRR functions passed all IS-IS tests, so a caller asking to
        DISABLE IP-FRR would silently have enabled it."""
        configure_isis_interface_ipv4_fast_reroute_ip(
            self.device, interface="swp1", enabled=False)
        self.assertEqual(self.emitted(), [
            INTF_CTX, "af IPV4 UNICAST", "fast-reroute ip enabled false",
            "exit", "!"])

    def test_unconfigure(self):
        unconfigure_isis_interface_ipv4_fast_reroute_ip(
            self.device, interface="swp1")
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "af IPV4 UNICAST", "no fast-reroute ip", "exit", "!"],
        )


class TestIsisInterfaceIpv6FastRerouteIp(ArcosIsisConfigureTestCase):

    def test_configure(self):
        configure_isis_interface_ipv6_fast_reroute_ip(
            self.device, interface="swp1", enabled=True)
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "af IPV6 UNICAST", "fast-reroute ip enabled true",
             "exit", "!"],
        )

    def test_unconfigure(self):
        unconfigure_isis_interface_ipv6_fast_reroute_ip(
            self.device, interface="swp1")
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "af IPV6 UNICAST", "no fast-reroute ip", "exit", "!"],
        )

    def test_configure_disabled(self):
        """H4, IPv6 half — see the IPv4 case."""
        configure_isis_interface_ipv6_fast_reroute_ip(
            self.device, interface="swp1", enabled=False)
        self.assertEqual(self.emitted(), [
            INTF_CTX, "af IPV6 UNICAST", "fast-reroute ip enabled false",
            "exit", "!"])

    def test_af_does_not_leak_between_v4_and_v6(self):
        """The v6 API must never emit the IPV4 submode."""
        configure_isis_interface_ipv6_fast_reroute_ip(
            self.device, interface="swp1")
        self.assertNotIn("af IPV4 UNICAST", self.emitted())


class TestIsisInterfaceCsnpEnabled(ArcosIsisConfigureTestCase):

    def test_configure_disabled(self):
        """The meaningful call: CSNP is on by default, so False is the real use."""
        configure_isis_interface_csnp_enabled(
            self.device, interface="swp1", enabled=False)
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "csnp enabled false", "!"],
        )

    def test_configure_enabled(self):
        configure_isis_interface_csnp_enabled(
            self.device, interface="swp1", enabled=True)
        self.assertIn("csnp enabled true", self.emitted())

    def test_unconfigure(self):
        unconfigure_isis_interface_csnp_enabled(self.device, interface="swp1")
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "no csnp enabled", "!"],
        )

    def test_does_not_emit_csnp_interval_or_authentication(self):
        """Guard against confusion with the two pre-existing csnp APIs."""
        configure_isis_interface_csnp_enabled(
            self.device, interface="swp1", enabled=False)
        joined = " ".join(self.emitted())
        self.assertNotIn("csnp-interval", joined)
        self.assertNotIn("csnp-authentication", joined)


class TestIsisInterfaceLevelEnabled(ArcosIsisConfigureTestCase):

    def test_configure_level_2(self):
        configure_isis_interface_level_enabled(
            self.device, interface="swp1", level="level_2", enabled=True)
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "level 2 enabled true", "!"],
        )

    def test_configure_level_1_disabled(self):
        configure_isis_interface_level_enabled(
            self.device, interface="swp1", level="level_1", enabled=False)
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "level 1 enabled false", "!"],
        )

    def test_unconfigure(self):
        unconfigure_isis_interface_level_enabled(
            self.device, interface="swp1", level="level_2")
        self.assertEqual(
            self.emitted(),
            [INTF_CTX, "no level 2 enabled", "!"],
        )

    def test_unconfigure_never_emits_bare_no_enabled(self):
        """R1 regression guard: a bare 'no enabled' would shut ISIS off the whole
        interface if the level submode were ever accepted-and-ignored. The
        single-line form must never produce one."""
        unconfigure_isis_interface_level_enabled(
            self.device, interface="swp1", level="level_2")
        self.assertNotIn("no enabled", self.emitted())
        self.assertIn("no level 2 enabled", self.emitted())

    def test_invalid_level_raises_before_configure(self):
        with self.assertRaises(ValueError):
            configure_isis_interface_level_enabled(
                self.device, interface="swp1", level="level_1_2")
        self.device.configure.assert_not_called()

    def test_unconfigure_invalid_level_raises_before_configure(self):
        """level_1_2 is not a single level — must raise before touching the device."""
        with self.assertRaises(ValueError):
            unconfigure_isis_interface_level_enabled(
                self.device, interface="swp1", level="level_1_2")
        self.device.configure.assert_not_called()


class TestCustomInstanceRendering(ArcosIsisConfigureTestCase):
    """M2: every function must honour non-default network/protocol instance.

    Regression guard — the only custom-instance test previously lived in the
    TestIsisDefaultMetric class, which was deleted with the withdrawn knob.
    """

    PROTO_CTX = "network-instance red protocol ISIS isis1"
    PROTO_INTF_CTX = "network-instance red protocol ISIS isis1 interface swp9"

    def test_protocol_scoped_functions(self):
        for fn, kwargs in [
            (configure_isis_timers_fast_reroute_interval, {"interval": 100}),
            (unconfigure_isis_timers_fast_reroute_interval, {}),
            (configure_isis_graceful_restart_helper_only, {}),
            (unconfigure_isis_graceful_restart_helper_only, {}),
        ]:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, network_instance="red",
                   protocol_instance="isis1", **kwargs)
                self.assertEqual(self.emitted()[0], self.PROTO_CTX)

    def test_interface_scoped_functions(self):
        for fn, kwargs in [
            (configure_isis_interface_mpls_ldp_sync, {}),
            (unconfigure_isis_interface_mpls_ldp_sync, {}),
            (configure_isis_interface_ipv4_fast_reroute_ip, {}),
            (unconfigure_isis_interface_ipv4_fast_reroute_ip, {}),
            (configure_isis_interface_ipv6_fast_reroute_ip, {}),
            (unconfigure_isis_interface_ipv6_fast_reroute_ip, {}),
            (configure_isis_interface_csnp_enabled, {}),
            (unconfigure_isis_interface_csnp_enabled, {}),
            (configure_isis_interface_level_enabled, {"level": "level_2"}),
            (unconfigure_isis_interface_level_enabled, {"level": "level_2"}),
        ]:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, interface="swp9", network_instance="red",
                   protocol_instance="isis1", **kwargs)
                self.assertEqual(self.emitted()[0], self.PROTO_INTF_CTX)


class TestFailurePropagation(ArcosIsisConfigureTestCase):
    """L1: a SubCommandFailure from the device must propagate from all 14."""

    def test_all_fourteen_propagate(self):
        for fn, kwargs in [
            (configure_isis_timers_fast_reroute_interval, {"interval": 100}),
            (unconfigure_isis_timers_fast_reroute_interval, {}),
            (configure_isis_graceful_restart_helper_only, {}),
            (unconfigure_isis_graceful_restart_helper_only, {}),
            (configure_isis_interface_mpls_ldp_sync, {"interface": "swp1"}),
            (unconfigure_isis_interface_mpls_ldp_sync, {"interface": "swp1"}),
            (configure_isis_interface_ipv4_fast_reroute_ip, {"interface": "swp1"}),
            (unconfigure_isis_interface_ipv4_fast_reroute_ip, {"interface": "swp1"}),
            (configure_isis_interface_ipv6_fast_reroute_ip, {"interface": "swp1"}),
            (unconfigure_isis_interface_ipv6_fast_reroute_ip, {"interface": "swp1"}),
            (configure_isis_interface_csnp_enabled, {"interface": "swp1"}),
            (unconfigure_isis_interface_csnp_enabled, {"interface": "swp1"}),
            (configure_isis_interface_level_enabled,
             {"interface": "swp1", "level": "level_2"}),
            (unconfigure_isis_interface_level_enabled,
             {"interface": "swp1", "level": "level_2"}),
        ]:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("device said no")
                with self.assertRaises(SubCommandFailure):
                    fn(self.device, **kwargs)


class TestExportedFromPackage(unittest.TestCase):
    """Every T1-04 function must be importable from the package __init__."""

    def test_all_fourteen_exported(self):
        from genie.libs.sdk.apis.arcos import isis as isis_pkg

        names = [
            "configure_isis_timers_fast_reroute_interval",
            "unconfigure_isis_timers_fast_reroute_interval",
            "configure_isis_graceful_restart_helper_only",
            "unconfigure_isis_graceful_restart_helper_only",
            "configure_isis_interface_mpls_ldp_sync",
            "unconfigure_isis_interface_mpls_ldp_sync",
            "configure_isis_interface_ipv4_fast_reroute_ip",
            "unconfigure_isis_interface_ipv4_fast_reroute_ip",
            "configure_isis_interface_ipv6_fast_reroute_ip",
            "unconfigure_isis_interface_ipv6_fast_reroute_ip",
            "configure_isis_interface_csnp_enabled",
            "unconfigure_isis_interface_csnp_enabled",
            "configure_isis_interface_level_enabled",
            "unconfigure_isis_interface_level_enabled",
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(hasattr(isis_pkg, name))
                self.assertIn(name, isis_pkg.__all__)


if __name__ == "__main__":
    unittest.main()
