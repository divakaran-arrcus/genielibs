"""Unit tests for ArcOS OSPFv2/OSPFv3 configure APIs added by batch T1-05.

Source: ``arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md``.
Proposal: ``orchestrator/proposals/approved/ospf_api_t1_05_logging_timers.md``.

8 configure/unconfigure pairs across ``apis.arcos.ospf.configure`` and
``apis.arcos.ospfv3.configure``. All lab-verified on rtr1 2026-08-17 in both
directions. Note OSPFv3's protocol token is ``OSPF3``, not ``OSPFv3``.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.ospf.configure import (
    OSPF_LOG_ADJ_MODES, OSPF_SNMP_TRAPS,
    configure_ospf_log_adjacency_changes, unconfigure_ospf_log_adjacency_changes,
    configure_ospf_spf_logging, unconfigure_ospf_spf_logging,
    configure_ospf_timers_lsa, unconfigure_ospf_timers_lsa,
    configure_ospf_snmp_send_trap, unconfigure_ospf_snmp_send_trap,
    configure_ospf_interface_auth_keychain, unconfigure_ospf_interface_auth_keychain,
)
from genie.libs.sdk.apis.arcos.ospfv3.configure import (
    OSPFV3_LOG_ADJ_MODES,
    configure_ospfv3_log_adjacency_changes, unconfigure_ospfv3_log_adjacency_changes,
    configure_ospfv3_spf_logging, unconfigure_ospfv3_spf_logging,
    configure_ospfv3_timers_lsa, unconfigure_ospfv3_timers_lsa,
)

V2 = "network-instance default protocol OSPF default"
V3 = "network-instance default protocol OSPF3 default"


class Base(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestLogAdjacencyChanges(Base):

    def test_v2_and_v3_emission(self):
        for fn, ctx in ((configure_ospf_log_adjacency_changes, V2),
                        (configure_ospfv3_log_adjacency_changes, V3)):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, mode="LOG_ADJ_ENABLE_DETAILED")
                self.assertEqual(self.emitted(), [
                    ctx, "global log-adjacency-changes LOG_ADJ_ENABLE_DETAILED", "!"])

    def test_all_documented_modes_reach_the_wire(self):
        """H3: this loop previously asserted nothing — hardcoding the emitted
        mode in BOTH modules left the suite green, since the one emission test
        uses that same mode. Two of three modes were never verified."""
        for modes, fn, ctx in (
            (OSPF_LOG_ADJ_MODES, configure_ospf_log_adjacency_changes, V2),
            (OSPFV3_LOG_ADJ_MODES, configure_ospfv3_log_adjacency_changes, V3),
        ):
            self.assertEqual(len(modes), 3)
            for m in modes:
                with self.subTest(fn=fn.__name__, mode=m):
                    self.device.configure.reset_mock()
                    fn(self.device, mode=m)
                    self.assertEqual(self.emitted(), [
                        ctx, f"global log-adjacency-changes {m}", "!"])

    def test_invalid_mode_rejected(self):
        for fn in (configure_ospf_log_adjacency_changes,
                   configure_ospfv3_log_adjacency_changes):
            for bad in ("enable", "LOG_ADJ_ENABLE", "", None):
                with self.subTest(fn=fn.__name__, mode=bad):
                    self.device.configure.reset_mock()
                    with self.assertRaises(ValueError):
                        fn(self.device, mode=bad)
                    self.device.configure.assert_not_called()

    def test_unconfigures(self):
        for fn, ctx in ((unconfigure_ospf_log_adjacency_changes, V2),
                        (unconfigure_ospfv3_log_adjacency_changes, V3)):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device)
                self.assertEqual(
                    self.emitted(), [ctx, "no global log-adjacency-changes", "!"])


class TestSpfLogging(Base):

    def test_both_leaves(self):
        configure_ospf_spf_logging(
            self.device, maximum_logs=20, maximum_triggers_per_log=10)
        self.assertEqual(self.emitted(), [
            V2,
            "global spf logging maximum-logs 20",
            "global spf logging maximum-triggers-per-log 10",
            "!",
        ])

    def test_leaf_name_is_maximum_triggers_per_log(self):
        """The audit called it `triggers-per-log`; the device leaf is
        `maximum-triggers-per-log`.

        M4: this guard covered only OSPFv2 — renaming the leaf in the v3 copy of
        _spf_logging_lines passed the whole suite. The two copies are identical
        today precisely because nothing enforced it, so loop over both.
        """
        for fn, ctx in ((configure_ospf_spf_logging, V2),
                        (configure_ospfv3_spf_logging, V3)):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, maximum_triggers_per_log=8)
                self.assertEqual(self.emitted(), [
                    ctx, "global spf logging maximum-triggers-per-log 8", "!"])

    def test_requires_at_least_one(self):
        for fn in (configure_ospf_spf_logging, configure_ospfv3_spf_logging):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    fn(self.device)
                self.device.configure.assert_not_called()

    def test_v3(self):
        configure_ospfv3_spf_logging(self.device, maximum_logs=20)
        self.assertEqual(
            self.emitted(), [V3, "global spf logging maximum-logs 20", "!"])

    def test_unconfigures(self):
        for fn, ctx in ((unconfigure_ospf_spf_logging, V2),
                        (unconfigure_ospfv3_spf_logging, V3)):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device)
                self.assertEqual(self.emitted(), [ctx, "no global spf logging", "!"])


class TestTimersLsa(Base):
    """`origination-delay` is deliberately absent — the CLI advertises it in `?`
    but rejects every assignment, on both OSPF and OSPF3."""

    def test_min_arrival_only(self):
        for fn, ctx in ((configure_ospf_timers_lsa, V2),
                        (configure_ospfv3_timers_lsa, V3)):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, min_arrival=100)
                self.assertEqual(
                    self.emitted(), [ctx, "global timers lsa min-arrival 100", "!"])

    def test_no_origination_delay_parameter(self):
        import inspect
        for fn in (configure_ospf_timers_lsa, configure_ospfv3_timers_lsa):
            with self.subTest(fn=fn.__name__):
                self.assertNotIn(
                    "origination_delay", inspect.signature(fn).parameters)

    def test_never_emits_origination_delay(self):
        configure_ospf_timers_lsa(self.device, min_arrival=1)
        self.assertNotIn("origination-delay", " ".join(self.emitted()))

    def test_min_arrival_is_required(self):
        with self.assertRaises(TypeError):
            configure_ospf_timers_lsa(self.device)

    def test_unconfigures(self):
        for fn, ctx in ((unconfigure_ospf_timers_lsa, V2),
                        (unconfigure_ospfv3_timers_lsa, V3)):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device)
                self.assertEqual(self.emitted(), [ctx, "no global timers lsa", "!"])


class TestSnmpSendTrap(Base):

    def test_emission(self):
        configure_ospf_snmp_send_trap(self.device, trap="if-state-change")
        self.assertEqual(self.emitted(), [
            V2, "global snmp send-trap if-state-change true", "!"])

    def test_all_ten_traps_reach_the_wire(self):
        """H2: this loop previously asserted nothing — hardcoding the emitted
        token to `if-state-change` left the whole suite green, because the one
        emission test happens to use that same trap."""
        self.assertEqual(len(OSPF_SNMP_TRAPS), 10)
        for t in OSPF_SNMP_TRAPS:
            with self.subTest(trap=t):
                self.device.configure.reset_mock()
                configure_ospf_snmp_send_trap(self.device, trap=t)
                self.assertEqual(self.emitted(), [
                    V2, f"global snmp send-trap {t} true", "!"])

    def test_m5_trap_enabled_false(self):
        """M5: the `enabled` parameter was never exercised at False."""
        configure_ospf_snmp_send_trap(
            self.device, trap="nbr-state-change", enabled=False)
        self.assertEqual(self.emitted(), [
            V2, "global snmp send-trap nbr-state-change false", "!"])

    def test_invalid_trap_rejected_both_directions(self):
        for fn in (configure_ospf_snmp_send_trap, unconfigure_ospf_snmp_send_trap):
            for bad in ("ifStateChange", "if_state_change", "", None):
                with self.subTest(fn=fn.__name__, trap=bad):
                    self.device.configure.reset_mock()
                    with self.assertRaises(ValueError):
                        fn(self.device, trap=bad)
                    self.device.configure.assert_not_called()

    def test_unconfigure(self):
        unconfigure_ospf_snmp_send_trap(self.device, trap="max-age-lsa")
        self.assertEqual(
            self.emitted(), [V2, "no global snmp send-trap max-age-lsa", "!"])


class TestInterfaceAuthKeychain(Base):

    def test_configure_sets_auth_type_and_keychain(self):
        configure_ospf_interface_auth_keychain(
            self.device, area_id="0", interface="swp1", keychain="kc1")
        self.assertEqual(self.emitted(), [
            V2,
            "area 0",
            "interface swp1",
            "authentication auth-type OSPF_AUTH_KEYCHAIN",
            "authentication crypto-keychain keychain kc1",
            "!",
        ])

    def test_does_not_use_crypto_key_path(self):
        """Must not collide with the MD5 sibling's `crypto-key` leaf."""
        configure_ospf_interface_auth_keychain(
            self.device, area_id="0", interface="swp1", keychain="kc1")
        joined = " ".join(self.emitted())
        self.assertNotIn("crypto-key algorithm", joined)
        self.assertNotIn("OSPF_AUTH_CRYPTO_KEY", joined)

    def test_unconfigure(self):
        unconfigure_ospf_interface_auth_keychain(
            self.device, area_id="0", interface="swp1")
        self.assertEqual(self.emitted(), [
            V2,
            "area 0",
            "interface swp1",
            "no authentication crypto-keychain",
            "no authentication auth-type",
            "!",
        ])


ALL_FUNCS = [
    (configure_ospf_log_adjacency_changes, {"mode": "LOG_ADJ_DISABLE"}, V2),
    (unconfigure_ospf_log_adjacency_changes, {}, V2),
    (configure_ospf_spf_logging, {"maximum_logs": 16}, V2),
    (unconfigure_ospf_spf_logging, {}, V2),
    (configure_ospf_timers_lsa, {"min_arrival": 200}, V2),
    (unconfigure_ospf_timers_lsa, {}, V2),
    (configure_ospf_snmp_send_trap, {"trap": "max-age-lsa"}, V2),
    (unconfigure_ospf_snmp_send_trap, {"trap": "max-age-lsa"}, V2),
    (configure_ospf_interface_auth_keychain,
     {"area_id": "0", "interface": "swp1", "keychain": "kc1"}, V2),
    (unconfigure_ospf_interface_auth_keychain,
     {"area_id": "0", "interface": "swp1"}, V2),
    (configure_ospfv3_log_adjacency_changes, {"mode": "LOG_ADJ_DISABLE"}, V3),
    (unconfigure_ospfv3_log_adjacency_changes, {}, V3),
    (configure_ospfv3_spf_logging, {"maximum_logs": 16}, V3),
    (unconfigure_ospfv3_spf_logging, {}, V3),
    (configure_ospfv3_timers_lsa, {"min_arrival": 200}, V3),
    (unconfigure_ospfv3_timers_lsa, {}, V3),
]


class TestCrossCutting(Base):

    def test_custom_instance(self):
        for fn, kwargs, ctx in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, network_instance="red",
                   protocol_instance="p1", **kwargs)
                tok = "OSPF3" if ctx is V3 else "OSPF"
                self.assertEqual(
                    self.emitted()[0],
                    f"network-instance red protocol {tok} p1")

    def test_failure_propagation(self):
        for fn, kwargs, _ in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("nope")
                with self.assertRaises(SubCommandFailure):
                    fn(self.device, **kwargs)

    def test_every_list_ends_with_bang(self):
        for fn, kwargs, ctx in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                cfg = self.emitted()
                self.assertEqual(cfg[0], ctx)
                self.assertEqual(cfg[-1], "!")


if __name__ == "__main__":
    unittest.main()
