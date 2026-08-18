"""Unit tests for ArcOS LDP + RSVP-TE configure APIs added by batch T1-06.

Source: ``arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md``.
Proposal: ``orchestrator/proposals/approved/ldp_api_t1_06_attrs_bindings.md``.

10 configure/unconfigure pairs in ``apis.arcos.ldp.configure`` plus one
backward-compatible extension in ``apis.arcos.rsvp_te.configure``. All
lab-verified on rtr1 2026-08-17 in both directions.

`_LDP_CTX` is a one-line PATH PREFIX, not a submode — every emitted line is a
full path, matching the file's existing convention.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.ldp.configure import (
    configure_ldp_fec_filter_export_policy, unconfigure_ldp_fec_filter_export_policy,
    configure_ldp_attributes_php_enable, unconfigure_ldp_attributes_php_enable,
    configure_ldp_attributes_label_distribution_mode,
    unconfigure_ldp_attributes_label_distribution_mode,
    configure_ldp_attributes_post_session_up_delay,
    unconfigure_ldp_attributes_post_session_up_delay,
    configure_ldp_maximum_local_binding, unconfigure_ldp_maximum_local_binding,
    configure_ldp_interface_attributes_hello,
    unconfigure_ldp_interface_attributes_hello,
    unconfigure_ldp_interface_attributes_hello_interval,
    configure_ldp_interface_hello, unconfigure_ldp_interface_hello,
    configure_ldp_neighbor_maximum_remote_binding,
    unconfigure_ldp_neighbor_maximum_remote_binding,
    configure_ldp_neighbor_targeted_hello, unconfigure_ldp_neighbor_targeted_hello,
)
from genie.libs.sdk.apis.arcos.rsvp_te.configure import (
    configure_rsvp_te_interface,
    configure_rsvp_interface,
)

L = "network-instance default mpls signaling-protocols ldp"
TE = "network-instance default mpls mpls-te"


class Base(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestGlobalLeaves(Base):

    CASES = [
        (configure_ldp_attributes_php_enable, {"enabled": False},
         f"{L} global attributes php-enable false"),
        (configure_ldp_attributes_label_distribution_mode, {"mode": "ordered"},
         f"{L} global attributes label-distribution-mode ordered"),
        (configure_ldp_attributes_post_session_up_delay, {"delay": 10},
         f"{L} global attributes post-session-up-delay 10"),
        (configure_ldp_maximum_local_binding, {"maximum": 1000},
         f"{L} global maximum-local-binding 1000"),
    ]

    UNC = [
        (unconfigure_ldp_attributes_php_enable,
         f"no {L} global attributes php-enable"),
        (unconfigure_ldp_attributes_label_distribution_mode,
         f"no {L} global attributes label-distribution-mode"),
        (unconfigure_ldp_attributes_post_session_up_delay,
         f"no {L} global attributes post-session-up-delay"),
        (unconfigure_ldp_maximum_local_binding,
         f"no {L} global maximum-local-binding"),
    ]

    def test_configure(self):
        for fn, kwargs, line in self.CASES:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                self.assertEqual(self.emitted(), [line, "!"])

    def test_unconfigure(self):
        for fn, line in self.UNC:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device)
                self.assertEqual(self.emitted(), [line, "!"])


class TestFecFilterExportPolicy(Base):

    def test_single_policy(self):
        configure_ldp_fec_filter_export_policy(self.device, policy="LDPPOL")
        self.assertEqual(
            self.emitted(),
            [f"{L} global fec-filter export-policy [ LDPPOL ]", "!"])

    def test_policy_list(self):
        configure_ldp_fec_filter_export_policy(self.device, policy=["p1", "p2"])
        self.assertEqual(
            self.emitted(),
            [f"{L} global fec-filter export-policy [ p1 p2 ]", "!"])

    def test_distinct_from_default_export_policy(self):
        """configure_ldp_global already sets `default-export-policy`; this must
        not touch that leaf."""
        configure_ldp_fec_filter_export_policy(self.device, policy="LDPPOL")
        self.assertNotIn("default-export-policy", " ".join(self.emitted()))

    def test_unconfigure(self):
        unconfigure_ldp_fec_filter_export_policy(self.device)
        self.assertEqual(
            self.emitted(), [f"no {L} global fec-filter export-policy", "!"])


class TestHelloTimers(Base):

    def test_global_interface_attributes(self):
        configure_ldp_interface_attributes_hello(
            self.device, hello_holdtime=15, hello_interval=5)
        self.assertEqual(self.emitted(), [
            f"{L} interface-attributes hello-holdtime 15",
            f"{L} interface-attributes hello-interval 5",
            "!",
        ])

    def test_per_interface(self):
        configure_ldp_interface_hello(
            self.device, interface="swp1", hello_holdtime=15, hello_interval=5)
        self.assertEqual(self.emitted(), [
            f"{L} interface-attributes interface swp1 hello-holdtime 15",
            f"{L} interface-attributes interface swp1 hello-interval 5",
            "!",
        ])

    def test_neighbor_targeted(self):
        configure_ldp_neighbor_targeted_hello(
            self.device, lsr_id="2.2.2.2", hello_holdtime=45, hello_interval=15)
        self.assertEqual(self.emitted(), [
            f"{L} neighbor 2.2.2.2 0 targeted hello-holdtime 45",
            f"{L} neighbor 2.2.2.2 0 targeted hello-interval 15",
            "!",
        ])

    def test_only_one_timer_is_allowed(self):
        configure_ldp_interface_hello(self.device, interface="swp1", hello_interval=5)
        self.assertEqual(self.emitted(), [
            f"{L} interface-attributes interface swp1 hello-interval 5", "!"])

    def test_neither_timer_raises(self):
        for fn, kwargs in (
            (configure_ldp_interface_attributes_hello, {}),
            (configure_ldp_interface_hello, {"interface": "swp1"}),
            (configure_ldp_neighbor_targeted_hello, {"lsr_id": "2.2.2.2"}),
        ):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    fn(self.device, **kwargs)
                self.device.configure.assert_not_called()


class TestHelloUnconfigureClearsBothLeaves(Base):
    """H1 regression guard.

    The configure halves set hello-holdtime AND hello-interval via
    _ldp_hello_lines, so the unconfigure must clear both. Shipping only the
    holdtime line left an interval-only call surviving its own documented
    removal — and the original lab check missed it because the verification
    script hand-wrote both `no` lines rather than emitting what the API emits.
    """

    def test_per_interface_clears_both(self):
        unconfigure_ldp_interface_hello(self.device, interface="swp1")
        self.assertEqual(self.emitted(), [
            f"no {L} interface-attributes interface swp1 hello-holdtime",
            f"no {L} interface-attributes interface swp1 hello-interval",
            "!",
        ])

    def test_neighbor_targeted_clears_both(self):
        unconfigure_ldp_neighbor_targeted_hello(self.device, lsr_id="2.2.2.2")
        self.assertEqual(self.emitted(), [
            f"no {L} neighbor 2.2.2.2 0 targeted hello-holdtime",
            f"no {L} neighbor 2.2.2.2 0 targeted hello-interval",
            "!",
        ])

    def test_every_leaf_a_configure_can_set_has_an_inverse(self):
        """Generic form of H1: for each hello pair, the leaves the configure
        emits must all appear in its unconfigure."""
        pairs = [
            (configure_ldp_interface_hello, unconfigure_ldp_interface_hello,
             {"interface": "swp1"}, {"interface": "swp1"}),
            (configure_ldp_neighbor_targeted_hello,
             unconfigure_ldp_neighbor_targeted_hello,
             {"lsr_id": "2.2.2.2"}, {"lsr_id": "2.2.2.2"}),
        ]
        for cfg_fn, unc_fn, cfg_kw, unc_kw in pairs:
            with self.subTest(fn=cfg_fn.__name__):
                self.device.configure.reset_mock()
                cfg_fn(self.device, hello_holdtime=15, hello_interval=5, **cfg_kw)
                set_leaves = {l.rsplit(" ", 1)[0] for l in self.emitted()
                              if "hello-" in l}
                self.device.configure.reset_mock()
                unc_fn(self.device, **unc_kw)
                cleared = {l[len("no "):] for l in self.emitted() if l.startswith("no ")}
                self.assertEqual(set_leaves, cleared)


class TestNeighborKeyIsTwoTokens(Base):
    """The LDP neighbor key is `{lsr_id} {label_space_id}`, matching
    configure_ldp_neighbor — NOT a colon-joined `lsr:space` form, which the
    device rejects with '% Invalid input detected'."""

    def test_default_label_space(self):
        configure_ldp_neighbor_maximum_remote_binding(
            self.device, lsr_id="2.2.2.2", maximum=10)
        self.assertEqual(self.emitted(), [
            f"{L} neighbor 2.2.2.2 0 maximum-remote-binding 10", "!"])

    def test_explicit_label_space(self):
        configure_ldp_neighbor_maximum_remote_binding(
            self.device, lsr_id="2.2.2.2", maximum=10, label_space_id=3)
        self.assertIn("neighbor 2.2.2.2 3 maximum-remote-binding 10",
                      " ".join(self.emitted()))

    def test_never_emits_colon_form(self):
        configure_ldp_neighbor_maximum_remote_binding(
            self.device, lsr_id="2.2.2.2", maximum=10)
        self.assertNotIn("2.2.2.2:0", " ".join(self.emitted()))

    def test_unconfigure(self):
        unconfigure_ldp_neighbor_maximum_remote_binding(
            self.device, lsr_id="2.2.2.2")
        self.assertEqual(self.emitted(), [
            f"no {L} neighbor 2.2.2.2 0 maximum-remote-binding", "!"])


class TestRsvpTeInterfaceExtension(Base):
    """T1-06 extended configure_rsvp_te_interface, which previously hardcoded
    `enable true` with no way to disable."""

    def test_enabled_param_exists_and_defaults_true(self):
        p = inspect.signature(configure_rsvp_te_interface).parameters
        self.assertIn("enabled", p)
        self.assertIs(p["enabled"].default, True)

    def test_default_call_is_backward_compatible(self):
        configure_rsvp_te_interface(self.device, interface="swp1")
        self.assertEqual(
            self.emitted(), [f"{TE} interface swp1", "enable true", "!"])

    def test_can_now_disable(self):
        configure_rsvp_te_interface(self.device, interface="swp1", enabled=False)
        self.assertEqual(
            self.emitted(), [f"{TE} interface swp1", "enable false", "!"])

    def test_rsvp_proper_interface_can_also_disable(self):
        """H2: configure_rsvp_interface is the function the audit flags as a
        partial API; it hardcoded `enable true` until T1-06."""
        p = inspect.signature(configure_rsvp_interface).parameters
        self.assertIn("enabled", p)
        self.assertIs(p["enabled"].default, True)
        configure_rsvp_interface(self.device, interface="swp1", enabled=False)
        self.assertEqual(self.emitted()[:2], [
            "network-instance default protocol RSVP default interface swp1",
            "enable false",
        ])

    def test_metric_still_works_with_enabled(self):
        configure_rsvp_te_interface(
            self.device, interface="swp1", metric=100, enabled=False)
        self.assertEqual(self.emitted(), [
            f"{TE} interface swp1", "enable false", "metric 100", "!"])


ALL = [
    (configure_ldp_fec_filter_export_policy, {"policy": "P"}),
    (unconfigure_ldp_fec_filter_export_policy, {}),
    (configure_ldp_attributes_php_enable, {}),
    (unconfigure_ldp_attributes_php_enable, {}),
    (configure_ldp_attributes_label_distribution_mode, {"mode": "ordered"}),
    (unconfigure_ldp_attributes_label_distribution_mode, {}),
    (configure_ldp_attributes_post_session_up_delay, {"delay": 10}),
    (unconfigure_ldp_attributes_post_session_up_delay, {}),
    (configure_ldp_maximum_local_binding, {"maximum": 1}),
    (unconfigure_ldp_maximum_local_binding, {}),
    (configure_ldp_interface_attributes_hello, {"hello_holdtime": 15}),
    (unconfigure_ldp_interface_attributes_hello, {}),
    (unconfigure_ldp_interface_attributes_hello_interval, {}),
    (configure_ldp_interface_hello, {"interface": "swp1", "hello_holdtime": 15}),
    (unconfigure_ldp_interface_hello, {"interface": "swp1"}),
    (configure_ldp_neighbor_maximum_remote_binding, {"lsr_id": "2.2.2.2", "maximum": 1}),
    (unconfigure_ldp_neighbor_maximum_remote_binding, {"lsr_id": "2.2.2.2"}),
    (configure_ldp_neighbor_targeted_hello, {"lsr_id": "2.2.2.2", "hello_holdtime": 45}),
    (unconfigure_ldp_neighbor_targeted_hello, {"lsr_id": "2.2.2.2"}),
]


class TestCrossCutting(Base):

    def test_failure_propagation(self):
        for fn, kwargs in ALL:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("nope")
                with self.assertRaises(SubCommandFailure):
                    fn(self.device, **kwargs)

    def test_every_list_is_full_paths_ending_in_bang(self):
        """No submode is entered, so every line must start with the LDP path."""
        for fn, kwargs in ALL:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                cfg = self.emitted()
                self.assertEqual(cfg[-1], "!")
                self.assertNotIn("exit", cfg)
                for line in cfg[:-1]:
                    self.assertTrue(
                        line.startswith(L) or line.startswith(f"no {L}"),
                        f"{line!r} is not a full LDP path")


if __name__ == "__main__":
    unittest.main()
