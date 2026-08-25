"""Regression tests for the ArcOS flex-algo interface-metric silent no-op (T2R-B).

Proposal: ``orchestrator/proposals/pending/t2r_b_flex_algo_metric_fix.md``.

**The bug.** ``configure_isis_interface_flex_algo_metric`` took an ``algo_id`` and
emitted ``level N flexible-algorithm {algo_id}``. The device accepts no algorithm
id at that node — ``level N flexible-algorithm ?`` offers exactly ``te-metric``
and ``delay-metric`` — so the line was rejected with ``syntax error: unknown
argument``. Verified on rtr1 2026-08-25: the call **returned without raising and
configured nothing**. Three sanity suites believed they were setting flex-algo
metrics and were not.

**Why a unit test is the safeguard here.** The failure mode cannot be caught at
runtime: a rejected line stages nothing, so ``commit`` returns ``% No
modifications to commit``, which the arcOS unicon plugin treats as success
(``error_pattern`` in ``patterns.py`` is dead code, and by decision is not being
fixed). Nothing raises. So an exact-emission pin plus
``TestAlgoIdCannotComeBack`` is the only thing standing between this bug and a
silent return to it.

**Scope note.** ``algo_id`` is *legitimate* on the global flex-algo functions
(``configure_isis_flexible_algorithm`` and friends) — the global definition
really is keyed by algorithm. Only the per-interface-level metric is not, because
operational state reports one ``flexible-algorithm`` object per level with no
algorithm key.
"""

import inspect
import re
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.isis.configure as ic

CTX = "network-instance default protocol ISIS default interface swp1"


class Base(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestConfigureEmission(Base):

    def test_te_metric_only(self):
        ic.configure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, te_metric=100)
        self.assertEqual(
            self.emitted(),
            [CTX, "level 2 flexible-algorithm te-metric 100", "!"])

    def test_delay_metric_only(self):
        ic.configure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, delay_metric=500)
        self.assertEqual(
            self.emitted(),
            [CTX, "level 2 flexible-algorithm delay-metric 500", "!"])

    def test_both_metrics(self):
        ic.configure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, te_metric=20, delay_metric=30)
        self.assertEqual(
            self.emitted(),
            [CTX,
             "level 2 flexible-algorithm te-metric 20",
             "level 2 flexible-algorithm delay-metric 30",
             "!"])

    def test_neither_raises_value_error_before_configuring(self):
        """A bare 'flexible-algorithm' line is rejected by the device."""
        with self.assertRaises(ValueError):
            ic.configure_isis_interface_flex_algo_metric(self.device, "swp1", 2)
        self.device.configure.assert_not_called()

    def test_each_metric_is_its_own_flat_line(self):
        """The metric must never be split from its 'flexible-algorithm' prefix.

        The original bug was a submode-style split: 'flexible-algorithm {algo}'
        then a bare 'te-metric 20' on the next line.
        """
        ic.configure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, te_metric=20, delay_metric=30)
        for line in self.emitted():
            if "metric" in line:
                self.assertIn("flexible-algorithm", line)
        for line in self.emitted():
            self.assertNotEqual(line.strip(), "te-metric 20")
            self.assertNotEqual(line.strip(), "delay-metric 30")


class TestUnconfigureEmission(Base):

    def test_no_flags_removes_both(self):
        ic.unconfigure_isis_interface_flex_algo_metric(self.device, "swp1", 2)
        self.assertEqual(
            self.emitted(),
            [CTX,
             "no level 2 flexible-algorithm te-metric",
             "no level 2 flexible-algorithm delay-metric",
             "!"])

    def test_te_only(self):
        ic.unconfigure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, te_metric=True)
        self.assertEqual(
            self.emitted(),
            [CTX, "no level 2 flexible-algorithm te-metric", "!"])

    def test_delay_only(self):
        ic.unconfigure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, delay_metric=True)
        self.assertEqual(
            self.emitted(),
            [CTX, "no level 2 flexible-algorithm delay-metric", "!"])

    def test_never_removes_the_flexible_algorithm_container(self):
        """Removing the container would take out the metric not being targeted."""
        ic.unconfigure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, te_metric=True)
        for line in self.emitted():
            self.assertNotEqual(
                line.strip(), "no level 2 flexible-algorithm")


class TestAlgoIdCannotComeBack(unittest.TestCase):
    """The regression guard. This is the point of the file.

    With the plugin unable to fail on a rejected line, an algo-id creeping back
    into the emitted path would be invisible on-device and in CI alike.
    """

    def test_neither_function_accepts_algo_id(self):
        for fn in (ic.configure_isis_interface_flex_algo_metric,
                   ic.unconfigure_isis_interface_flex_algo_metric):
            with self.subTest(fn=fn.__name__):
                self.assertNotIn(
                    "algo_id", inspect.signature(fn).parameters,
                    "the per-interface-level metric is algorithm-agnostic; "
                    "see the module docstring")

    def test_no_emitted_line_puts_a_number_after_flexible_algorithm(self):
        """'flexible-algorithm 128' is the exact rejected form."""
        device = Mock()
        device.name = "test_device"
        bad = re.compile(r"flexible-algorithm\s+\d")
        for kwargs in ({"te_metric": 100},
                       {"delay_metric": 500},
                       {"te_metric": 20, "delay_metric": 30}):
            device.configure.reset_mock()
            ic.configure_isis_interface_flex_algo_metric(
                device, "swp1", 2, **kwargs)
            for line in device.configure.call_args[0][0]:
                self.assertIsNone(
                    bad.search(line),
                    f"emitted the rejected algo-id form: {line!r}")
        device.configure.reset_mock()
        ic.unconfigure_isis_interface_flex_algo_metric(device, "swp1", 2)
        for line in device.configure.call_args[0][0]:
            self.assertIsNone(bad.search(line))

    def test_algo_id_is_still_valid_on_the_global_functions(self):
        """Scope guard: only the interface-level metric lost algo_id.

        The global definition genuinely is keyed by algorithm, so a blanket
        'remove algo_id from flex-algo APIs' change would be wrong.
        """
        for name in ("configure_isis_flexible_algorithm",
                     "configure_isis_flexible_algorithm_priority",
                     "configure_isis_flexible_algorithm_admin_groups"):
            with self.subTest(fn=name):
                fn = getattr(ic, name)
                self.assertIn("algo_id", inspect.signature(fn).parameters)


class TestFlexAlgoSiblingConsistency(unittest.TestCase):
    """All three interface-level flex-algo functions must emit no numeric arg."""

    def test_no_interface_flex_algo_function_emits_a_numeric_algo(self):
        device = Mock()
        device.name = "test_device"
        bad = re.compile(r"flexible-algorithm\s+\d")
        for fn, args, kwargs in [
            (ic.configure_isis_interface_flex_algo_metric,
             ("swp1", 2), {"te_metric": 10}),
            (ic.configure_isis_interface_flex_algo_admin_groups,
             ("swp1", ["red"]), {}),
            (ic.configure_isis_interface_flex_algo_delay_metric_dynamic,
             ("swp1", 2), {}),
        ]:
            with self.subTest(fn=fn.__name__):
                device.configure.reset_mock()
                fn(device, *args, **kwargs)
                for line in device.configure.call_args[0][0]:
                    self.assertIsNone(bad.search(line))


class TestCrossCuttingTriad(Base):

    CASES = [
        ("configure", {"te_metric": 20, "delay_metric": 30}),
        ("unconfigure", {}),
    ]

    def _call(self, which, **kwargs):
        fn = (ic.configure_isis_interface_flex_algo_metric if which == "configure"
              else ic.unconfigure_isis_interface_flex_algo_metric)
        return fn(self.device, "swp1", 2, **kwargs)

    def test_no_stray_exit(self):
        for which, kwargs in self.CASES:
            with self.subTest(fn=which):
                self.device.configure.reset_mock()
                self._call(which, **kwargs)
                for line in self.device.configure.call_args[0][0]:
                    self.assertNotEqual(line.strip(), "exit")

    def test_renders_non_default_instances(self):
        for which, kwargs in self.CASES:
            with self.subTest(fn=which):
                self.device.configure.reset_mock()
                fn = (ic.configure_isis_interface_flex_algo_metric
                      if which == "configure"
                      else ic.unconfigure_isis_interface_flex_algo_metric)
                fn(self.device, "swp1", 2,
                   network_instance="vrf-1", protocol_instance="isis1", **kwargs)
                self.assertEqual(
                    self.device.configure.call_args[0][0][0],
                    "network-instance vrf-1 protocol ISIS isis1 interface swp1")

    def test_failure_propagates(self):
        for which, kwargs in self.CASES:
            with self.subTest(fn=which):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("no")
                with self.assertRaises(SubCommandFailure):
                    self._call(which, **kwargs)


if __name__ == "__main__":
    unittest.main()
