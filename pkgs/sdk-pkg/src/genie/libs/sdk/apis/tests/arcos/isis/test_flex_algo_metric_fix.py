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
runtime. A rejected line stages nothing, so ``commit`` returns ``% No
modifications to commit``, which the arcOS unicon plugin treats as success --
nothing raises. The precise mechanism: the arcOS plugin does not override
unicon's ``CONFIGURE_ERROR_PATTERN``, so it inherits the generic default, a list
of IOS-shaped strings (``overlaps with``, ``% Class-map ...``, ``%ERROR:``) that
does not contain arcOS's own error vocabulary (``syntax error: ...``,
``Aborted: ...``). By decision the plugin is not being changed. So the exact
emission pins plus ``TestNoAlgorithmTokenCanComeBack`` are the only thing
standing between this bug and a silent return to it -- which is why that guard
pins the emitted SHAPE rather than a parameter name.

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

    def test_level_is_actually_used(self):
        """Mutation guard: hardcoding 'level 2' in the API passed every test.

        Every other unconfigure case here uses level 2, so a bug that ignored
        the argument was invisible -- and `unconfigure(level=1)` emitting a
        level-2 removal is CLI the device ACCEPTS, silently wiping the wrong
        level's metric.
        """
        for lvl in (1, 2):
            with self.subTest(level=lvl):
                self.device.configure.reset_mock()
                ic.unconfigure_isis_interface_flex_algo_metric(
                    self.device, "swp1", lvl)
                self.assertEqual(
                    self.emitted(),
                    [CTX,
                     f"no level {lvl} flexible-algorithm te-metric",
                     f"no level {lvl} flexible-algorithm delay-metric",
                     "!"])

    def test_never_removes_the_flexible_algorithm_container(self):
        """Removing the container would take out the metric not being targeted."""
        ic.unconfigure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, te_metric=True)
        for line in self.emitted():
            self.assertNotEqual(
                line.strip(), "no level 2 flexible-algorithm")


class TestNoAlgorithmTokenCanComeBack(unittest.TestCase):
    """The regression guard. This is the point of the file.

    With the plugin unable to fail on a rejected line, an algorithm token
    creeping back into the emitted path would be invisible on-device and in CI.

    **This pins the emitted SHAPE, not a parameter spelling.** An earlier version
    asserted only that ``algo_id`` was absent from the signature; a mutation test
    showed that adding ``algo=None`` under any other name and emitting
    ``level N flexible-algorithm {algo}`` restored the bug with the whole suite
    still green. The whitelist below rejects *any* unexpected token, whatever it
    is called.
    """

    #: The only shapes either function may ever emit, besides the context and '!'.
    ALLOWED = re.compile(
        r"^(?:no )?level (?:1|2) flexible-algorithm (?:te|delay)-metric"
        r"(?: [1-9]\d*)?$"
    )

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def _emitted_lines(self):
        """Return the emitted config, asserting it really is a list.

        A mutation test showed that if the API ever emitted a single joined
        string, `for line in ...` would iterate per CHARACTER and every regex
        check below would pass vacuously.
        """
        cfg = self.device.configure.call_args[0][0]
        self.assertIsInstance(cfg, list, "emission must be a list of lines")
        for line in cfg:
            self.assertIsInstance(line, str)
        return cfg

    def _check(self, cfg):
        for line in cfg:
            if line.startswith(CTX) or line == "!":
                continue
            self.assertRegex(
                line, self.ALLOWED,
                f"emitted a line outside the allowed flex-algo shapes: {line!r}")

    def test_configure_emits_only_allowed_shapes(self):
        for kwargs in ({"te_metric": 100},
                       {"delay_metric": 500},
                       {"te_metric": 20, "delay_metric": 30}):
            with self.subTest(**kwargs):
                self.device.configure.reset_mock()
                ic.configure_isis_interface_flex_algo_metric(
                    self.device, "swp1", 2, **kwargs)
                self._check(self._emitted_lines())

    def test_unconfigure_emits_only_allowed_shapes(self):
        for kwargs in ({}, {"te_metric": True}, {"delay_metric": True},
                       {"te_metric": True, "delay_metric": True}):
            with self.subTest(**kwargs):
                self.device.configure.reset_mock()
                ic.unconfigure_isis_interface_flex_algo_metric(
                    self.device, "swp1", 2, **kwargs)
                self._check(self._emitted_lines())

    def test_no_extra_parameter_can_inject_a_token(self):
        """Call each function with EVERY optional kwarg it accepts, at once.

        This is what makes the guard resistant to a renamed algo argument: a new
        parameter that reaches the emission is exercised here and its token is
        then rejected by the whitelist.
        """
        for fn, base in (
            (ic.configure_isis_interface_flex_algo_metric, {"te_metric": 10}),
            (ic.unconfigure_isis_interface_flex_algo_metric, {}),
        ):
            sig = inspect.signature(fn)
            kwargs = dict(base)
            for name, param in sig.parameters.items():
                if name in ("device", "interface", "level") or name in kwargs:
                    continue
                if param.default is inspect.Parameter.empty:
                    continue
                # Feed a recognisable value to any optional param we do not know.
                if name in ("network_instance", "protocol_instance"):
                    continue
                if isinstance(param.default, bool):
                    kwargs[name] = True
                elif param.default is None:
                    kwargs[name] = 7
            with self.subTest(fn=fn.__name__, kwargs=kwargs):
                self.device.configure.reset_mock()
                try:
                    fn(self.device, "swp1", 2, **kwargs)
                except (ValueError, TypeError):
                    continue   # rejecting the input is an acceptable outcome
                self._check(self._emitted_lines())

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


class TestInputValidationClosesTheSameHole(Base):
    """Reject inputs the DEVICE rejects, since a rejected line is a silent no-op.

    Every case below was confirmed rejected on rtr1 2026-08-31. Without these
    guards each one emits a well-formed-looking line that the device refuses,
    the commit reports "% No modifications to commit", and the call returns
    success having configured nothing -- exactly the defect this module fixed.
    """

    def test_level_enum_form_is_rejected(self):
        """configure_isis_interface_flex_algo_metric takes 2, not 'level_2'.

        `configure_isis_interface` in the same module takes the enum form, so
        this is an easy mistake. Device: syntax error: "level_2" is not a valid
        value.
        """
        with self.assertRaises(ValueError):
            ic.configure_isis_interface_flex_algo_metric(
                self.device, "swp1", "level_2", te_metric=10)
        self.device.configure.assert_not_called()

    def test_out_of_range_level_rejected(self):
        for bad in (0, 3, "L2", None, True):
            with self.subTest(level=bad):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    ic.configure_isis_interface_flex_algo_metric(
                        self.device, "swp1", bad, te_metric=10)
                self.device.configure.assert_not_called()

    def test_numeric_level_accepted_as_int_or_str(self):
        for good in (2, "2", 1, "1"):
            with self.subTest(level=good):
                self.device.configure.reset_mock()
                ic.configure_isis_interface_flex_algo_metric(
                    self.device, "swp1", good, te_metric=10)
                self.assertIn(
                    f"level {good} flexible-algorithm te-metric 10",
                    self.device.configure.call_args[0][0])

    def test_zero_and_falsy_metrics_rejected(self):
        """Device: syntax error: "0" is out of range. An `is None` guard alone
        would let 0, False and '' through to a rejected line."""
        for bad in (0, False, "", "20", -1, 1.5):
            with self.subTest(te_metric=bad):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    ic.configure_isis_interface_flex_algo_metric(
                        self.device, "swp1", 2, te_metric=bad)
                self.device.configure.assert_not_called()

    def test_unconfigure_flags_must_be_bools(self):
        """The same names carry VALUES in configure and FLAGS here.

        A caller copying the configure's shape and passing te_metric=0 would
        otherwise fall through to the no-flags branch and clear BOTH metrics --
        removing a metric the caller never named.
        """
        for bad in (0, 20, "yes", None):
            with self.subTest(te_metric=bad):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    ic.unconfigure_isis_interface_flex_algo_metric(
                        self.device, "swp1", 2, te_metric=bad)
                self.device.configure.assert_not_called()

    def test_unconfigure_still_accepts_bools_and_omission(self):
        """The guard must not break the two legitimate call shapes."""
        self.device.configure.reset_mock()
        ic.unconfigure_isis_interface_flex_algo_metric(
            self.device, "swp1", 2, te_metric=True)
        # context + one 'no' line + '!'
        self.assertEqual(
            self.device.configure.call_args[0][0],
            [CTX, "no level 2 flexible-algorithm te-metric", "!"])
        self.device.configure.reset_mock()
        ic.unconfigure_isis_interface_flex_algo_metric(self.device, "swp1", 2)
        # context + both 'no' lines + '!'
        self.assertEqual(
            self.device.configure.call_args[0][0],
            [CTX,
             "no level 2 flexible-algorithm te-metric",
             "no level 2 flexible-algorithm delay-metric",
             "!"])


if __name__ == "__main__":
    unittest.main()
