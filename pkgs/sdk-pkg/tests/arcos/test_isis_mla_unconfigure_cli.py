"""Where ``no`` goes in the ISIS micro-loop-avoidance unconfigure CLI.

``unconfigure_isis_micro_loop_avoidance_sr_mpls`` emitted::

    global af IPV4 UNICAST no micro-loop-avoidance sr-mpls-enabled

with ``no`` in the MIDDLE of the path. arcOS rejects that, and the caret in
its error points straight at the ``no``::

    root@rtr1(config-protocol-ISIS/default)# global af IPV4 UNICAST no micro-loop-avoidance sr-mpls-enabled
    ----------------------------------------------------------------^
    syntax error: element does not exist

The reason it went unnoticed for so long is the same one behind the
``usage SRGB`` defect: arcOS rejects the offending leaf but still COMMITS the
surrounding block, so ``device.configure()`` raises nothing, the API returns
cleanly, and the suite reports PASS over a complete no-op. Build 1834 scored
48/48 with this rejection in its device-CLI log.

Measured on the docker lab (rtr1, 2026-09-11), configure then unconfigure,
reading the running-config back after each step:

    configure sr-mpls-enabled true    -> ACCEPTED, readback: present
    'global af .. UNICAST no ..'      -> REJECTED, readback: STILL PRESENT
    'no global af .. UNICAST ..'      -> ACCEPTED, readback: ABSENT

So the mid-path form does not merely log an error; it leaves MLA enabled on
the device while every caller believes it was removed.

Scope, corrected after review -- the first version of this file overstated
it twice. No MLA config-lifecycle testcase asserts a read-back after
unconfiguring (all 19 call sites are unasserted ``finally:`` teardowns), and
residue does NOT leak between suites, because ``isis/utils/cleanup.py``
deletes the whole ISIS instance. The real cost is that the teardown silently
does nothing, not that a specific assertion was fooled.

Nor was SR-MPLS the "lone outlier": a device-verified sweep found the same
mid-path ``no`` in 21 emitted CLI lines across 9 unconfigure builders in
isis, bgp, ospf and ospfv3, all fixed together here. ``isis/configure.py``
already documented this hazard (lab-validated 2026-05-22) and it was missed.

The root enabler is neither of those: unicon's arcos ``ERROR_PATTERN``
already contains ``syntax error``, yet ``device.configure()`` returns a
buffer containing ``syntax error: element does not exist`` without raising.
Until that is addressed, every malformed arcOS config line in every arcos
API passes silently. That fix is deliberately out of scope here.
"""

import unittest
from unittest.mock import MagicMock

from genie.libs.sdk.apis.arcos.isis.configure import (
    configure_isis_micro_loop_avoidance_sr_mpls,
    unconfigure_isis_micro_loop_avoidance_sr_mpls,
    unconfigure_isis_micro_loop_avoidance_srv6,
    unconfigure_isis_micro_loop_avoidance_rib_update_delay,
)


def _pushed(device):
    """The config lines handed to device.configure()."""
    args = device.configure.call_args[0][0]
    return args if isinstance(args, list) else [args]


class TestMlaSrMplsUnconfigureCli(unittest.TestCase):

    def setUp(self):
        self.device = MagicMock()
        self.device.name = "rtr1"

    # ---- the defect ------------------------------------------------------

    def test_no_leads_the_path(self):
        unconfigure_isis_micro_loop_avoidance_sr_mpls(self.device, af="IPV4")
        line = [l for l in _pushed(self.device) if "micro-loop-avoidance" in l][0]
        self.assertTrue(
            line.startswith("no "),
            f"`no` must lead the whole path; arcOS rejects it mid-path. Got: {line!r}",
        )

    def test_the_rejected_mid_path_form_is_never_emitted(self):
        """Pins the exact string the device rejected, for both AFs."""
        for af in ("IPV4", "IPV6"):
            self.device.reset_mock()
            unconfigure_isis_micro_loop_avoidance_sr_mpls(self.device, af=af)
            for line in _pushed(self.device):
                self.assertNotIn(
                    f"global af {af} UNICAST no micro-loop-avoidance",
                    line,
                    "this is the form arcOS rejects with "
                    "'syntax error: element does not exist'",
                )

    def test_exact_line_for_each_af(self):
        for af in ("IPV4", "IPV6"):
            self.device.reset_mock()
            unconfigure_isis_micro_loop_avoidance_sr_mpls(self.device, af=af)
            self.assertIn(
                f"no global af {af} UNICAST micro-loop-avoidance sr-mpls-enabled",
                _pushed(self.device),
            )

    # ---- the configure twin must NOT grow a `no` -------------------------

    def test_configure_does_not_lead_with_no(self):
        """Guards the fix from being applied to the wrong builder."""
        configure_isis_micro_loop_avoidance_sr_mpls(self.device, af="IPV4")
        line = [l for l in _pushed(self.device) if "micro-loop-avoidance" in l][0]
        self.assertFalse(line.startswith("no "))
        self.assertIn("sr-mpls-enabled true", line)

    # ---- cross-builder parity -------------------------------------------

    def test_all_mla_unconfigure_builders_lead_with_no(self):
        """The invariant that was violated, asserted across the family.

        Driving each builder rather than pattern-matching source, so a
        reworded log line or a reflow cannot make this gate vacuous --
        and asserting each one actually emitted a line, so a builder
        that goes silent cannot pass by inspecting nothing.
        """
        offenders, silent = [], []
        for label, call in (
            ("sr_mpls IPV4",
             lambda d: unconfigure_isis_micro_loop_avoidance_sr_mpls(d, af="IPV4")),
            ("sr_mpls IPV6",
             lambda d: unconfigure_isis_micro_loop_avoidance_sr_mpls(d, af="IPV6")),
            ("srv6", unconfigure_isis_micro_loop_avoidance_srv6),
            ("rib_update_delay",
             unconfigure_isis_micro_loop_avoidance_rib_update_delay),
        ):
            dev = MagicMock()
            dev.name = "rtr1"
            call(dev)
            matched = [l for l in _pushed(dev) if "micro-loop-avoidance" in l]
            # Without this, a builder that stops emitting the line at all
            # leaves `offenders` empty and the gate passes having inspected
            # nothing -- measured: that mutation survived the first version.
            if not matched:
                silent.append(label)
            for line in matched:
                if not line.startswith("no "):
                    offenders.append(f"{label}: {line!r}")
        self.assertEqual(
            silent, [],
            f"these emitted no micro-loop-avoidance line at all, so the "
            f"parity check inspected nothing for them: {silent}",
        )
        self.assertEqual(
            offenders, [],
            f"these emit `no` mid-path, which arcOS rejects: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
