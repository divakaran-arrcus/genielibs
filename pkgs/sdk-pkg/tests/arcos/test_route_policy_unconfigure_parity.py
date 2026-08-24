"""Unconfigure parity for ArcOS route_policy (batch T2R-C), plus a
workspace-wide gate that stops the gap reopening in any arcos module.

Source: Div's standing rule — everything configurable must be unconfigurable.
Proposal: ``orchestrator/proposals/pending/t2r_c_route_policy_unconfigure_parity.md``.

`route_policy/configure.py` had 25 ``configure_*`` and 11 ``unconfigure_*``. This
batch adds the 14 missing inverses.

**The one rule every function here follows:** remove at the deepest SINGLE-OWNER
node, never at ``actions bgp-actions`` or ``conditions bgp-conditions``. Those
two containers are written by 8 and 4 configure functions respectively, so
removing one destroys leaves the caller never set. Verified on rtr1 2026-08-25:
a single ``no ... actions bgp-actions`` wiped three leaves owned by three
different functions (``set_aigp``, ``set_route_origin``, ``adjust_med``).
``TestNoSharedContainerRemoval`` enforces this and is the most important test in
the file.

Emissions are pinned exactly, following ``test_bgp_unconfigure_emissions.py``,
whose docstring records that a mutation sweep found 14 removal paths where a
bogus token left the whole suite green. Every expected list below was confirmed
on rtr1 by commit + running-config read-back, asserting on leaves rather than
blocks.
"""

import glob
import inspect
import os
import re
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.route_policy.configure as rp

STMT = "no routing-policy policy-definition POL1 statement 10"


class TestUnconfigureExactEmission(unittest.TestCase):
    """One exact-list assertion per new removal path."""

    #: (function name, kwargs, expected emitted list)
    CASES = [
        # --- Group A: single-leaf setters -------------------------------
        ('unconfigure_routing_policy_adjust_local_pref', {},
         [f'{STMT} actions bgp-actions adjust-local-pref', '!']),
        ('unconfigure_routing_policy_adjust_med', {},
         [f'{STMT} actions bgp-actions adjust-med', '!']),
        ('unconfigure_routing_policy_set_aigp', {},
         [f'{STMT} actions bgp-actions set-aigp', '!']),
        ('unconfigure_routing_policy_set_as_path_prepend', {},
         [f'{STMT} actions bgp-actions set-as-path-prepend', '!']),
        ('unconfigure_routing_policy_set_route_origin', {},
         [f'{STMT} actions bgp-actions set-route-origin', '!']),
        ('unconfigure_routing_policy_drop_attr', {},
         [f'{STMT} actions bgp-actions drop-attr', '!']),
        ('unconfigure_routing_policy_call_policy', {},
         [f'{STMT} conditions call-policy', '!']),
        ('unconfigure_routing_policy_match_interface', {},
         [f'{STMT} conditions match-interface', '!']),
        # --- Group B: match-set conditions (2 leaves each) --------------
        ('unconfigure_routing_policy_match_community_set', {},
         [f'{STMT} conditions bgp-conditions match-community-set', '!']),
        ('unconfigure_routing_policy_match_as_path_set', {},
         [f'{STMT} conditions bgp-conditions match-as-path-set', '!']),
        ('unconfigure_routing_policy_match_large_community_set', {},
         [f'{STMT} conditions bgp-conditions match-large-community-set', '!']),
        # --- Group C: composites ----------------------------------------
        ('unconfigure_routing_policy_set_community', {},
         [f'{STMT} actions bgp-actions set-community', '!']),
        ('unconfigure_routing_policy_bgp_conditions', {},
         [f'{STMT} conditions bgp-conditions match-ext-community-set', '!']),
        ('unconfigure_routing_policy_bgp_actions', {},
         [f'{STMT} actions bgp-actions set-local-pref',
          f'{STMT} actions bgp-actions set-med',
          f'{STMT} actions bgp-actions set-next-hop',
          f'{STMT} actions bgp-actions set-ext-community',
          '!']),
    ]

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_exact_emission(self):
        for name, kwargs, expected in self.CASES:
            with self.subTest(fn=name):
                self.device.configure.reset_mock()
                getattr(rp, name)(self.device, 'POL1', '10', **kwargs)
                self.assertEqual(
                    self.device.configure.call_args[0][0], expected)

    def test_every_new_removal_path_is_covered(self):
        """No new unconfigure may ship without an exact-emission pin."""
        src = open(rp.__file__).read()
        blk = src[src.index("Unconfigure parity (T2R-C)"):]
        shipped = set(re.findall(r"\ndef (unconfigure_\w+)\(", blk))
        pinned = {n for n, _, _ in self.CASES}
        self.assertEqual(
            shipped - pinned, set(),
            "unconfigure functions with no exact-emission pin")


class TestBgpActionsMirrorArgs(unittest.TestCase):
    """C3 is the one mirror-args inverse; its selectivity matters."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        return self.device.configure.call_args[0][0]

    def test_no_flags_clears_all_four(self):
        rp.unconfigure_routing_policy_bgp_actions(self.device, 'POL1', '10')
        self.assertEqual(len(self.emitted()), 5)  # 4 removals + '!'

    def test_single_flag_removes_only_that_subnode(self):
        rp.unconfigure_routing_policy_bgp_actions(
            self.device, 'POL1', '10', set_med=True)
        self.assertEqual(
            self.emitted(),
            [f'{STMT} actions bgp-actions set-med', '!'])

    def test_two_flags_removes_exactly_two(self):
        rp.unconfigure_routing_policy_bgp_actions(
            self.device, 'POL1', '10', set_med=True, set_next_hop=True)
        self.assertEqual(
            self.emitted(),
            [f'{STMT} actions bgp-actions set-med',
             f'{STMT} actions bgp-actions set-next-hop',
             '!'])

    def test_mirrors_the_configure_flag_names(self):
        """A mirror-args inverse is only usable if the names match."""
        cfg = set(inspect.signature(
            rp.configure_routing_policy_bgp_actions).parameters)
        unc = set(inspect.signature(
            rp.unconfigure_routing_policy_bgp_actions).parameters)
        for flag in ('set_local_pref', 'set_med', 'set_next_hop'):
            self.assertIn(flag, cfg)
            self.assertIn(flag, unc)


class TestNoSharedContainerRemoval(unittest.TestCase):
    """No emitted line may terminate at a shared container.

    ``actions bgp-actions`` is written by 8 configure functions and
    ``conditions bgp-conditions`` by 4. A ``no`` that stops at either wipes
    config owned by every other function — lab-confirmed on rtr1 2026-08-25,
    where one such line destroyed three leaves across three owners. This test
    is what keeps that from regressing in.
    """

    SHARED = ('actions bgp-actions', 'conditions bgp-conditions')

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_no_line_ends_at_a_shared_container(self):
        for name, kwargs, _ in TestUnconfigureExactEmission.CASES:
            with self.subTest(fn=name):
                self.device.configure.reset_mock()
                getattr(rp, name)(self.device, 'POL1', '10', **kwargs)
                for line in self.device.configure.call_args[0][0]:
                    for shared in self.SHARED:
                        self.assertFalse(
                            line.rstrip().endswith(shared),
                            f"{name} emits a removal ending at the shared "
                            f"container '{shared}': {line!r}")

    def test_bgp_actions_never_collapses_to_the_parent(self):
        """The tempting one-liner for C3 is the destructive one."""
        rp.unconfigure_routing_policy_bgp_actions(self.device, 'POL1', '10')
        for line in self.device.configure.call_args[0][0]:
            self.assertNotEqual(
                line, f'{STMT} actions bgp-actions',
                "C3 collapsed to the shared container")


class TestDropAttrTakesNoCodes(unittest.TestCase):
    """arcOS cannot subtract one entry from a leaf-list, and lies about it.

    Verified on rtr1 2026-08-25: with ``drop-attr [ 40 128 ]`` committed,
    ``no ... drop-attr [ 40 ]`` returned ``Commit complete.`` and removed BOTH
    codes. Reproduced naming ``[ 128 ]`` instead — same result. An
    ``attr_codes`` parameter here would therefore read as "remove this code"
    while silently removing every code, so the signature deliberately omits it.
    """

    def test_signature_has_no_attr_codes(self):
        params = inspect.signature(
            rp.unconfigure_routing_policy_drop_attr).parameters
        self.assertNotIn("attr_codes", params)
        self.assertEqual(
            list(params), ["device", "policy_name", "statement_name"])

    def test_configure_side_still_takes_codes(self):
        """The asymmetry is deliberate, not an oversight in the configure."""
        self.assertIn(
            "attr_codes",
            inspect.signature(rp.configure_routing_policy_drop_attr).parameters)


class TestCrossCuttingTriad(unittest.TestCase):
    """Applied over all 14 new functions."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_no_stray_exit(self):
        for name, kwargs, _ in TestUnconfigureExactEmission.CASES:
            with self.subTest(fn=name):
                self.device.configure.reset_mock()
                getattr(rp, name)(self.device, 'POL1', '10', **kwargs)
                for line in self.device.configure.call_args[0][0]:
                    self.assertNotEqual(line.strip(), "exit")

    def test_failure_propagates(self):
        for name, kwargs, _ in TestUnconfigureExactEmission.CASES:
            with self.subTest(fn=name):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("no")
                with self.assertRaises(SubCommandFailure):
                    getattr(rp, name)(self.device, 'POL1', '10', **kwargs)

    def test_instance_scoping_not_applicable(self):
        """``routing-policy`` is global, so no function takes an instance.

        Recorded explicitly rather than asserted vacuously: if a future
        arcOS release scopes routing-policy per network-instance, this test
        is the breadcrumb explaining why these signatures have no such param.
        """
        for name, _, _ in TestUnconfigureExactEmission.CASES:
            with self.subTest(fn=name):
                params = inspect.signature(getattr(rp, name)).parameters
                self.assertNotIn("network_instance", params)
                self.assertNotIn("protocol_instance", params)


class TestWorkspaceWideUnconfigureParity(unittest.TestCase):
    """Every ``configure_*`` in every arcos module needs an ``unconfigure_*``.

    Measured 2026-08-25 across 50 modules / 407 configure functions: 43 modules
    were already fully paired and 24 functions were unpaired, 14 of them in
    ``route_policy``. This batch closes those 14, leaving the 10 below.

    The allow-list is a visible backlog, not a rubber stamp — it is short
    enough that each entry is a reviewable decision. Shrinking it is the goal;
    adding to it should cost one deliberate line and a reason.
    """

    #: Known unpaired configure functions, outside route_policy.
    #: Each is a real gap awaiting its own batch, not a deliberate one-way API.
    ALLOWED_UNPAIRED = {
        "bgp": {
            "configure_bgp_erpl_connection_wait_time",
            "configure_bgp_med_missing_as_worst",
            "configure_bgp_multipath_as_path_relax",
            "configure_bgp_multipath_evpn_etree_ead_relax",
        },
        "fqdn_filter": {"configure_fqdn_active_policies"},
        "interface": {
            "configure_interface_subinterface_ipv4_enabled",
            "configure_interface_subinterface_ipv6_enabled",
        },
        "mpls_ttl": {"configure_mpls_ttl_propagation"},
        "ospf": {"configure_ospf_interface_auth_md5"},
        "sla": {"configure_sla_icmp_admin_state"},
    }

    #: Repo-relative path to the arcos API tree.
    #:
    #: Deliberately NOT derived from ``rp.__file__``. The venv's editable
    #: installs are shadowed by site-packages wheels, so without PYTHONPATH the
    #: imported module resolves into site-packages — and a gate that scanned
    #: *that* copy would report on a stale wheel while the repo carried a real
    #: gap. Anchoring on this test file's own location keeps the gate
    #: authoritative however the package is imported.
    ARCOS_DIR = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "src", "genie", "libs", "sdk", "apis", "arcos"))

    def test_scan_target_is_the_repo_not_site_packages(self):
        """The gate is worthless if it reads an installed copy."""
        self.assertTrue(
            os.path.isdir(self.ARCOS_DIR),
            f"arcos API tree not found at {self.ARCOS_DIR}")
        self.assertNotIn("site-packages", self.ARCOS_DIR)
        self.assertTrue(os.path.isfile(
            os.path.join(self.ARCOS_DIR, "route_policy", "configure.py")))

    def _scan(self):
        arcos_dir = self.ARCOS_DIR
        found = {}
        for path in sorted(glob.glob(os.path.join(arcos_dir, "*", "configure.py"))):
            src = open(path).read()
            cfg = set(re.findall(r"^def configure_(\w+)\(", src, re.M))
            unc = set(re.findall(r"^def unconfigure_(\w+)\(", src, re.M))
            unpaired = {f"configure_{n}" for n in (cfg - unc)}
            if unpaired:
                found[os.path.basename(os.path.dirname(path))] = unpaired
        return found

    def test_no_unexpected_unpaired_configure_functions(self):
        found = self._scan()
        unexpected = {}
        for mod, fns in found.items():
            extra = fns - self.ALLOWED_UNPAIRED.get(mod, set())
            if extra:
                unexpected[mod] = sorted(extra)
        self.assertEqual(
            unexpected, {},
            "configure_* without an unconfigure_* partner. Add the inverse, or "
            "add it to ALLOWED_UNPAIRED with a reason if it is genuinely "
            "one-way.")

    def test_route_policy_is_fully_paired(self):
        """The module this batch targets must have zero gaps."""
        self.assertNotIn("route_policy", self._scan())

    def test_allowlist_has_no_stale_entries(self):
        """A fixed gap must be removed from the allow-list.

        Without this, the list silently becomes a permanent exemption
        register and stops tracking reality.
        """
        found = self._scan()
        stale = {}
        for mod, fns in self.ALLOWED_UNPAIRED.items():
            still = fns & found.get(mod, set())
            if still != fns:
                stale[mod] = sorted(fns - still)
        self.assertEqual(
            stale, {},
            "ALLOWED_UNPAIRED lists functions that now have partners — "
            "remove them from the allow-list.")


if __name__ == "__main__":
    unittest.main()
