"""Unit tests for ArcOS MPLS reserved-label-block APIs.

Covers ``configure_mpls_reserved_label_block``'s post-commit read-back, which
exists because of a specific arcOS behaviour: an unknown ``usage`` enum token
is rejected as ``syntax error: unknown element`` but the surrounding block
still commits, so the block ends up on the box with lower-bound, upper-bound,
protocol-identifier, protocol-name -- and NO usage leaf. ``device.configure()``
raises nothing, so without a read-back the API reports success on a block that
was never fully applied.

Seen in production: nightly build 1541 (isis_mla_sr_mpls_flexalgo_ipv4) pushed
``usage SRGB`` to all six routers, every leaf was rejected, and the suite still
reported 34/34 PASSED.
"""

import unittest
from unittest.mock import Mock, patch

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.segment_routing.configure import (
    configure_mpls_reserved_label_block,
    unconfigure_mpls_reserved_label_block,
)

# A block as the parser yields it once every leaf landed. Note the BARE usage
# token: the parser namespace-strips via strip_namespace(), so a parsed block
# never carries the `arcos-mpls:` prefix arcOS puts on the wire.
GOOD_BLOCK = {
    "local-id": "SRGB_BLOCK",
    "lower-bound": 16000,
    "upper-bound": 23999,
    "usage": "ISIS_SRGB",
    "protocol-identifier": "ISIS",
    "protocol-name": "default",
}

# The same block after arcOS rejected `usage SRGB` -- note the absent usage
# leaf. This is the exact shape build 1541 left on all six routers.
BLOCK_MISSING_USAGE = {k: v for k, v in GOOD_BLOCK.items() if k != "usage"}

# Patched at its DEFINITION site, not on `configure`: the read-back imports
# the getter inside the function (parsers stay out of configure.py by
# convention, and genie.libs.parser is not an sdk-pkg install_requires), so
# `configure` has no such module attribute to patch.
_GETTER = ("genie.libs.sdk.apis.arcos.segment_routing.get."
           "get_mpls_reserved_label_block")

# Keep the polling tests from actually sleeping.
FAST = {"verify_max_time": 0.05, "verify_check_interval": 0.01}


class TestConfigureReservedLabelBlockReadBack(unittest.TestCase):
    """The read-back must fail a block whose leaves did not land."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _configure(self, usage="ISIS_SRGB", **kw):
        return configure_mpls_reserved_label_block(
            self.device,
            block_id="SRGB_BLOCK",
            lower_bound=16000,
            upper_bound=23999,
            usage=usage,
            protocol_identifier="ISIS",
            protocol_name="default",
            **kw
        )

    def test_emits_expected_cli(self):
        with patch(_GETTER, return_value=GOOD_BLOCK):
            self._configure()
        args = self.device.configure.call_args[0][0]
        self.assertIn("network-instance default", args)
        self.assertIn("mpls global reserved-label-block SRGB_BLOCK", args)
        self.assertIn("lower-bound 16000", args)
        self.assertIn("upper-bound 23999", args)
        self.assertIn("usage ISIS_SRGB", args)
        self.assertIn("protocol-identifier ISIS", args)
        self.assertIn("protocol-name default", args)

    def test_good_block_passes_read_back(self):
        with patch(_GETTER, return_value=GOOD_BLOCK) as getter:
            self._configure()
        getter.assert_called_once()

    # ---- the build-1541 defect -------------------------------------------

    def test_missing_usage_leaf_raises(self):
        """Block present, usage rejected -- what build 1541 shipped."""
        with patch(_GETTER, return_value=BLOCK_MISSING_USAGE):
            with self.assertRaises(SubCommandFailure) as ctx:
                self._configure(usage="SRGB")
        msg = str(ctx.exception)
        self.assertIn("SRGB_BLOCK", msg)
        self.assertIn("usage", msg)
        self.assertIn("rtr1", msg)
        self.assertIn("<leaf absent>", msg)

    def test_mismatched_usage_raises(self):
        with patch(_GETTER, return_value=dict(GOOD_BLOCK, usage="ISIS_SRLB")):
            with self.assertRaises(SubCommandFailure):
                self._configure(usage="ISIS_SRGB")

    def test_namespace_qualified_usage_accepted(self):
        """Defensive only: the parser already strips via strip_namespace(), so
        a parsed block carries the bare token. This pins the belt-and-braces
        split for a caller feeding in a raw, unstripped dict."""
        with patch(_GETTER,
                   return_value=dict(GOOD_BLOCK,
                                     usage="arcos-mpls:ISIS_SRGB")):
            self._configure(usage="ISIS_SRGB")

    def test_mismatched_bounds_raise(self):
        bad = dict(GOOD_BLOCK, **{"upper-bound": 20000})
        with patch(_GETTER, return_value=bad):
            with self.assertRaises(SubCommandFailure):
                self._configure()

    # ---- every other enum leaf is droppable the same way ------------------

    def test_wrong_protocol_identifier_raises(self):
        with patch(_GETTER,
                   return_value=dict(GOOD_BLOCK,
                                     **{"protocol-identifier": "OSPF"})):
            with self.assertRaises(SubCommandFailure) as ctx:
                self._configure()
        self.assertIn("protocol-identifier", str(ctx.exception))

    def test_absent_protocol_name_leaf_raises(self):
        block = {k: v for k, v in GOOD_BLOCK.items() if k != "protocol-name"}
        with patch(_GETTER, return_value=block):
            with self.assertRaises(SubCommandFailure) as ctx:
                self._configure()
        msg = str(ctx.exception)
        self.assertIn("protocol-name", msg)
        self.assertIn("<leaf absent>", msg)

    def test_protocol_name_unchecked_when_not_sent(self):
        """protocol_name is optional; absent-and-not-sent is not a mismatch."""
        block = {k: v for k, v in GOOD_BLOCK.items() if k != "protocol-name"}
        with patch(_GETTER, return_value=block):
            configure_mpls_reserved_label_block(
                self.device, block_id="SRGB_BLOCK", lower_bound=16000,
                upper_bound=23999, usage="ISIS_SRGB",
                protocol_identifier="ISIS",
            )

    # ---- fail-closed on an unreadable read -------------------------------

    def test_unreadable_block_raises(self):
        """Fails CLOSED -- the point is not to pass when we cannot see.

        An empty read cannot be told apart from an unreadable one: the parser
        swallows its own errors, so "no blocks", a parse failure, and a
        platform without `| display json` all arrive as {}. Passing here would
        reproduce precisely the silent-pass this check exists to catch. A
        false red breaks every suite at once and is diagnosed in minutes; a
        false green is the original bug.
        """
        with patch(_GETTER, return_value=None):
            with self.assertRaises(SubCommandFailure) as ctx:
                self._configure(**FAST)
        msg = str(ctx.exception)
        self.assertIn("could not be read back", msg)
        # The message must name the escape hatch, or an operator on a platform
        # without the read path has no way forward but to revert the API.
        self.assertIn("verify=False", msg)

    def test_read_exception_is_swallowed_then_raises(self):
        with patch(_GETTER, side_effect=OSError("transport gone")):
            with self.assertRaises(SubCommandFailure):
                self._configure(**FAST)

    def test_read_back_polls_until_the_datastore_catches_up(self):
        """The running-config read can lag the commit that just returned."""
        with patch(_GETTER,
                   side_effect=[None, None, GOOD_BLOCK]) as getter:
            self._configure(verify_max_time=5, verify_check_interval=0.01)
        self.assertEqual(getter.call_count, 3)

    def test_read_back_can_be_disabled(self):
        with patch(_GETTER) as getter:
            self._configure(usage="SRGB", verify=False)
        getter.assert_not_called()

    # ---- plumbing ---------------------------------------------------------

    def test_network_instance_is_threaded_to_the_read_back(self):
        """`network_instance` in the public signature, `ni` in get.py."""
        with patch(_GETTER, return_value=GOOD_BLOCK) as getter:
            self._configure(network_instance="vrf-red")
        self.assertEqual(getter.call_args.kwargs["ni"], "vrf-red")

    def test_configure_failure_still_raises_before_read_back(self):
        self.device.configure.side_effect = SubCommandFailure("nope")
        with patch(_GETTER) as getter:
            with self.assertRaises(SubCommandFailure):
                self._configure()
        getter.assert_not_called()


class TestUnconfigureReservedLabelBlockReadBack(unittest.TestCase):
    """Removal is the easy direction: an empty read IS the success case."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_absent_after_removal_passes(self):
        with patch(_GETTER, return_value=None):
            unconfigure_mpls_reserved_label_block(self.device, "SRGB_BLOCK")

    def test_still_present_after_removal_raises(self):
        with patch(_GETTER, return_value=GOOD_BLOCK):
            with self.assertRaises(SubCommandFailure) as ctx:
                unconfigure_mpls_reserved_label_block(
                    self.device, "SRGB_BLOCK")
        self.assertIn("still present", str(ctx.exception))

    def test_unreadable_after_removal_passes(self):
        """No ambiguity to resolve here -- unreadable and gone look alike, and
        both are consistent with a successful removal."""
        with patch(_GETTER, side_effect=OSError("transport gone")):
            unconfigure_mpls_reserved_label_block(self.device, "SRGB_BLOCK")

    def test_removal_read_back_can_be_disabled(self):
        with patch(_GETTER) as getter:
            unconfigure_mpls_reserved_label_block(
                self.device, "SRGB_BLOCK", verify=False)
        getter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
