"""Unit tests for ArcOS MPLS reserved-label-block APIs.

Covers ``configure_mpls_reserved_label_block``'s post-commit read-back, which
exists because of a specific arcOS behaviour: an unknown ``usage`` enum token is
rejected as ``syntax error: unknown element`` but the surrounding block still
commits, so the block ends up on the box with lower-bound, upper-bound,
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
)

# A block as the device renders it once every leaf landed. arcOS namespace-
# qualifies the usage enum; the parser strips the prefix on read.
GOOD_BLOCK = {
    "local-id": "SRGB_BLOCK",
    "lower-bound": 16000,
    "upper-bound": 23999,
    "usage": "ISIS_SRGB",
    "protocol-identifier": "ISIS",
    "protocol-name": "default",
}

# The same block after arcOS rejected `usage SRGB` -- note the absent usage leaf.
# This is the exact shape build 1541 left on all six routers.
BLOCK_MISSING_USAGE = {
    "local-id": "SRGB_BLOCK",
    "lower-bound": 16000,
    "upper-bound": 23999,
    "protocol-identifier": "ISIS",
    "protocol-name": "default",
}

_GETTER = ("genie.libs.sdk.apis.arcos.segment_routing.configure."
           "get_mpls_reserved_label_block")


class TestConfigureReservedLabelBlockReadBack(unittest.TestCase):
    """The read-back must fail a block whose usage leaf did not land."""

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

    def test_missing_usage_leaf_raises(self):
        """The build-1541 failure: block present, usage silently rejected."""
        with patch(_GETTER, return_value=BLOCK_MISSING_USAGE):
            with self.assertRaises(SubCommandFailure) as ctx:
                self._configure(usage="SRGB")
        msg = str(ctx.exception)
        self.assertIn("SRGB_BLOCK", msg)
        self.assertIn("usage", msg)
        self.assertIn("rtr1", msg)

    def test_mismatched_usage_raises(self):
        """A block carrying the wrong usage token is a failure, not a pass."""
        with patch(_GETTER, return_value=dict(GOOD_BLOCK, usage="ISIS_SRLB")):
            with self.assertRaises(SubCommandFailure):
                self._configure(usage="ISIS_SRGB")

    def test_namespace_qualified_usage_accepted(self):
        """arcOS renders `arcos-mpls:ISIS_SRGB`; that must compare equal."""
        with patch(_GETTER,
                   return_value=dict(GOOD_BLOCK, usage="arcos-mpls:ISIS_SRGB")):
            self._configure(usage="ISIS_SRGB")

    def test_mismatched_bounds_raise(self):
        with patch(_GETTER, return_value=dict(GOOD_BLOCK, **{"upper-bound": 20000})):
            with self.assertRaises(SubCommandFailure):
                self._configure()

    def test_absent_block_warns_but_does_not_raise(self):
        """A None read-back cannot distinguish 'absent' from 'unparseable'.

        ``get_mpls_reserved_label_blocks`` is defensive by design -- it returns
        ``{}`` on SchemaEmptyParserError AND on any parse failure. Raising here
        would turn a broken parser or an unsupported platform into a false red
        on a block that committed fine, so this path warns only. The leaf-level
        checks above are the ones with real evidence behind them.
        """
        with patch(_GETTER, return_value=None):
            self._configure()   # must not raise

    def test_read_back_can_be_disabled(self):
        with patch(_GETTER) as getter:
            self._configure(usage="SRGB", verify=False)
        getter.assert_not_called()

    def test_configure_failure_still_raises_before_read_back(self):
        self.device.configure.side_effect = SubCommandFailure("nope")
        with patch(_GETTER) as getter:
            with self.assertRaises(SubCommandFailure):
                self._configure()
        getter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
