#!/usr/bin/env python3
"""Unit tests for arcOS Segment Routing verify APIs (full coverage).

Verify helpers wrap the segment_routing.get helpers (imported directly into
the verify module namespace) in a Timeout loop. ``Timeout(max_time=0, ...)``
never enters the poll loop at all (confirmed against
``genie.utils.timeout.Timeout``), so:

  - "found on first try" cases patch the get/is helper to return the
    desired value and call the verify function with its default
    (real, positive) max_time -- the loop body runs once and returns
    True immediately, so no actual delay occurs.
  - "exhaust timeout" cases use a small non-zero max_time/check_interval
    (0.03s / 0.01s) so the loop body actually executes (Timeout.iterate()
    is guaranteed to yield at least once for max_time > 0) before timing
    out and returning False.
"""

import unittest
from unittest.mock import patch, Mock

from genie.libs.sdk.apis.arcos.segment_routing import verify as sr_verify
from genie.libs.sdk.apis.arcos.segment_routing.verify import (
    verify_srv6_locator_present,
    verify_srv6_locator_not_present,
    verify_srms_mapping_present,
    verify_srms_mapping_not_present,
    verify_srv6_encap_source_address,
    verify_srv6_locator_count,
    verify_srv6_locator_algorithm,
    verify_srv6_locator_micro_segment_enabled,
    verify_srv6_local_sid_present,
    verify_srv6_local_sid_behavior,
    verify_mpls_reserved_label_block,
)

MOD = "genie.libs.sdk.apis.arcos.segment_routing.verify"

FAST_FAIL = {"max_time": 0.03, "check_interval": 0.01}


class TestVerifySrv6LocatorPresent(unittest.TestCase):
    """verify_srv6_locator_present / verify_srv6_locator_not_present"""

    @patch(f"{MOD}.is_srv6_locator_present", return_value=True)
    def test_present_found_first_try(self, mock_is):
        self.assertTrue(verify_srv6_locator_present(object(), "loc1"))

    @patch(f"{MOD}.is_srv6_locator_present", return_value=False)
    def test_present_exhaust_timeout(self, mock_is):
        self.assertFalse(
            verify_srv6_locator_present(object(), "loc1", **FAST_FAIL)
        )
        mock_is.assert_called()

    @patch(f"{MOD}.is_srv6_locator_present", side_effect=Exception("boom"))
    def test_present_exception_exhaust_timeout(self, mock_is):
        self.assertFalse(
            verify_srv6_locator_present(object(), "loc1", **FAST_FAIL)
        )

    @patch(f"{MOD}.is_srv6_locator_present", return_value=False)
    def test_not_present_found_first_try(self, mock_is):
        self.assertTrue(verify_srv6_locator_not_present(object(), "loc1"))

    @patch(f"{MOD}.is_srv6_locator_present", return_value=True)
    def test_not_present_exhaust_timeout(self, mock_is):
        self.assertFalse(
            verify_srv6_locator_not_present(object(), "loc1", **FAST_FAIL)
        )
        mock_is.assert_called()

    @patch(f"{MOD}.is_srv6_locator_present", side_effect=Exception("boom"))
    def test_not_present_exception_exhaust_timeout(self, mock_is):
        self.assertFalse(
            verify_srv6_locator_not_present(object(), "loc1", **FAST_FAIL)
        )


class TestVerifySrmsMappingPresent(unittest.TestCase):
    """verify_srms_mapping_present / verify_srms_mapping_not_present"""

    @patch(f"{MOD}.is_srms_mapping_present", return_value=True)
    def test_present_found_first_try(self, mock_is):
        self.assertTrue(verify_srms_mapping_present(object(), "map1"))

    @patch(f"{MOD}.is_srms_mapping_present", return_value=False)
    def test_present_exhaust_timeout(self, mock_is):
        self.assertFalse(
            verify_srms_mapping_present(object(), "map1", **FAST_FAIL)
        )
        mock_is.assert_called()

    @patch(f"{MOD}.is_srms_mapping_present", return_value=False)
    def test_not_present_found_first_try(self, mock_is):
        self.assertTrue(verify_srms_mapping_not_present(object(), "map1"))

    @patch(f"{MOD}.is_srms_mapping_present", return_value=True)
    def test_not_present_exhaust_timeout(self, mock_is):
        self.assertFalse(
            verify_srms_mapping_not_present(object(), "map1", **FAST_FAIL)
        )
        mock_is.assert_called()


class TestVerifySrv6EncapSourceAddress(unittest.TestCase):
    """verify_srv6_encap_source_address"""

    @patch(f"{MOD}.get_srv6_encap_source_address", return_value="2001:db8::1")
    def test_match_found_first_try(self, mock_get):
        self.assertTrue(
            verify_srv6_encap_source_address(object(), "2001:db8::1")
        )

    @patch(f"{MOD}.get_srv6_encap_source_address", return_value="2001:db8::9")
    def test_mismatch_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_encap_source_address(
                object(), "2001:db8::1", **FAST_FAIL
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_srv6_encap_source_address", return_value=None)
    def test_none_actual_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_encap_source_address(
                object(), "2001:db8::1", **FAST_FAIL
            )
        )


class TestVerifySrv6LocatorCount(unittest.TestCase):
    """verify_srv6_locator_count"""

    @patch(f"{MOD}.get_srv6_locator_count", return_value=2)
    def test_match_found_first_try(self, mock_get):
        self.assertTrue(verify_srv6_locator_count(object(), 2))

    @patch(f"{MOD}.get_srv6_locator_count", return_value=1)
    def test_mismatch_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_locator_count(object(), 2, **FAST_FAIL)
        )
        mock_get.assert_called()


class TestVerifySrv6LocatorAlgorithm(unittest.TestCase):
    """verify_srv6_locator_algorithm"""

    @patch(f"{MOD}.get_srv6_locator_algorithm", return_value=128)
    def test_match_found_first_try(self, mock_get):
        self.assertTrue(
            verify_srv6_locator_algorithm(object(), "loc1", 128)
        )

    @patch(f"{MOD}.get_srv6_locator_algorithm", return_value=None)
    def test_none_actual_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_locator_algorithm(
                object(), "loc1", 128, **FAST_FAIL
            )
        )

    @patch(f"{MOD}.get_srv6_locator_algorithm", return_value=99)
    def test_mismatch_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_locator_algorithm(
                object(), "loc1", 128, **FAST_FAIL
            )
        )
        mock_get.assert_called()


class TestVerifySrv6LocatorMicroSegmentEnabled(unittest.TestCase):
    """verify_srv6_locator_micro_segment_enabled"""

    @patch(f"{MOD}.get_srv6_locator_micro_segment_enabled", return_value=True)
    def test_match_found_first_try(self, mock_get):
        self.assertTrue(
            verify_srv6_locator_micro_segment_enabled(
                object(), "loc1", True
            )
        )

    @patch(f"{MOD}.get_srv6_locator_micro_segment_enabled", return_value=False)
    def test_mismatch_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_locator_micro_segment_enabled(
                object(), "loc1", True, **FAST_FAIL
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_srv6_locator_micro_segment_enabled", return_value=None)
    def test_none_actual_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_locator_micro_segment_enabled(
                object(), "loc1", True, **FAST_FAIL
            )
        )


class TestVerifySrv6LocalSidPresent(unittest.TestCase):
    """verify_srv6_local_sid_present"""

    SIDS = {
        "fcbb:bb00:1:1::/64": {
            "behavior": "END_PSP_USD", "locator_name": "loc1",
        },
        "fcbb:bb00:2:1::/64": {
            "behavior": "END_X", "locator_name": "loc2",
        },
    }

    @patch(f"{MOD}.get_srv6_local_sids")
    def test_present_match_by_sid_found_first_try(self, mock_get):
        mock_get.return_value = self.SIDS
        self.assertTrue(
            verify_srv6_local_sid_present(
                object(), sid="fcbb:bb00:1:1::/64"
            )
        )

    @patch(f"{MOD}.get_srv6_local_sids")
    def test_present_match_by_locator_and_behavior(self, mock_get):
        mock_get.return_value = self.SIDS
        self.assertTrue(
            verify_srv6_local_sid_present(
                object(), locator_name="loc2", behavior="END_X"
            )
        )

    @patch(f"{MOD}.get_srv6_local_sids")
    def test_not_present_exhaust_timeout(self, mock_get):
        mock_get.return_value = self.SIDS
        self.assertFalse(
            verify_srv6_local_sid_present(
                object(), sid="fcbb:bb00:9:9::/64", **FAST_FAIL
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_srv6_local_sids")
    def test_not_present_filter_mismatch_exhaust_timeout(self, mock_get):
        mock_get.return_value = self.SIDS
        self.assertFalse(
            verify_srv6_local_sid_present(
                object(), locator_name="loc1", behavior="END_X", **FAST_FAIL
            )
        )

    @patch(f"{MOD}.get_srv6_local_sids", side_effect=Exception("boom"))
    def test_exception_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_local_sid_present(
                object(), sid="fcbb:bb00:1:1::/64", **FAST_FAIL
            )
        )


class TestVerifySrv6LocalSidBehavior(unittest.TestCase):
    """verify_srv6_local_sid_behavior"""

    @patch(f"{MOD}.get_srv6_local_sid_behavior", return_value="END_PSP_USD")
    def test_match_found_first_try(self, mock_get):
        self.assertTrue(
            verify_srv6_local_sid_behavior(
                object(), "fcbb:bb00:1:1::/64", "END_PSP_USD"
            )
        )

    @patch(f"{MOD}.get_srv6_local_sid_behavior", return_value="END_X")
    def test_mismatch_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_local_sid_behavior(
                object(), "fcbb:bb00:1:1::/64", "END_PSP_USD", **FAST_FAIL
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_srv6_local_sid_behavior", return_value=None)
    def test_none_actual_exhaust_timeout(self, mock_get):
        self.assertFalse(
            verify_srv6_local_sid_behavior(
                object(), "fcbb:bb00:9:9::/64", "END_PSP_USD", **FAST_FAIL
            )
        )



GOOD_BLOCK = {
    "local-id": "SRGB_BLOCK",
    "lower-bound": 16000,
    "upper-bound": 23999,
    # arcOS renders the enum namespace-qualified; callers pass the bare token.
    "usage": "arcos-mpls:ISIS_SRGB",
    "protocol-identifier": "ISIS",
    "protocol-name": "default",
}

# The same block after arcOS refused `usage SRGB`: every other leaf landed and
# the usage leaf is simply gone. This is the state nightly build 1541 left on
# six routers while reporting 34/34 PASSED.
BLOCK_MISSING_USAGE = {k: v for k, v in GOOD_BLOCK.items() if k != "usage"}


class TestVerifyMplsReservedLabelBlock(unittest.TestCase):
    """verify_mpls_reserved_label_block

    Unlike its siblings above, this one logs ``device.name``, so a bare
    ``self.device`` will not do.
    """

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch(f"{MOD}.get_mpls_reserved_label_block", return_value=GOOD_BLOCK)
    def test_presence_only(self, mock_get):
        self.assertTrue(verify_mpls_reserved_label_block(self.device, "SRGB_BLOCK"))

    @patch(f"{MOD}.get_mpls_reserved_label_block", return_value=GOOD_BLOCK)
    def test_all_leaves_match(self, mock_get):
        self.assertTrue(verify_mpls_reserved_label_block(
            self.device, "SRGB_BLOCK", lower_bound=16000, upper_bound=23999,
            usage="ISIS_SRGB"))

    @patch(f"{MOD}.get_mpls_reserved_label_block", return_value=GOOD_BLOCK)
    def test_usage_comparison_strips_yang_prefix(self, mock_get):
        """`arcos-mpls:ISIS_SRGB` must compare equal to `ISIS_SRGB`."""
        self.assertTrue(verify_mpls_reserved_label_block(
            self.device, "SRGB_BLOCK", usage="ISIS_SRGB"))

    @patch(f"{MOD}.get_mpls_reserved_label_block",
           return_value=BLOCK_MISSING_USAGE)
    def test_absent_usage_leaf_fails(self, mock_get):
        self.assertFalse(verify_mpls_reserved_label_block(
            self.device, "SRGB_BLOCK", usage="ISIS_SRGB", **FAST_FAIL))

    @patch(f"{MOD}.get_mpls_reserved_label_block",
           return_value=BLOCK_MISSING_USAGE)
    def test_absent_usage_leaf_still_passes_presence_check(self, mock_get):
        """Presence is not the same question as correctness."""
        self.assertTrue(verify_mpls_reserved_label_block(self.device, "SRGB_BLOCK"))

    @patch(f"{MOD}.get_mpls_reserved_label_block", return_value=GOOD_BLOCK)
    def test_wrong_bound_fails(self, mock_get):
        self.assertFalse(verify_mpls_reserved_label_block(
            self.device, "SRGB_BLOCK", upper_bound=20000, **FAST_FAIL))

    @patch(f"{MOD}.get_mpls_reserved_label_block", return_value=None)
    def test_absent_block_exhausts_timeout(self, mock_get):
        self.assertFalse(verify_mpls_reserved_label_block(
            self.device, "SRGB_BLOCK", **FAST_FAIL))
        mock_get.assert_called()

    @patch(f"{MOD}.get_mpls_reserved_label_block",
           side_effect=Exception("boom"))
    def test_read_error_exhausts_timeout(self, mock_get):
        self.assertFalse(verify_mpls_reserved_label_block(
            self.device, "SRGB_BLOCK", **FAST_FAIL))


class TestSegmentRoutingVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    segment_routing/verify.py must be referenced by name somewhere in this
    test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sr_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sr_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Segment Routing verify functions: {missing}")

        print(
            f"\nSegment Routing verify coverage: {len(names)} functions, "
            f"0 missing"
        )


if __name__ == "__main__":
    unittest.main()
