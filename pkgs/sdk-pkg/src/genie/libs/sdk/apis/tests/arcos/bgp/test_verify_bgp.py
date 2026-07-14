#!/usr/bin/env python3
"""Unit tests for arcOS BGP verify APIs.

Verify helpers wrap the get helpers in a Timeout loop; positive cases return on
the first iteration, negatives use max_time=0 to fast-fail. The underlying
parser (ShowBgpNeighbor) is patched to drive canned output.
"""

import unittest
from unittest.mock import patch, Mock

from genie.libs.sdk.apis.arcos.bgp.verify import (
    verify_bgp_neighbor_present,
    verify_bgp_neighbor_not_present,
)

NB = "genie.libs.parser.arcos.show_bgp.ShowBgpNeighbor"
NEIGHBORS = {
    "neighbors": {
        "10.0.0.2": {"state": "ESTABLISHED"},
    }
}


class TestVerifyBgp(unittest.TestCase):
    @patch(NB)
    def test_neighbor_present(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertTrue(verify_bgp_neighbor_present(Mock(), "10.0.0.2"))

    @patch(NB)
    def test_neighbor_present_false_fast_fail(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertFalse(
            verify_bgp_neighbor_present(Mock(), "9.9.9.9", max_time=0)
        )

    @patch(NB)
    def test_neighbor_not_present_true(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertTrue(verify_bgp_neighbor_not_present(Mock(), "9.9.9.9"))

    @patch(NB)
    def test_neighbor_not_present_false_fast_fail(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertFalse(
            verify_bgp_neighbor_not_present(Mock(), "10.0.0.2", max_time=0)
        )


if __name__ == "__main__":
    unittest.main()
