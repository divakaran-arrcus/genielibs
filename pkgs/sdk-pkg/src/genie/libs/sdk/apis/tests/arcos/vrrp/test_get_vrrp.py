#!/usr/bin/env python3
"""Unit tests for arcOS VRRP get APIs (full coverage).

get.py instantiates ShowVrrp(device=device).parse(...) directly inside the
private _parse_vrrp() helper, so ShowVrrp is patched at the get module's
import site (genie.libs.sdk.apis.arcos.vrrp.get.ShowVrrp).
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.vrrp.get import (
    get_vrrp_groups,
    get_vrrp_group,
    get_vrrp_group_mode,
    is_vrrp_group_present,
)

MOD = "genie.libs.sdk.apis.arcos.vrrp.get"

BASIC_OUTPUT = {
    "vrrp-groups": {
        "swp10:0:ipv4:172.16.1.1:10": {
            "interface": "swp10",
            "sub-id": 0,
            "af": "ipv4",
            "address": "172.16.1.1",
            "virtual-router-id": 10,
            "virtual-address": ["172.16.1.100"],
            "priority": 200,
            "preempt": True,
            "accept-mode": True,
            "advertisement-interval": 1,
            "vrrp-version": "VRRP_V3",
            "virtual-router-mode": "MASTER",
            "virtual-mac-address": "00:00:5e:00:01:0a",
        },
        "swp11:0:ipv4:172.16.2.1:11": {
            "interface": "swp11",
            "sub-id": 0,
            "af": "ipv4",
            "address": "172.16.2.1",
            "virtual-router-id": 11,
            "priority": 100,
            "virtual-router-mode": "BACKUP",
        },
    }
}


class TestGetVrrpGroups(unittest.TestCase):
    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowVrrp")
    def test_get_vrrp_groups_basic(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        result = get_vrrp_groups(self.device)
        self.assertEqual(result, BASIC_OUTPUT["vrrp-groups"])

    @patch(f"{MOD}.ShowVrrp")
    def test_get_vrrp_groups_passes_kwargs(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        get_vrrp_groups(
            self.device, interface="swp10", sub_id=0, af="ipv4",
            address="172.16.1.1",
        )
        mock_show.assert_called_once_with(device=self.device)
        mock_show.return_value.parse.assert_called_once_with(
            interface="swp10", sub_id=0, af="ipv4", address="172.16.1.1",
        )

    @patch(f"{MOD}.ShowVrrp")
    def test_get_vrrp_groups_schema_empty(self, mock_show):
        """SchemaEmptyParserError -- degrade to empty dict."""
        mock_show.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )
        result = get_vrrp_groups(self.device)
        self.assertEqual(result, {})

    @patch(f"{MOD}.ShowVrrp")
    def test_get_vrrp_groups_generic_exception(self, mock_show):
        """Any other exception -- also degrades to empty dict (logged)."""
        mock_show.return_value.parse.side_effect = Exception("boom")
        result = get_vrrp_groups(self.device)
        self.assertEqual(result, {})


class TestGetVrrpGroup(unittest.TestCase):
    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowVrrp")
    def test_get_vrrp_group_found(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        grp = get_vrrp_group(
            self.device, "swp10", 0, "ipv4", "172.16.1.1", 10,
        )
        self.assertIsNotNone(grp)
        self.assertEqual(grp["virtual-router-mode"], "MASTER")

    @patch(f"{MOD}.ShowVrrp")
    def test_get_vrrp_group_not_found(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        grp = get_vrrp_group(
            self.device, "swp99", 0, "ipv4", "172.16.9.9", 99,
        )
        self.assertIsNone(grp)

    @patch(f"{MOD}.ShowVrrp")
    def test_get_vrrp_group_empty_parser(self, mock_show):
        mock_show.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )
        grp = get_vrrp_group(
            self.device, "swp10", 0, "ipv4", "172.16.1.1", 10,
        )
        self.assertIsNone(grp)


class TestGetVrrpGroupMode(unittest.TestCase):
    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowVrrp")
    def test_mode_master(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        mode = get_vrrp_group_mode(
            self.device, "swp10", 0, "ipv4", "172.16.1.1", 10,
        )
        self.assertEqual(mode, "MASTER")

    @patch(f"{MOD}.ShowVrrp")
    def test_mode_backup(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        mode = get_vrrp_group_mode(
            self.device, "swp11", 0, "ipv4", "172.16.2.1", 11,
        )
        self.assertEqual(mode, "BACKUP")

    @patch(f"{MOD}.ShowVrrp")
    def test_mode_group_not_found(self, mock_show):
        """Group missing entirely -- returns None (grp is falsy)."""
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        mode = get_vrrp_group_mode(
            self.device, "swp99", 0, "ipv4", "172.16.9.9", 99,
        )
        self.assertIsNone(mode)

    @patch(f"{MOD}.ShowVrrp")
    def test_mode_missing_field(self, mock_show):
        """Group present but has no virtual-router-mode key."""
        output = {
            "vrrp-groups": {
                "swp12:0:ipv4:172.16.3.1:12": {
                    "interface": "swp12",
                    "sub-id": 0,
                    "af": "ipv4",
                    "address": "172.16.3.1",
                    "virtual-router-id": 12,
                }
            }
        }
        mock_show.return_value.parse.return_value = output
        mode = get_vrrp_group_mode(
            self.device, "swp12", 0, "ipv4", "172.16.3.1", 12,
        )
        self.assertIsNone(mode)


class TestIsVrrpGroupPresent(unittest.TestCase):
    def setUp(self):
        self.device = Mock()

    @patch(f"{MOD}.ShowVrrp")
    def test_present_true(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        self.assertTrue(
            is_vrrp_group_present(
                self.device, "swp10", 0, "ipv4", "172.16.1.1", 10,
            )
        )

    @patch(f"{MOD}.ShowVrrp")
    def test_present_false(self, mock_show):
        mock_show.return_value.parse.return_value = BASIC_OUTPUT
        self.assertFalse(
            is_vrrp_group_present(
                self.device, "swp99", 0, "ipv4", "172.16.9.9", 99,
            )
        )

    @patch(f"{MOD}.ShowVrrp")
    def test_present_false_when_parser_empty(self, mock_show):
        mock_show.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )
        self.assertFalse(
            is_vrrp_group_present(
                self.device, "swp10", 0, "ipv4", "172.16.1.1", 10,
            )
        )


if __name__ == "__main__":
    unittest.main()
