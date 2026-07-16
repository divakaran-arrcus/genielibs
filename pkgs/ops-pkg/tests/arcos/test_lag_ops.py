"""Unit tests for ArcOS LAG Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.lag.arcos.lag import Lag

MOD = "genie.libs.ops.lag.arcos.lag"

SINGLE_MEMBER_OUTPUT = {
    "interfaces": {
        "bond111": {
            "name": "bond111",
            "interval": "FAST",
            "members": {
                "ethernet-1/1": {
                    "interface": "ethernet-1/1",
                    "timeout": "SHORT",
                    "synchronization": "IN_SYNC",
                    "aggregatable": True,
                    "collecting": True,
                    "distributing": True,
                },
            },
        },
    },
}

MULTI_MEMBER_OUTPUT = {
    "interfaces": {
        "bond200": {
            "name": "bond200",
            "interval": "SLOW",
            "members": {
                "ethernet-1/1": {
                    "interface": "ethernet-1/1",
                    "timeout": "LONG",
                    "synchronization": "IN_SYNC",
                    "aggregatable": True,
                    "collecting": True,
                    "distributing": True,
                },
                "ethernet-1/2": {
                    "interface": "ethernet-1/2",
                    "timeout": "LONG",
                    "synchronization": "OUT_SYNC",
                    "aggregatable": True,
                    "collecting": False,
                    "distributing": False,
                },
                "ethernet-1/3": {
                    "interface": "ethernet-1/3",
                    "timeout": "LONG",
                    "synchronization": "IN_SYNC",
                    "aggregatable": True,
                    "collecting": True,
                    "distributing": True,
                },
            },
        },
    },
}


class TestLagOps(unittest.TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowLacpInterface")
    def test_learn_basic(self, mock_parser_cls):
        """Test learn with a single bond and one member."""
        mock_parser_cls.return_value.parse.return_value = SINGLE_MEMBER_OUTPUT

        ops = Lag(device=self.device)
        ops.learn()

        self.assertIn("interfaces", ops.info)
        bond = ops.info["interfaces"]["bond111"]

        self.assertEqual(bond["name"], "bond111")
        self.assertEqual(bond["bundle_id"], 111)
        self.assertEqual(bond["protocol"], "lacp")
        self.assertEqual(bond["oper_status"], "up")

        # Member checks
        self.assertIn("members", bond)
        mem = bond["members"]["ethernet-1/1"]
        self.assertEqual(mem["interface"], "ethernet-1/1")
        self.assertTrue(mem["bundled"])
        self.assertEqual(mem["activity"], "active")
        self.assertEqual(mem["synchronization"], "synchronized")
        self.assertTrue(mem["aggregatable"])
        self.assertTrue(mem["collecting"])
        self.assertTrue(mem["distributing"])

    @patch(f"{MOD}.ShowLacpInterface")
    def test_learn_empty(self, mock_parser_cls):
        """Parser raises exception -- info should be empty."""
        mock_parser_cls.return_value.parse.side_effect = Exception("No data")

        ops = Lag(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowLacpInterface")
    def test_learn_multiple_members(self, mock_parser_cls):
        """Test learn with one bond and multiple members (mixed state)."""
        mock_parser_cls.return_value.parse.return_value = MULTI_MEMBER_OUTPUT

        ops = Lag(device=self.device)
        ops.learn()

        self.assertIn("interfaces", ops.info)
        bond = ops.info["interfaces"]["bond200"]

        self.assertEqual(bond["name"], "bond200")
        self.assertEqual(bond["bundle_id"], 200)
        self.assertEqual(bond["protocol"], "lacp")
        # At least one member is distributing, so oper_status = up
        self.assertEqual(bond["oper_status"], "up")

        members = bond["members"]
        self.assertEqual(len(members), 3)

        # First member: fully active
        m1 = members["ethernet-1/1"]
        self.assertTrue(m1["bundled"])
        self.assertEqual(m1["activity"], "passive")
        self.assertEqual(m1["synchronization"], "synchronized")
        self.assertTrue(m1["collecting"])
        self.assertTrue(m1["distributing"])

        # Second member: out of sync, not distributing
        m2 = members["ethernet-1/2"]
        self.assertFalse(m2["bundled"])
        self.assertEqual(m2["synchronization"], "unsynchronized")
        self.assertFalse(m2["collecting"])
        self.assertFalse(m2["distributing"])

        # Third member: fully active
        m3 = members["ethernet-1/3"]
        self.assertTrue(m3["bundled"])
        self.assertTrue(m3["distributing"])

    @patch(f"{MOD}.ShowLacpInterface")
    def test_learn_empty_interfaces_dict(self, mock_parser_cls):
        """Parser returns a dict with an empty 'interfaces' key (no
        exception) -- info should remain empty."""
        mock_parser_cls.return_value.parse.return_value = {"interfaces": {}}

        ops = Lag(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowLacpInterface")
    def test_learn_no_bundle_id_suffix(self, mock_parser_cls):
        """Bond name with no trailing digits -- bundle_id should be
        omitted."""
        output = {
            "interfaces": {
                "bond-mgmt": {
                    "name": "bond-mgmt",
                    "interval": "FAST",
                },
            },
        }
        mock_parser_cls.return_value.parse.return_value = output

        ops = Lag(device=self.device)
        ops.learn()

        bond = ops.info["interfaces"]["bond-mgmt"]
        self.assertNotIn("bundle_id", bond)
        self.assertEqual(bond["protocol"], "lacp")
        # No members -> oper_status defaults to down
        self.assertEqual(bond["oper_status"], "down")
        self.assertNotIn("members", bond)

    @patch(f"{MOD}.ShowLacpInterface")
    def test_learn_no_interval_no_activity(self, mock_parser_cls):
        """Bond with no 'interval' key -- member 'activity' should be
        omitted."""
        output = {
            "interfaces": {
                "bond300": {
                    "name": "bond300",
                    "members": {
                        "ethernet-1/1": {
                            "interface": "ethernet-1/1",
                            "synchronization": "IN_SYNC",
                            "aggregatable": True,
                            "collecting": True,
                            "distributing": True,
                        },
                    },
                },
            },
        }
        mock_parser_cls.return_value.parse.return_value = output

        ops = Lag(device=self.device)
        ops.learn()

        bond = ops.info["interfaces"]["bond300"]
        mem = bond["members"]["ethernet-1/1"]
        self.assertNotIn("activity", mem)

    @patch(f"{MOD}.ShowLacpInterface")
    def test_learn_unmapped_synchronization_value(self, mock_parser_cls):
        """Synchronization values not in _SYNC_MAP fall back to
        lower-cased raw value."""
        output = {
            "interfaces": {
                "bond400": {
                    "name": "bond400",
                    "members": {
                        "ethernet-1/1": {
                            "interface": "ethernet-1/1",
                            "synchronization": "UNKNOWN_STATE",
                        },
                    },
                },
            },
        }
        mock_parser_cls.return_value.parse.return_value = output

        ops = Lag(device=self.device)
        ops.learn()

        mem = ops.info["interfaces"]["bond400"]["members"]["ethernet-1/1"]
        self.assertEqual(mem["synchronization"], "unknown_state")


if __name__ == "__main__":
    unittest.main()
