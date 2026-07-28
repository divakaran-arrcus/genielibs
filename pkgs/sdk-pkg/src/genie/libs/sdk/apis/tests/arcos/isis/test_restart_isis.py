#!/usr/bin/env python3
"""Unit test for the arcOS ISIS restart action helper (restart_isis_instance)."""
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure
from genie.libs.sdk.apis.arcos.isis.configure import restart_isis_instance


class TestRestartIsisInstance(unittest.TestCase):
    def _dev(self, **kw):
        d = Mock()
        d.name = "rtr1"
        d.execute = Mock(**kw)
        return d

    def test_restart_default_instance(self):
        d = self._dev(return_value="")
        restart_isis_instance(d)
        self.assertEqual(d.execute.call_args[0][0], "restart isis default default")
        # restart prompt is auto-confirmed via a reply Dialog
        self.assertIn("reply", d.execute.call_args.kwargs)

    def test_restart_named_instance(self):
        d = self._dev(return_value="")
        restart_isis_instance(d, network_instance="red", protocol_instance="isis1")
        self.assertEqual(d.execute.call_args[0][0], "restart isis red isis1")

    def test_restart_failure_reraises(self):
        d = self._dev(side_effect=SubCommandFailure("boom"))
        with self.assertRaises(SubCommandFailure):
            restart_isis_instance(d)


if __name__ == "__main__":
    unittest.main()
