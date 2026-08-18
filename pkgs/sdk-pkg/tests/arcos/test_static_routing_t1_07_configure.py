"""Unit tests for ArcOS static-routing configure APIs added by batch T1-07.

Source: ``arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md``.
Proposal: ``orchestrator/proposals/approved/static_api_t1_07_route_attrs.md``.

Lab-verified on rtr1 2026-08-17. Three commit-time-only constraints were found
and are documented on the functions; they cannot be asserted here because they
only surface on a real commit.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.static_routing.configure import (
    configure_static_route_attributes, unconfigure_static_route_attributes,
    configure_static_route_nexthop, unconfigure_static_route_nexthop,
)

PFX = "10.9.9.0/24"
CTX = ["network-instance default", "protocol STATIC default",
       f"static-route {PFX}"]


class Base(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestRouteAttributes(Base):

    def test_all_three(self):
        configure_static_route_attributes(
            self.device, prefix=PFX, description="to-DC",
            preference=10, local_label_index=100)
        self.assertEqual(self.emitted(), CTX + [
            'description "to-DC"', "preference 10", "local-label-index 100", "!"])

    def test_description_is_quoted(self):
        """A description with spaces must survive as one CLI token."""
        configure_static_route_attributes(
            self.device, prefix=PFX, description="to the DC")
        self.assertIn('description "to the DC"', self.emitted())

    def test_requires_one_attribute(self):
        with self.assertRaises(ValueError):
            configure_static_route_attributes(self.device, prefix=PFX)
        self.device.configure.assert_not_called()

    def test_unconfigure_selected_only(self):
        unconfigure_static_route_attributes(
            self.device, prefix=PFX, preference=True)
        self.assertEqual(self.emitted(), CTX + ["no preference", "!"])

    def test_unconfigure_requires_a_selection(self):
        with self.assertRaises(ValueError):
            unconfigure_static_route_attributes(self.device, prefix=PFX)
        self.device.configure.assert_not_called()


class TestNexthop(Base):

    def test_minimal(self):
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh1", next_hop="10.1.1.2")
        self.assertEqual(
            self.emitted(), CTX + ["next-hop-index nh1", "next-hop 10.1.1.2", "!"])

    def test_full(self):
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh2", next_hop="10.1.1.3",
            interface="swp1", subinterface=0, metric=5,
            next_network_instance="vrfA", remote_label_stack=[1000, 2000])
        self.assertEqual(self.emitted(), CTX + [
            "next-hop-index nh2",
            "next-hop 10.1.1.3",
            "interface swp1",
            "subinterface 0",
            "metric 5",
            "next-network-instance-name vrfA",
            "remote-label-stack [ 1000 2000 ]",
            "!",
        ])

    def test_leaf_is_next_network_instance_NAME(self):
        """The audit row spelled it `next-network-instance`; the device leaf is
        `next-network-instance-name`."""
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh1", next_network_instance="vrfA")
        joined = " ".join(self.emitted())
        self.assertIn("next-network-instance-name vrfA", joined)

    def test_remote_label_stack_accepts_string(self):
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh1",
            remote_label_stack="1000 2000 3000")
        self.assertIn("remote-label-stack [ 1000 2000 3000 ]", self.emitted())

    def test_requires_one_attribute(self):
        with self.assertRaises(ValueError):
            configure_static_route_nexthop(
                self.device, prefix=PFX, nh_index="nh1")
        self.device.configure.assert_not_called()

    def test_ecmp_is_one_call_per_index(self):
        """ECMP is built by repeated calls; each emits exactly one index."""
        for idx in ("nh1", "nh2", "nh3"):
            with self.subTest(nh=idx):
                self.device.configure.reset_mock()
                configure_static_route_nexthop(
                    self.device, prefix=PFX, nh_index=idx, next_hop="10.1.1.2")
                indexes = [l for l in self.emitted() if l.startswith("next-hop-index")]
                self.assertEqual(indexes, [f"next-hop-index {idx}"])

    def test_unconfigure(self):
        unconfigure_static_route_nexthop(self.device, prefix=PFX, nh_index="nh2")
        self.assertEqual(self.emitted(), CTX + ["no next-hop-index nh2", "!"])


class TestCrossCutting(Base):

    ALL = [
        (configure_static_route_attributes, {"prefix": PFX, "preference": 1}),
        (unconfigure_static_route_attributes, {"prefix": PFX, "preference": True}),
        (configure_static_route_nexthop,
         {"prefix": PFX, "nh_index": "nh1", "next_hop": "10.1.1.2"}),
        (unconfigure_static_route_nexthop, {"prefix": PFX, "nh_index": "nh1"}),
    ]

    def test_custom_network_instance(self):
        for fn, kwargs in self.ALL:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, network_instance="red", **kwargs)
                self.assertEqual(self.emitted()[0], "network-instance red")

    def test_failure_propagation(self):
        for fn, kwargs in self.ALL:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("nope")
                with self.assertRaises(SubCommandFailure):
                    fn(self.device, **kwargs)

    def test_submode_shape(self):
        for fn, kwargs in self.ALL:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                cfg = self.emitted()
                self.assertEqual(cfg[:3], CTX)
                self.assertEqual(cfg[-1], "!")


if __name__ == "__main__":
    unittest.main()
