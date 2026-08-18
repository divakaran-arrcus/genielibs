"""Unit tests for the four T1-07 knobs completed on 2026-08-18.

Closes the batch left PARTIAL on 2026-08-17. Sources:
``arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md``;
proposal ``orchestrator/proposals/approved/static_api_t1_07_route_attrs.md``.

Three of the four turned out to live outside `static_routing/`, which is why the
first pass could not find them:

  * `system rib <AF> rnh-resolution-*`  -> `apis.arcos.system.configure` (NEW pair)
  * micro-BFD                            -> `apis.arcos.interface.configure`
                                            (ALREADY existed; extended with `profile`)
  * static-route BFD                     -> `apis.arcos.static_routing.configure` (NEW)

The fourth, `mpls-label-ranges`, is NOT ON THIS BUILD and has no API.
All emitted lists lab-verified on rtr1 2026-08-18 in both directions.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.static_routing.configure import (
    configure_static_route_nexthop,
    configure_static_route_bfd_profile, unconfigure_static_route_bfd_profile,
)
from genie.libs.sdk.apis.arcos.system.configure import (
    SYSTEM_RIB_AFS,
    configure_system_rib_rnh_resolution, unconfigure_system_rib_rnh_resolution,
)
from genie.libs.sdk.apis.arcos.interface.configure import (
    configure_interface_bfd_micro,
)

PFX = "192.168.100.1/32"
CTX = ["network-instance default", "protocol STATIC default",
       f"static-route {PFX}"]


class Base(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestStaticRouteBfdProfile(Base):

    def test_configure(self):
        configure_static_route_bfd_profile(
            self.device, prefix=PFX, profile="GLOBAL")
        self.assertEqual(self.emitted(), CTX + ["bfd profile GLOBAL", "!"])

    def test_unconfigure(self):
        unconfigure_static_route_bfd_profile(self.device, prefix=PFX)
        self.assertEqual(self.emitted(), CTX + ["no bfd profile", "!"])

    def test_custom_network_instance(self):
        configure_static_route_bfd_profile(
            self.device, prefix=PFX, profile="G", network_instance="red")
        self.assertEqual(self.emitted()[0], "network-instance red")

    def test_failure_propagates(self):
        self.device.configure.side_effect = SubCommandFailure("nope")
        with self.assertRaises(SubCommandFailure):
            configure_static_route_bfd_profile(
                self.device, prefix=PFX, profile="GLOBAL")


class TestNexthopBfdDestinationAddress(Base):
    """The device takes a BARE address. Static_Routing.adoc:183 shows
    `bfd destination-address ipv4 <addr>`, which this build rejects."""

    def test_bare_address_form(self):
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh1",
            bfd_destination_address="10.1.1.2")
        self.assertEqual(self.emitted(), CTX + [
            "next-hop-index nh1", "bfd destination-address 10.1.1.2", "!"])

    def test_never_emits_the_adoc_ipv4_keyword_form(self):
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh1",
            bfd_destination_address="10.1.1.2")
        self.assertNotIn(
            "bfd destination-address ipv4 10.1.1.2", self.emitted())

    def test_counts_as_an_attribute_for_the_empty_call_guard(self):
        """Supplying only the BFD address must not trip the 'no attribute' guard."""
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh1",
            bfd_destination_address="10.1.1.2")
        self.device.configure.assert_called_once()

    def test_ordered_after_the_other_nexthop_leaves(self):
        configure_static_route_nexthop(
            self.device, prefix=PFX, nh_index="nh1", next_hop="10.1.1.2",
            interface="swp1", bfd_destination_address="10.1.1.2")
        cfg = self.emitted()
        self.assertLess(cfg.index("interface swp1"),
                        cfg.index("bfd destination-address 10.1.1.2"))


class TestSystemRibRnhResolution(Base):

    def test_default_route_only(self):
        configure_system_rib_rnh_resolution(
            self.device, af="IPV4", via_default_route=True)
        self.assertEqual(self.emitted(), [
            "system rib IPV4 rnh-resolution-via-default-route true", "!"])

    def test_both_leaves_both_afs(self):
        for af in SYSTEM_RIB_AFS:
            with self.subTest(af=af):
                self.device.configure.reset_mock()
                configure_system_rib_rnh_resolution(
                    self.device, af=af, via_default_route=True,
                    via_aggregate_route=False)
                self.assertEqual(self.emitted(), [
                    f"system rib {af} rnh-resolution-via-default-route true",
                    f"system rib {af} rnh-resolution-via-aggregate-route false",
                    "!",
                ])

    def test_invalid_af_rejected_both_directions(self):
        for fn, kw in ((configure_system_rib_rnh_resolution,
                        {"via_default_route": True}),
                       (unconfigure_system_rib_rnh_resolution,
                        {"via_default_route": True})):
            for bad in ("ipv4", "IPV4_UNICAST", "", None):
                with self.subTest(fn=fn.__name__, af=bad):
                    self.device.configure.reset_mock()
                    with self.assertRaises(ValueError):
                        fn(self.device, af=bad, **kw)
                    self.device.configure.assert_not_called()

    def test_requires_a_selection(self):
        for fn in (configure_system_rib_rnh_resolution,
                   unconfigure_system_rib_rnh_resolution):
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    fn(self.device, af="IPV4")
                self.device.configure.assert_not_called()

    def test_unconfigure_selected_only(self):
        unconfigure_system_rib_rnh_resolution(
            self.device, af="IPV6", via_aggregate_route=True)
        self.assertEqual(self.emitted(), [
            "no system rib IPV6 rnh-resolution-via-aggregate-route", "!"])

    def test_not_under_the_static_protocol(self):
        """The audit filed this against static-routing; it is a system knob."""
        configure_system_rib_rnh_resolution(
            self.device, af="IPV4", via_default_route=True)
        self.assertNotIn("protocol STATIC", " ".join(self.emitted()))


class TestMicroBfdProfileExtension(Base):
    """configure_interface_bfd_micro already existed; T1-07 added `profile`."""

    def test_profile_param_exists_and_defaults_none(self):
        p = inspect.signature(configure_interface_bfd_micro).parameters
        self.assertIn("profile", p)
        self.assertIsNone(p["profile"].default)

    def test_default_call_is_backward_compatible(self):
        configure_interface_bfd_micro(
            self.device, "bond1", remote_ipv4="1.1.1.2")
        self.assertEqual(self.emitted(), [
            "interface bond1",
            "bfd micro remote-address ipv4 1.1.1.2",
            "bfd micro enabled true",
            "!",
        ])
        self.assertNotIn("bfd micro profile", " ".join(self.emitted()))

    def test_profile_is_emitted_before_enabled(self):
        configure_interface_bfd_micro(
            self.device, "bond1", remote_ipv4="1.1.1.2", profile="GLOBAL")
        self.assertEqual(self.emitted(), [
            "interface bond1",
            "bfd micro remote-address ipv4 1.1.1.2",
            "bfd micro profile GLOBAL",
            "bfd micro enabled true",
            "!",
        ])

    def test_profile_with_both_afs(self):
        configure_interface_bfd_micro(
            self.device, "bond1", remote_ipv4="1.1.1.2",
            remote_ipv6="1000::2", profile="P", enabled=False)
        self.assertEqual(self.emitted(), [
            "interface bond1",
            "bfd micro remote-address ipv4 1.1.1.2",
            "bfd micro remote-address ipv6 1000::2",
            "bfd micro profile P",
            "bfd micro enabled false",
            "!",
        ])


if __name__ == "__main__":
    unittest.main()
