#!/usr/bin/env python3
"""
Native ArcOS BFD configuration plugin for Genie.

Implements BFD profile and single-hop interface configuration.

BFD profiles define session parameters (tx/rx intervals, detection multiplier,
HW offload) and are referenced by ISIS, BGP, and OSPF for session negotiation.

BFD single-hop interface overrides allow per-interface BFD parameters that
take precedence over the profile when a session comes up on that interface.
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


class Bfd(ABC):
    """ArcOS-specific BFD implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level BFD attributes for ArcOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build BFD configuration for ArcOS device."""
            assert not kwargs, f"Unexpected kwargs: {kwargs}"
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # BFD profiles
            for sub, profile_attributes in attributes.mapping_values(
                "profile_attr", sort=True
            ):
                profile_config = sub.build_config(
                    apply=False,
                    attributes=profile_attributes,
                    unconfig=unconfig,
                )
                if profile_config:
                    configurations.append_block(profile_config)

            # BFD single-hop interface overrides
            for sub, sh_attributes in attributes.mapping_values(
                "single_hop_interface_attr", sort=True
            ):
                sh_config = sub.build_config(
                    apply=False,
                    attributes=sh_attributes,
                    unconfig=unconfig,
                )
                if sh_config:
                    configurations.append_block(sh_config)

            if apply:
                if configurations:
                    self.device.configure(str(configurations))
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build BFD unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        class ProfileAttributes(ABC):
            """Per-profile BFD attributes for ArcOS.

            Generates CLI under 'bfd profile <name>'.
            """

            enabled = managedattribute(
                name='enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Administratively enabled (true/false)')

            desired_minimum_tx_interval = managedattribute(
                name='desired_minimum_tx_interval',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Minimum TX interval in milliseconds')

            required_minimum_receive = managedattribute(
                name='required_minimum_receive',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Minimum RX interval in milliseconds')

            detection_multiplier = managedattribute(
                name='detection_multiplier',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Missed packets before declaring session down')

            dscp_value = managedattribute(
                name='dscp_value',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='DSCP value for BFD packets (0-63)')

            v4_hw_offload = managedattribute(
                name='v4_hw_offload',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='IPv4 BFD hardware offload')

            v6_hw_offload = managedattribute(
                name='v6_hw_offload',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='IPv6 BFD hardware offload')

            def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                """Build configuration for a specific BFD profile."""
                assert not kwargs, f"Unexpected kwargs: {kwargs}"
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                profile_name = self.profile_name

                with configurations.submode_context(f"bfd profile {profile_name}"):
                    enabled = attributes.value("enabled")
                    if enabled is not None:
                        configurations.append_line(
                            f"enabled {'true' if enabled else 'false'}"
                        )

                    tx_interval = attributes.value("desired_minimum_tx_interval")
                    if tx_interval is not None:
                        configurations.append_line(
                            f"desired-minimum-tx-interval {tx_interval}"
                        )

                    rx_interval = attributes.value("required_minimum_receive")
                    if rx_interval is not None:
                        configurations.append_line(
                            f"required-minimum-receive {rx_interval}"
                        )

                    multiplier = attributes.value("detection_multiplier")
                    if multiplier is not None:
                        configurations.append_line(
                            f"detection-multiplier {multiplier}"
                        )

                    dscp = attributes.value("dscp_value")
                    if dscp is not None:
                        configurations.append_line(f"dscp-value {dscp}")

                    v4_hw = attributes.value("v4_hw_offload")
                    if v4_hw is not None:
                        configurations.append_line(
                            f"v4-hw-offload {'true' if v4_hw else 'false'}"
                        )

                    v6_hw = attributes.value("v6_hw_offload")
                    if v6_hw is not None:
                        configurations.append_line(
                            f"v6-hw-offload {'true' if v6_hw else 'false'}"
                        )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build unconfiguration for this BFD profile."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )

        class SingleHopInterfaceAttributes(ABC):
            """Per-interface single-hop BFD attributes for ArcOS.

            Generates CLI under 'bfd single-hop interface <name>'.
            """

            desired_minimum_tx_interval = managedattribute(
                name='desired_minimum_tx_interval',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Minimum TX interval in milliseconds')

            required_minimum_receive = managedattribute(
                name='required_minimum_receive',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Minimum RX interval in milliseconds')

            detection_multiplier = managedattribute(
                name='detection_multiplier',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Missed packets before declaring session down')

            def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                """Build configuration for a specific BFD single-hop interface."""
                assert not kwargs, f"Unexpected kwargs: {kwargs}"
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                intf_name = self.interface_name

                with configurations.submode_context(
                    f"bfd single-hop interface {intf_name}"
                ):
                    tx_interval = attributes.value("desired_minimum_tx_interval")
                    if tx_interval is not None:
                        configurations.append_line(
                            f"desired-minimum-tx-interval {tx_interval}"
                        )

                    rx_interval = attributes.value("required_minimum_receive")
                    if rx_interval is not None:
                        configurations.append_line(
                            f"required-minimum-receive {rx_interval}"
                        )

                    multiplier = attributes.value("detection_multiplier")
                    if multiplier is not None:
                        configurations.append_line(
                            f"detection-multiplier {multiplier}"
                        )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build unconfiguration for this BFD single-hop interface."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )
