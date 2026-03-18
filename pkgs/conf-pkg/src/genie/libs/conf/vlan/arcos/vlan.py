#!/usr/bin/env python3
"""
Arcos VLAN Configuration Support for Genie.

Generates arcOS VLAN creation CLI:
    vlan <name>
     vlan-id <id>
    !
"""

from abc import ABC
import logging

from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


class Vlan(ABC):
    """Arcos-specific VLAN implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level VLAN attributes for ArcOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build VLAN configuration for an Arcos device."""
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            for sub, vlan_attributes in attributes.mapping_values(
                "vlan_attr", keys=self.vlans, sort=True
            ):
                vlan_config = sub.build_config(
                    apply=False,
                    attributes=vlan_attributes,
                    unconfig=unconfig,
                )
                if vlan_config:
                    configurations.append_block(vlan_config)

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
            """Build VLAN unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        class VlanAttributes(ABC):
            """Per-VLAN attributes for Arcos.

            Attributes:
                vlan_id (int): VLAN ID number
            """

            def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                """Build configuration for a specific VLAN."""
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=False)

                vlan_name = self.vlan_name

                if unconfig:
                    configurations.append_line(f"no vlan {vlan_name}")
                else:
                    with configurations.submode_context(
                        f"vlan {vlan_name}", cancel_empty=True
                    ):
                        vlan_id = attributes.value("vlan_id")
                        if vlan_id is not None:
                            configurations.append_line(f"vlan-id {vlan_id}")

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build unconfiguration for this VLAN."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )
