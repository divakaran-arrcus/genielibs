#!/usr/bin/env python3
"""
Native ArcOS TE admin-group configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles TE admin-group definitions under network-instance context:

    network-instance <instance>
     te admin-group <name>
      bit-position <value>
     !
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class Te(ABC):
    """ArcOS-specific TE implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level TE attributes for ArcOS."""

        admin_groups = managedattribute(
            name='admin_groups',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Dict of TE admin-group definitions keyed by group name. '
                'Each value is a dict with key: bit_position (int). '
                'Example: {"green": {"bit_position": 2}, "red": {"bit_position": 11}}')

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build TE admin-group configuration for ArcOS device."""
            assert not kwargs, f"Unexpected kwargs: {kwargs}"
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            instance_name = getattr(self.device, 'custom', {}).get(
                'instance_name', 'default'
            )

            if unconfig:
                # Remove all configured admin-groups
                admin_groups = attributes.value('admin_groups')
                if admin_groups and isinstance(admin_groups, dict):
                    for group_name in sorted(admin_groups.keys()):
                        configurations.append_line(
                            f'network-instance {instance_name} '
                            f'te admin-group {group_name}'
                        )
            else:
                admin_groups = attributes.value('admin_groups')
                if admin_groups and isinstance(admin_groups, dict):
                    with configurations.submode_context(
                        f'network-instance {instance_name}'
                    ):
                        for group_name in sorted(admin_groups.keys()):
                            group_attrs = admin_groups[group_name]
                            if not isinstance(group_attrs, dict):
                                configurations.append_line(
                                    f'te admin-group {group_name}'
                                )
                                configurations.append_line('!')
                                continue

                            bit_pos = group_attrs.get('bit_position')
                            if bit_pos is not None:
                                with configurations.submode_context(
                                    f'te admin-group {group_name}'
                                ):
                                    configurations.append_line(
                                        f'bit-position {bit_pos}'
                                    )
                                configurations.append_line('!')
                            else:
                                configurations.append_line(
                                    f'te admin-group {group_name}'
                                )
                                configurations.append_line('!')
                    configurations.append_line('!')

            if apply:
                if configurations:
                    self.device.configure(
                        str(configurations), fail_invalid=True
                    )
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build unconfiguration for TE admin-groups."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )
