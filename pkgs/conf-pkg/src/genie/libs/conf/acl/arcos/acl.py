#!/usr/bin/env python3
"""
Native ArcOS ACL configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles ACL set definitions with ACL entries (ACEs) including
L3 (IPv4/IPv6), L2, and transport match criteria with actions.

CLI structure:
    acl acl-set <name> <type>
     description "<desc>"
     acl-entry <seq>
      description "<desc>"
      ipv4 source-address <prefix>
      actions forwarding-action <ACCEPT|DROP|REDIRECT>
     !
    !
"""

from abc import ABC
import logging
from typing import Any, Dict

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


def _build_acl_entry(cfg, seq_id, entry):
    """Render a single ACL entry within an acl-set context.

    Args:
        cfg: CliConfigBuilder instance.
        seq_id: Sequence ID (int or str).
        entry: Dict with ACE attributes.
    """

    def _get(key):
        if isinstance(entry, dict):
            return entry.get(key)
        return getattr(entry, key, None)

    with cfg.submode_context(f'acl-entry {seq_id}'):
        # Description
        desc = _get('description')
        if desc:
            cfg.append_line(f'description {desc}')

        # IPv4 match
        v = _get('ipv4_source_address')
        if v:
            cfg.append_line(f'ipv4 source-address {v}')

        v = _get('ipv4_destination_address')
        if v:
            cfg.append_line(f'ipv4 destination-address {v}')

        v = _get('ipv4_protocol')
        if v:
            cfg.append_line(f'ipv4 protocol {v}')

        # IPv6 match
        v = _get('ipv6_source_address')
        if v:
            cfg.append_line(f'ipv6 source-address {v}')

        v = _get('ipv6_destination_address')
        if v:
            cfg.append_line(f'ipv6 destination-address {v}')

        v = _get('ipv6_protocol')
        if v:
            cfg.append_line(f'ipv6 protocol {v}')

        # L2 match
        v = _get('l2_source_mac')
        if v:
            cfg.append_line(f'l2 source-mac {v}')

        v = _get('l2_source_mac_mask')
        if v:
            cfg.append_line(f'l2 source-mac-mask {v}')

        # Transport match
        v = _get('transport_source_port')
        if v is not None:
            cfg.append_line(f'transport source-port {v}')

        v = _get('transport_destination_port')
        if v is not None:
            cfg.append_line(f'transport destination-port {v}')

        # Actions
        v = _get('forwarding_action')
        if v:
            cfg.append_line(f'actions forwarding-action {v}')

        v = _get('log_action')
        if v:
            cfg.append_line(f'actions log-action {v}')

        # Redirect parameters (only when forwarding_action is REDIRECT)
        v = _get('redirect_next_hop')
        if v:
            cfg.append_line(f'actions ipv4-redirect next-hop {v}')

        v = _get('redirect_network_instance')
        if v:
            cfg.append_line(f'actions ipv4-redirect network-instance {v}')


class Acl(ABC):
    """ArcOS-specific ACL implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level ACL attributes for ArcOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build ACL configuration for an ArcOS device."""
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Delegate to per-ACL-set children
            for sub, acl_set_attributes in attributes.mapping_values(
                'acl_set_attr', sort=True
            ):
                acl_set_config = sub.build_config(
                    apply=False,
                    attributes=acl_set_attributes,
                    unconfig=unconfig,
                )
                if acl_set_config:
                    configurations.append_block(acl_set_config)

            if apply:
                if configurations:
                    self.device.configure(str(configurations),
                                          fail_invalid=True)
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build ACL unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        # =============================================================
        # ACL SET ATTRIBUTES
        # =============================================================

        class AclSetAttributes(ABC):
            """Per-ACL-set attributes for ArcOS.

            Key format: '{name} {type}' e.g. 'v4-acl ACL_IPV4'
            Types: ACL_IPV4, ACL_IPV6, ACL_L2
            """

            description = managedattribute(
                name='description',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='ACL set description')

            acl_entries = managedattribute(
                name='acl_entries',
                default=None,
                type=(None, managedattribute.test_istype(dict)),
                doc='Dict of ACL entries keyed by sequence-id (int or str)')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, **kwargs):
                """Build per-ACL-set configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                acl_set_key = self.acl_set_key  # e.g. "v4-acl ACL_IPV4"

                with configurations.submode_context(
                    f'acl acl-set {acl_set_key}'
                ):
                    # Description
                    desc = attributes.value('description')
                    if desc:
                        configurations.append_line(f'description {desc}')

                    # ACL entries
                    entries = attributes.value('acl_entries')
                    if entries:
                        for seq_id in sorted(entries.keys(),
                                             key=lambda x: int(x)):
                            entry = entries[seq_id]
                            _build_acl_entry(
                                configurations, seq_id, entry
                            )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None,
                               **kwargs):
                """Build per-ACL-set unconfiguration."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )
