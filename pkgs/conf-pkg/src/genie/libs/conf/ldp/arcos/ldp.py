#!/usr/bin/env python3
"""
Native ArcOS LDP configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles LDP global settings, per-interface link-hello configuration,
targeted hello settings, and per-neighbor configuration.

All LDP commands live under:
    network-instance default mpls signaling-protocols ldp

Note: LDP can only be configured under the default network-instance.
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)

# Base CLI prefix for all LDP commands
_LDP_PREFIX = 'mpls signaling-protocols ldp'


class Ldp(ABC):
    """ArcOS-specific LDP implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level LDP attributes for ArcOS."""

        # =============================================================
        # GLOBAL ATTRIBUTES
        # =============================================================

        lsr_id = managedattribute(
            name='lsr_id',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='LSR identifier (IPv4 address)')

        enable = managedattribute(
            name='enable',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Globally enable/disable LDP')

        label_distribution_mode = managedattribute(
            name='label_distribution_mode',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Label distribution mode (independent or ordered)')

        php_enable = managedattribute(
            name='php_enable',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable/disable penultimate hop popping')

        php_type = managedattribute(
            name='php_type',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='PHP type: EXPLICIT or IMPLICIT')

        post_session_up_delay = managedattribute(
            name='post_session_up_delay',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='IGP notification delay after LDP session up (seconds)')

        auth_enable = managedattribute(
            name='auth_enable',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Global MD5 authentication enable')

        auth_key = managedattribute(
            name='auth_key',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Global MD5 authentication key')

        fec_filter_default_export_policy = managedattribute(
            name='fec_filter_default_export_policy',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Default FEC export policy (ACCEPT_ROUTE or DENY_ROUTE)')

        fec_filter_export_policy = managedattribute(
            name='fec_filter_export_policy',
            default=None,
            type=(None, managedattribute.test_istype((str, list))),
            doc='FEC export policy name(s)')

        transport_address_ipv4 = managedattribute(
            name='transport_address_ipv4',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='IPv4 transport address for LDP sessions')

        transport_address_ipv6 = managedattribute(
            name='transport_address_ipv6',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='IPv6 transport address for LDP sessions')

        maximum_local_binding = managedattribute(
            name='maximum_local_binding',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Maximum number of local label bindings')

        rib_preference = managedattribute(
            name='rib_preference',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='LDP RIB route preference (1-255)')

        session_protection = managedattribute(
            name='session_protection',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Session protection timer in seconds (0 = infinite)')

        # =============================================================
        # INTERFACE-ATTRIBUTES GLOBAL
        # =============================================================

        hello_holdtime = managedattribute(
            name='hello_holdtime',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Global link hello hold time (default 15s)')

        hello_interval = managedattribute(
            name='hello_interval',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Global link hello interval (default 5s)')

        # =============================================================
        # TARGETED GLOBAL
        # =============================================================

        targeted_hello_accept = managedattribute(
            name='targeted_hello_accept',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Accept targeted hellos globally')

        targeted_hello_holdtime = managedattribute(
            name='targeted_hello_holdtime',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Targeted hello hold time (default 45s)')

        targeted_hello_interval = managedattribute(
            name='targeted_hello_interval',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Targeted hello interval (default 15s)')

        targeted_strict = managedattribute(
            name='targeted_strict',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Strict targeted hellos (only respond to configured neighbors)')

        # =============================================================
        # build_config
        # =============================================================

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build LDP configuration for an ArcOS device."""
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # LDP is always under default network-instance
            ni_prefix = f'network-instance default {_LDP_PREFIX}'

            # --- Global ---
            v = attributes.value('lsr_id')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global lsr-id {v}')

            v = attributes.value('enable')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global enable '
                    f'{"true" if v else "false"}')

            v = attributes.value('label_distribution_mode')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global attributes '
                    f'label-distribution-mode {v}')

            v = attributes.value('php_enable')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global attributes php-enable '
                    f'{"true" if v else "false"}')

            v = attributes.value('php_type')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global attributes php-type {v}')

            v = attributes.value('post_session_up_delay')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global attributes '
                    f'post-session-up-delay {v}')

            v = attributes.value('auth_enable')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global authentication enable '
                    f'{"true" if v else "false"}')

            v = attributes.value('auth_key')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global authentication '
                    f'authentication-key {v}')

            v = attributes.value('fec_filter_default_export_policy')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global fec-filter '
                    f'default-export-policy {v}')

            v = attributes.value('fec_filter_export_policy')
            if v is not None:
                if isinstance(v, (list, tuple)):
                    policy_str = ' '.join(str(p) for p in v)
                else:
                    policy_str = str(v)
                configurations.append_line(
                    f'{ni_prefix} global fec-filter '
                    f'export-policy [ {policy_str} ]')

            v = attributes.value('transport_address_ipv4')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global transport-address ipv4 {v}')

            v = attributes.value('transport_address_ipv6')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global transport-address ipv6 {v}')

            v = attributes.value('maximum_local_binding')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global maximum-local-binding {v}')

            v = attributes.value('rib_preference')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global rib-preference {v}')

            v = attributes.value('session_protection')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} global session-protection {v}')

            # --- Interface-Attributes Global ---
            v = attributes.value('hello_holdtime')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} interface-attributes '
                    f'hello-holdtime {v}')

            v = attributes.value('hello_interval')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} interface-attributes '
                    f'hello-interval {v}')

            # --- Per-interface ---
            for sub, intf_attributes in attributes.mapping_values(
                'interface_attr', sort=True
            ):
                intf_config = sub.build_config(
                    apply=False,
                    attributes=intf_attributes,
                    unconfig=unconfig,
                    ni_prefix=ni_prefix,
                )
                if intf_config:
                    configurations.append_block(intf_config)

            # --- Targeted Global ---
            v = attributes.value('targeted_hello_accept')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} targeted hello-accept '
                    f'{"true" if v else "false"}')

            v = attributes.value('targeted_hello_holdtime')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} targeted hello-holdtime {v}')

            v = attributes.value('targeted_hello_interval')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} targeted hello-interval {v}')

            v = attributes.value('targeted_strict')
            if v is not None:
                configurations.append_line(
                    f'{ni_prefix} targeted strict-targeted-hellos '
                    f'{"true" if v else "false"}')

            # --- Per-neighbor ---
            for sub, nbr_attributes in attributes.mapping_values(
                'neighbor_attr', sort=True
            ):
                nbr_config = sub.build_config(
                    apply=False,
                    attributes=nbr_attributes,
                    unconfig=unconfig,
                    ni_prefix=ni_prefix,
                )
                if nbr_config:
                    configurations.append_block(nbr_config)

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
            """Build LDP unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        # =============================================================
        # INTERFACE ATTRIBUTES
        # =============================================================

        class InterfaceAttributes(ABC):
            """Per-interface LDP attributes for ArcOS."""

            link_hello = managedattribute(
                name='link_hello',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable LDP link-hello on this interface')

            intf_hello_holdtime = managedattribute(
                name='intf_hello_holdtime',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Per-interface hello hold time')

            intf_hello_interval = managedattribute(
                name='intf_hello_interval',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Per-interface hello interval')

            ipv4_enabled = managedattribute(
                name='ipv4_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable IPv4 address family on this interface')

            ipv6_enabled = managedattribute(
                name='ipv6_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable IPv6 address family on this interface')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, ni_prefix='', **kwargs):
                """Build per-interface LDP configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                intf_name = self.interface_name

                with configurations.submode_context(
                    f'{ni_prefix} interface-attributes interface {intf_name}'
                ):
                    v = attributes.value('link_hello')
                    if v is not None:
                        configurations.append_line(
                            f'link-hello {"true" if v else "false"}')

                    v = attributes.value('intf_hello_holdtime')
                    if v is not None:
                        configurations.append_line(
                            f'hello-holdtime {v}')

                    v = attributes.value('intf_hello_interval')
                    if v is not None:
                        configurations.append_line(
                            f'hello-interval {v}')

                    # Address family IPv4
                    v = attributes.value('ipv4_enabled')
                    if v is not None:
                        with configurations.submode_context(
                            'address-family IPV4'
                        ):
                            configurations.append_line(
                                f'enabled {"true" if v else "false"}')

                    # Address family IPv6
                    v = attributes.value('ipv6_enabled')
                    if v is not None:
                        with configurations.submode_context(
                            'address-family IPV6'
                        ):
                            configurations.append_line(
                                f'enabled {"true" if v else "false"}')

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build per-interface LDP unconfiguration."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )

        # =============================================================
        # NEIGHBOR ATTRIBUTES
        # =============================================================

        class NeighborAttributes(ABC):
            """Per-neighbor LDP attributes for ArcOS.

            Neighbor key format: '{lsr_id} {label_space_id}'
            e.g., '1.1.1.1 0'
            """

            nbr_auth_enable = managedattribute(
                name='nbr_auth_enable',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Per-neighbor MD5 authentication enable')

            nbr_auth_key = managedattribute(
                name='nbr_auth_key',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Per-neighbor MD5 authentication key')

            nbr_max_remote_binding = managedattribute(
                name='nbr_max_remote_binding',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Maximum remote label bindings for this neighbor')

            nbr_targeted_hello_holdtime = managedattribute(
                name='nbr_targeted_hello_holdtime',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Per-neighbor targeted hello hold time')

            nbr_targeted_hello_interval = managedattribute(
                name='nbr_targeted_hello_interval',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Per-neighbor targeted hello interval')

            nbr_targeted_ipv4_enabled = managedattribute(
                name='nbr_targeted_ipv4_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable IPv4 targeted hellos to this neighbor')

            nbr_targeted_ipv4_dest = managedattribute(
                name='nbr_targeted_ipv4_dest',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='IPv4 destination address for targeted hellos')

            nbr_targeted_ipv6_enabled = managedattribute(
                name='nbr_targeted_ipv6_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable IPv6 targeted hellos to this neighbor')

            nbr_targeted_ipv6_dest = managedattribute(
                name='nbr_targeted_ipv6_dest',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='IPv6 destination address for targeted hellos')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, ni_prefix='', **kwargs):
                """Build per-neighbor LDP configuration.

                The neighbor key is '{lsr_id} {label_space_id}',
                e.g., '1.1.1.1 0'.
                """
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                nbr_key = self.neighbor_id

                with configurations.submode_context(
                    f'{ni_prefix} neighbor {nbr_key}'
                ):
                    v = attributes.value('nbr_auth_enable')
                    if v is not None:
                        configurations.append_line(
                            f'authentication enable '
                            f'{"true" if v else "false"}')

                    v = attributes.value('nbr_auth_key')
                    if v is not None:
                        configurations.append_line(
                            f'authentication authentication-key {v}')

                    v = attributes.value('nbr_max_remote_binding')
                    if v is not None:
                        configurations.append_line(
                            f'maximum-remote-binding {v}')

                    v = attributes.value('nbr_targeted_hello_holdtime')
                    if v is not None:
                        configurations.append_line(
                            f'targeted hello-holdtime {v}')

                    v = attributes.value('nbr_targeted_hello_interval')
                    if v is not None:
                        configurations.append_line(
                            f'targeted hello-interval {v}')

                    # Targeted address-family IPv4
                    ipv4_en = attributes.value('nbr_targeted_ipv4_enabled')
                    ipv4_dest = attributes.value('nbr_targeted_ipv4_dest')
                    if ipv4_en is not None or ipv4_dest is not None:
                        with configurations.submode_context(
                            'targeted address-family IPV4'
                        ):
                            if ipv4_en is not None:
                                configurations.append_line(
                                    f'enabled '
                                    f'{"true" if ipv4_en else "false"}')
                            if ipv4_dest is not None:
                                configurations.append_line(
                                    f'destination-address {ipv4_dest}')

                    # Targeted address-family IPv6
                    ipv6_en = attributes.value('nbr_targeted_ipv6_enabled')
                    ipv6_dest = attributes.value('nbr_targeted_ipv6_dest')
                    if ipv6_en is not None or ipv6_dest is not None:
                        with configurations.submode_context(
                            'targeted address-family IPV6'
                        ):
                            if ipv6_en is not None:
                                configurations.append_line(
                                    f'enabled '
                                    f'{"true" if ipv6_en else "false"}')
                            if ipv6_dest is not None:
                                configurations.append_line(
                                    f'destination-address {ipv6_dest}')

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                """Build per-neighbor LDP unconfiguration."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )
