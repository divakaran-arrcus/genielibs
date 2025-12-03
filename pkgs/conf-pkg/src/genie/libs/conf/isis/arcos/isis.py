#!/usr/bin/env python3
"""
Native ArcOS ISIS configuration plugin for Genie.

This implementation is based on the existing Arrcus ISIS configuration
logic and provides full ArcOS ISIS CLI generation under the standard
Genie conf ISIS abstraction.
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class Isis(ABC):
    """ArcOS-specific ISIS implementation for Genie (native plugin)."""

    class DeviceAttributes(ABC):
        """Device-level ISIS attributes for ArcOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build ISIS configuration for an ArcOS device.

            This follows the ArcOS OpenConfig-like hierarchy:

                network-instance <instance_name>
                 protocol ISIS <pid>
                  ... global and per-interface config ...
            """
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Get network instance name (usually 'default')
            instance_name = getattr(self.device, 'custom', {}).get('instance_name', 'default')

            # Get protocol instance name (ISIS process name, usually 'default')
            pid = attributes.value('pid') or 'default'

            if unconfig:
                # Simple unconfiguration - remove entire ISIS protocol
                # Don't add 'no' prefix here - CliConfigBuilder will add it automatically
                configurations.append_line(f'network-instance {instance_name} protocol ISIS {pid}')

            else:
                # Build full ISIS configuration
                with configurations.submode_context(f'network-instance {instance_name}'):
                    with configurations.submode_context(f'protocol ISIS {pid}'):

                        # ========================================
                        # BASIC CONFIGURATION
                        # ========================================

                        # Configure NET (Network Entity Title)
                        # Support multiple NETs with same system-id but different area addresses
                        # Format: global net [ 49.0001.... 49.0002.... ]
                        net_list = attributes.value('net')
                        if net_list:
                            if isinstance(net_list, (list, tuple)):
                                net_str = ' '.join(net_list)
                                configurations.append_line(f'global net [ {net_str} ]')
                            else:
                                configurations.append_line(f'global net [ {net_list} ]')
                        else:
                            # Fallback to legacy single NET for backward compatibility
                            net_id = attributes.value('net_id')
                            if net_id:
                                configurations.append_line(f'global net [ {net_id} ]')

                        # ========================================
                        # ADDRESS FAMILIES (global)
                        # ========================================

                        # Configure address families (IPv4 and IPv6)
                        for sub, af_attributes in attributes.mapping_values('address_family_attr', sort=True):
                            af_config = sub.build_config(
                                apply=False,
                                attributes=af_attributes,
                                unconfig=unconfig,
                            )
                            if af_config:
                                configurations.append_block(af_config)

                        # ========================================
                        # GRACEFUL RESTART
                        # ========================================

                        graceful_restart_enabled = attributes.value('graceful_restart_enabled')
                        if graceful_restart_enabled is not None:
                            enabled_str = 'true' if graceful_restart_enabled else 'false'
                            configurations.append_line(
                                f'global graceful-restart enabled {enabled_str}'
                            )

                        graceful_restart_helper_only = attributes.value('graceful_restart_helper_only')
                        if graceful_restart_helper_only is not None:
                            helper_str = 'true' if graceful_restart_helper_only else 'false'
                            configurations.append_line(
                                f'global graceful-restart helper-only {helper_str}'
                            )

                        # ========================================
                        # IS-TYPE / LEVEL CONFIGURATION
                        # ========================================

                        is_type = attributes.value('is_type')
                        levels_to_configure = []
                        if is_type:
                            from genie.libs.conf.isis import Isis as GenieIsis

                            if is_type == GenieIsis.IsType.level_1:
                                levels_to_configure = [1]
                                level_capability = 'LEVEL_1'
                            elif is_type == GenieIsis.IsType.level_2:
                                levels_to_configure = [2]
                                level_capability = 'LEVEL_2'
                            elif is_type == GenieIsis.IsType.level_1_2:
                                levels_to_configure = [1, 2]
                                level_capability = 'LEVEL_1_2'

                            configurations.append_line(
                                f'global level-capability {level_capability}'
                            )
                        else:
                            # Default to level-2
                            levels_to_configure = [2]
                            configurations.append_line('global level-capability LEVEL_2')

                        # ========================================
                        # INTER-LEVEL PROPAGATION POLICIES
                        # ========================================

                        l1_to_l2_policy = attributes.value('level1_to_level2_import_policy')
                        if l1_to_l2_policy:
                            if isinstance(l1_to_l2_policy, (list, tuple)):
                                policy_str = ' '.join(str(p) for p in l1_to_l2_policy)
                            else:
                                policy_str = str(l1_to_l2_policy)
                            configurations.append_line(
                                'global inter-level-propagation-policies '
                                f'level1-to-level2 import-policy [ {policy_str} ]'
                            )

                        l2_to_l1_policy = attributes.value('level2_to_level1_import_policy')
                        if l2_to_l1_policy:
                            if isinstance(l2_to_l1_policy, (list, tuple)):
                                policy_str = ' '.join(str(p) for p in l2_to_l1_policy)
                            else:
                                policy_str = str(l2_to_l1_policy)
                            configurations.append_line(
                                'global inter-level-propagation-policies '
                                f'level2-to-level1 import-policy [ {policy_str} ]'
                            )

                        # ========================================
                        # LSP BIT CONFIGURATIONS
                        # ========================================

                        lsp_attached_ignore = attributes.value('lsp_bit_attached_ignore')
                        if lsp_attached_ignore is not None:
                            ignore_str = 'true' if lsp_attached_ignore else 'false'
                            configurations.append_line(
                                f'global lsp-bit attached-bit ignore-bit {ignore_str}'
                            )

                        lsp_attached_suppress = attributes.value('lsp_bit_attached_suppress')
                        if lsp_attached_suppress is not None:
                            suppress_str = 'true' if lsp_attached_suppress else 'false'
                            configurations.append_line(
                                f'global lsp-bit attached-bit suppress-bit {suppress_str}'
                            )

                        lsp_overload_set_on_boot = attributes.value('lsp_bit_overload_set_on_boot')
                        if lsp_overload_set_on_boot is not None:
                            boot_str = 'true' if lsp_overload_set_on_boot else 'false'
                            configurations.append_line(
                                f'global lsp-bit overload-bit set-bit-on-boot {boot_str}'
                            )

                        lsp_overload_advertise_high_metric = attributes.value(
                            'lsp_bit_overload_advertise_high_metric'
                        )
                        if lsp_overload_advertise_high_metric is not None:
                            metric_str = (
                                'true' if lsp_overload_advertise_high_metric else 'false'
                            )
                            configurations.append_line(
                                'global lsp-bit overload-bit '
                                f'advertise-high-metric {metric_str}'
                            )

                        lsp_overload_reset_trigger = attributes.value(
                            'lsp_bit_overload_reset_trigger'
                        )
                        if lsp_overload_reset_trigger:
                            lsp_overload_reset_delay = attributes.value(
                                'lsp_bit_overload_reset_delay'
                            )
                            if lsp_overload_reset_delay:
                                with configurations.submode_context(
                                    'global lsp-bit overload-bit '
                                    f'reset-trigger {lsp_overload_reset_trigger}'
                                ):
                                    configurations.append_line(
                                        f'delay {lsp_overload_reset_delay}'
                                    )
                                configurations.append_line('!')
                            else:
                                configurations.append_line(
                                    'global lsp-bit overload-bit '
                                    f'reset-trigger {lsp_overload_reset_trigger}'
                                )

                        # Max ECMP Paths
                        max_ecmp_paths = attributes.value('max_ecmp_paths')
                        if max_ecmp_paths is not None:
                            configurations.append_line(
                                f'global max-ecmp-paths {max_ecmp_paths}'
                            )

                        # LSP MTU Size
                        lsp_mtu_size = attributes.value('lsp_mtu_size')
                        if lsp_mtu_size is not None:
                            configurations.append_line(
                                f'global transport lsp-mtu-size {lsp_mtu_size}'
                            )

                        # ========================================
                        # SRv6 CONFIGURATION
                        # ========================================

                        srv6_enabled = attributes.value('srv6_enabled')
                        srv6_locators = attributes.value('srv6_locators')
                        if srv6_locators is None:
                            srv6_locators = attributes.value('srv6_locator')

                        if srv6_enabled is not None:
                            enabled_str = 'true' if srv6_enabled else 'false'
                            configurations.append_line(
                                f'global srv6 enabled {enabled_str}'
                            )

                        locator_names = []
                        if srv6_locators:
                            if isinstance(srv6_locators, dict):
                                locator_names = sorted(
                                    str(name) for name in srv6_locators.keys()
                                )
                            elif isinstance(srv6_locators, (list, tuple, set)):
                                locator_names = [str(name) for name in srv6_locators]
                            else:
                                locator_names = [str(srv6_locators)]

                        for locator_name in locator_names:
                            configurations.append_line(
                                f'global srv6 locator {locator_name}'
                            )
                            configurations.append_line('!')

                        # Traffic Engineering IPv6 Router ID
                        te_ipv6_rtrid = attributes.value(
                            'traffic_engineering_ipv6_router_id'
                        )
                        if te_ipv6_rtrid:
                            configurations.append_line(
                                'global traffic-engineering '
                                f'ipv6-router-id {te_ipv6_rtrid}'
                            )

                        # Segment Routing Enable/Disable
                        segment_routing_enabled = attributes.value(
                            'segment_routing_enabled'
                        )
                        if segment_routing_enabled is not None:
                            sr_enabled_str = 'true' if segment_routing_enabled else 'false'
                            configurations.append_line(
                                f'global segment-routing enabled {sr_enabled_str}'
                            )

                        # Micro-Loop Avoidance SRv6 Enabled
                        mla_srv6_enabled = attributes.value(
                            'micro_loop_avoidance_srv6_enabled'
                        )
                        if mla_srv6_enabled is not None:
                            mla_srv6_str = 'true' if mla_srv6_enabled else 'false'
                            configurations.append_line(
                                'global micro-loop-avoidance '
                                f'srv6-enabled {mla_srv6_str}'
                            )

                        # Micro-Loop Avoidance RIB Update Delay
                        mla_rib_delay = attributes.value(
                            'micro_loop_avoidance_rib_update_delay'
                        )
                        if mla_rib_delay is not None:
                            configurations.append_line(
                                'global micro-loop-avoidance '
                                f'rib-update-delay {mla_rib_delay}'
                            )

                        # Dynamic Delay Measurement Timers
                        ddm_probe_interval = attributes.value(
                            'dynamic_delay_measurement_probe_interval'
                        )
                        if ddm_probe_interval is not None:
                            configurations.append_line(
                                'global dynamic-delay-measurement '
                                f'probe-interval {ddm_probe_interval}'
                            )

                        ddm_adv_interval = attributes.value(
                            'dynamic_delay_measurement_advertisement_interval'
                        )
                        if ddm_adv_interval is not None:
                            configurations.append_line(
                                'global dynamic-delay-measurement '
                                f'advertisement-interval {ddm_adv_interval}'
                            )

                        # ========================================
                        # LSP / SPF TIMERS
                        # ========================================

                        lsp_refresh = attributes.value('lsp_refresh_interval')
                        if lsp_refresh:
                            configurations.append_line(
                                f'global timers lsp-refresh-interval {lsp_refresh}'
                            )

                        lsp_lifetime = attributes.value('lsp_lifetime')
                        if lsp_lifetime:
                            configurations.append_line(
                                'global timers lsp-lifetime-interval '
                                f'{lsp_lifetime}'
                            )

                        spf_first = attributes.value('spf_first_interval')
                        spf_second = attributes.value('spf_second_interval')
                        spf_hold = attributes.value('spf_hold_interval')
                        spf_legacy = attributes.value('spf_interval')

                        if spf_first is None and spf_legacy is not None:
                            spf_first = spf_legacy

                        if spf_first is not None:
                            configurations.append_line(
                                'global timers spf spf-first-interval '
                                f'{spf_first}'
                            )
                        if spf_second is not None:
                            configurations.append_line(
                                'global timers spf spf-second-interval '
                                f'{spf_second}'
                            )
                        if spf_hold is not None:
                            configurations.append_line(
                                'global timers spf spf-hold-interval '
                                f'{spf_hold}'
                            )

                        # ========================================
                        # AUTHENTICATION (Domain-level)
                        # ========================================

                        auth_mode = attributes.value('authentication_mode')
                        auth_key = attributes.value('authentication_key')
                        if auth_mode and auth_key:
                            mode = str(auth_mode).lower()
                            configurations.append_line(
                                'global hello-authentication '
                                'hello-authentication true'
                            )
                            configurations.append_line(
                                'global hello-authentication '
                                f'key auth-password {auth_key}'
                            )
                            if mode == 'md5':
                                configurations.append_line(
                                    'global hello-authentication '
                                    'key crypto-algorithm MD5'
                                )

                        # ========================================
                        # LEVEL-SPECIFIC CONFIGURATION
                        # ========================================

                        for lvl in levels_to_configure:
                            with configurations.submode_context(f'level {lvl}'):
                                configurations.append_line('enabled true')

                                try:
                                    lsp_auth = attributes.value(
                                        f'level{lvl}_lsp_authentication'
                                    )
                                    if lsp_auth is not None:
                                        lsp_auth_str = 'true' if lsp_auth else 'false'
                                        configurations.append_line(
                                            'authentication lsp-authentication '
                                            f'{lsp_auth_str}'
                                        )

                                    level_auth_password = attributes.value(
                                        f'level{lvl}_auth_password'
                                    )
                                    if level_auth_password:
                                        configurations.append_line(
                                            'authentication key auth-password '
                                            f'{level_auth_password}'
                                        )

                                    level_crypto_algo = attributes.value(
                                        f'level{lvl}_crypto_algorithm'
                                    )
                                    if level_crypto_algo:
                                        configurations.append_line(
                                            'authentication key crypto-algorithm '
                                            f'{level_crypto_algo}'
                                        )
                                except Exception:
                                    pass

                            configurations.append_line('!')

                        # ========================================
                        # INTERFACE-SPECIFIC CONFIGURATION
                        # ========================================

                        for sub, intf_attributes in attributes.mapping_values(
                            'interface_attr', keys=self.interfaces, sort=True
                        ):
                            intf_config = sub.build_config(
                                apply=False,
                                attributes=intf_attributes,
                                unconfig=unconfig,
                                levels=levels_to_configure,
                            )
                            if intf_config:
                                configurations.append_block(intf_config)

                    # End protocol ISIS
                    configurations.append_line('!')
                # End network-instance
                configurations.append_line('!')

            if apply:
                if configurations:
                    self.device.configure(str(configurations))
            else:
                return CliConfig(
                    device=self.device, unconfig=unconfig, cli_config=configurations
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build unconfiguration commands."""
            return self.build_config(
                apply=apply, attributes=attributes, unconfig=True, **kwargs
            )

        # ========================================
        # ADDRESS FAMILY ATTRIBUTES (global)
        # ========================================

        class AddressFamilyAttributes(ABC):
            """Address-family specific ISIS attributes for IPv4/IPv6 (global)."""

            def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
                """Build global address-family configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                # Determine AF type (ipv4 or ipv6)
                af_name = self.address_family.value.upper().replace('_', ' ')
                if af_name == 'IPV4':
                    af_name = 'IPV4 UNICAST'
                elif af_name == 'IPV6':
                    af_name = 'IPV6 UNICAST'

                with configurations.submode_context(f'global af {af_name}'):
                    # Enable the address family
                    enabled = attributes.value('enabled')
                    if enabled or enabled is None:
                        configurations.append_line('enabled true')

                    # Prefix-unreachable knobs
                    pfx_adv_lifetime = attributes.value(
                        'prefix_unreachable_adv_lifetime'
                    )
                    if pfx_adv_lifetime is not None:
                        configurations.append_line(
                            'prefix-unreachable adv-lifetime '
                            f'{pfx_adv_lifetime}'
                        )

                    pfx_adv_metric = attributes.value('prefix_unreachable_adv_metric')
                    if pfx_adv_metric is not None:
                        configurations.append_line(
                            'prefix-unreachable adv-metric '
                            f'{pfx_adv_metric}'
                        )

                    pfx_adv_maximum = attributes.value(
                        'prefix_unreachable_adv_maximum'
                    )
                    if pfx_adv_maximum is not None:
                        configurations.append_line(
                            'prefix-unreachable adv-maximum '
                            f'{pfx_adv_maximum}'
                        )

                    pfx_rx_process = attributes.value('prefix_unreachable_rx_process')
                    if pfx_rx_process is not None:
                        rx_process_str = 'true' if pfx_rx_process else 'false'
                        configurations.append_line(
                            'prefix-unreachable rx-process '
                            f'{rx_process_str}'
                        )

                    # IPv6 multi-topology
                    if 'IPV6' in af_name:
                        multi_topo = attributes.value('ipv6_multi_topology')
                        if multi_topo:
                            configurations.append_line('multi-topology enabled true')

                    # Summary prefixes
                    summary_prefixes = attributes.value('summary_prefixes')
                    if summary_prefixes:
                        for prefix, prefix_attrs in sorted(
                            summary_prefixes.items()
                        ):
                            with configurations.submode_context(
                                f'summary-prefix {prefix}'
                            ):
                                level = prefix_attrs.get('level')
                                if level:
                                    configurations.append_line(f'level {level}')

                                metric = prefix_attrs.get('metric')
                                if metric is not None:
                                    configurations.append_line(f'metric {metric}')

                                tag = prefix_attrs.get('tag')
                                if tag is not None:
                                    configurations.append_line(f'tag {tag}')

                                algorithm = prefix_attrs.get('algorithm')
                                if algorithm is not None:
                                    configurations.append_line(
                                        f'algorithm {algorithm}'
                                    )

                                adv_unreachable = prefix_attrs.get(
                                    'adv_unreachable'
                                )
                                if adv_unreachable is not None:
                                    adv_unreachable_str = (
                                        'true' if adv_unreachable else 'false'
                                    )
                                    configurations.append_line(
                                        'adv-unreachable '
                                        f'{adv_unreachable_str}'
                                    )

                            configurations.append_line('!')

                configurations.append_line('!')

                return CliConfig(
                    device=self.device, unconfig=unconfig, cli_config=configurations
                )

            def build_unconfig(self, apply=True, attributes=None, **kwargs):
                """Build global address-family unconfiguration."""
                return self.build_config(
                    apply=apply, attributes=attributes, unconfig=True, **kwargs
                )

            class SummaryPrefixAttributes(ABC):
                """Summary-prefix attributes within an address family."""

                def build_config(self, apply=False, attributes=None, unconfig=False, **kwargs):
                    attributes = AttributesHelper(self, attributes)
                    configurations = CliConfigBuilder(unconfig=unconfig)

                    prefix = str(self.summary_prefix)

                    if unconfig:
                        configurations.append_line(f'summary-prefix {prefix}')
                    else:
                        with configurations.submode_context(
                            f'summary-prefix {prefix}'
                        ):
                            level = attributes.value('level')
                            if level:
                                configurations.append_line(f'level {level}')

                            metric = attributes.value('metric')
                            if metric is not None:
                                configurations.append_line(f'metric {metric}')

                            tag = attributes.value('tag')
                            if tag is not None:
                                configurations.append_line(f'tag {tag}')

                            algorithm = attributes.value('algorithm')
                            if algorithm is not None:
                                configurations.append_line(
                                    f'algorithm {algorithm}'
                                )

                            adv_unreachable = attributes.value('adv_unreachable')
                            if adv_unreachable is not None:
                                adv_unreachable_str = (
                                    'true' if adv_unreachable else 'false'
                                )
                                configurations.append_line(
                                    'adv-unreachable '
                                    f'{adv_unreachable_str}'
                                )

                        configurations.append_line('!')

                    return CliConfig(
                        device=self.device, unconfig=unconfig, cli_config=configurations
                    )

                def build_unconfig(self, apply=False, attributes=None, **kwargs):
                    return self.build_config(
                        apply=apply, attributes=attributes, unconfig=True, **kwargs
                    )

        # ========================================
        # INTERFACE ATTRIBUTES
        # ========================================

        class InterfaceAttributes(ABC):
            """Interface-specific ISIS attributes for ArcOS."""

            # ========================================
            # IPv4 UNICAST Address Family Attributes
            # ========================================
            # Enabled flag for IPv4 AF
            ipv4_unicast_enabled = managedattribute(
                name='ipv4_unicast_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable IPv4 unicast address family on this interface')

            # SR-MPLS: TI-LFA fast-reroute enabled (IPv4)
            ipv4_ti_lfa_sr_mpls_enabled = managedattribute(
                name='ipv4_ti_lfa_sr_mpls_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable TI-LFA SR-MPLS fast-reroute on IPv4 AF')

            # SR-MPLS: Adjacency-SID for IPv4 AF (dict: adjacency_type, sid_type, value)
            ipv4_adjacency_sid = managedattribute(
                name='ipv4_adjacency_sid',
                default=None,
                type=(None, managedattribute.test_istype(dict)),
                doc='IPv4 Adjacency-SID: {adjacency_type, sid_type, value}')

            # SR-MPLS: Prefix-SID for IPv4 AF (dict: algorithm, sid_type, value, label_option, clear_n_flag)
            ipv4_prefix_sid = managedattribute(
                name='ipv4_prefix_sid',
                default=None,
                type=(None, managedattribute.test_istype(dict)),
                doc='IPv4 Prefix-SID: {algorithm, sid_type, value, label_option, clear_n_flag}')

            # ========================================
            # IPv6 UNICAST Address Family Attributes
            # ========================================
            # Enabled flag for IPv6 AF
            ipv6_unicast_enabled = managedattribute(
                name='ipv6_unicast_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable IPv6 unicast address family on this interface')

            # SR-MPLS: TI-LFA fast-reroute enabled (IPv6)
            ipv6_ti_lfa_sr_mpls_enabled = managedattribute(
                name='ipv6_ti_lfa_sr_mpls_enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable TI-LFA SR-MPLS fast-reroute on IPv6 AF')

            # SR-MPLS: Adjacency-SID for IPv6 AF (dict: adjacency_type, sid_type, value)
            ipv6_adjacency_sid = managedattribute(
                name='ipv6_adjacency_sid',
                default=None,
                type=(None, managedattribute.test_istype(dict)),
                doc='IPv6 Adjacency-SID: {adjacency_type, sid_type, value}')

            # SR-MPLS: Prefix-SID for IPv6 AF (dict: algorithm, sid_type, value, label_option, clear_n_flag)
            ipv6_prefix_sid = managedattribute(
                name='ipv6_prefix_sid',
                default=None,
                type=(None, managedattribute.test_istype(dict)),
                doc='IPv6 Prefix-SID: {algorithm, sid_type, value, label_option, clear_n_flag}')


            def build_config(
                self,
                apply=True,
                attributes=None,
                unconfig=False,
                levels=None,
                **kwargs,
            ):
                """Build interface-specific ISIS configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                # Get interface name
                intf_name = attributes.value('interface_id') or self.interface.name

                # Skip passive interfaces (configured at global level)
                if attributes.value('passive'):
                    return None

                # Check if interface is enabled for ISIS
                if not attributes.value('enabled'):
                    return None

                with configurations.submode_context(f'interface {intf_name}'):
                    configurations.append_line('enabled      true')

                    # Passive mode (interface-level)
                    passive = attributes.value('passive')
                    if passive:
                        configurations.append_line('passive true')

                    # Network type
                    if_type = attributes.value('if_type')
                    if if_type:
                        network_type_map = {
                            'point-to-point': 'POINT_TO_POINT',
                            'broadcast': 'BROADCAST',
                            'POINT_TO_POINT': 'POINT_TO_POINT',
                            'BROADCAST': 'BROADCAST',
                        }
                        network_type = network_type_map.get(if_type, 'POINT_TO_POINT')
                        configurations.append_line(
                            f'network-type {network_type}'
                        )

                    # Address families (interface-level) with SR-MPLS support
                    if not unconfig:
                        # IPv6 UNICAST
                        ipv6_enabled = attributes.value('ipv6_unicast_enabled')
                        if ipv6_enabled is None or ipv6_enabled:
                            with configurations.submode_context('af IPV6 UNICAST'):
                                configurations.append_line('enabled true')

                                # IPv6 TI-LFA SR-MPLS
                                ipv6_ti_lfa = attributes.value('ipv6_ti_lfa_sr_mpls_enabled')
                                if ipv6_ti_lfa is not None:
                                    enabled_str = 'true' if ipv6_ti_lfa else 'false'
                                    configurations.append_line(
                                        f'fast-reroute ti-lfa sr-mpls enabled {enabled_str}'
                                    )

                                # IPv6 Adjacency-SID
                                ipv6_adj_sid = attributes.value('ipv6_adjacency_sid')
                                if ipv6_adj_sid:
                                    adj_type = ipv6_adj_sid.get('adjacency_type', 'POINT_TO_POINT') if isinstance(ipv6_adj_sid, dict) else 'POINT_TO_POINT'
                                    with configurations.submode_context(f'adjacency-sid {adj_type}'):
                                        sid_type = ipv6_adj_sid.get('sid_type') if isinstance(ipv6_adj_sid, dict) else None
                                        value = ipv6_adj_sid.get('value') if isinstance(ipv6_adj_sid, dict) else None
                                        if sid_type:
                                            configurations.append_line(f'sid-type {sid_type}')
                                        if value is not None:
                                            configurations.append_line(f'value    {value}')
                                    configurations.append_line('!')

                                # IPv6 Prefix-SID
                                ipv6_pfx_sid = attributes.value('ipv6_prefix_sid')
                                if ipv6_pfx_sid:
                                    algorithm = ipv6_pfx_sid.get('algorithm', 'SPF') if isinstance(ipv6_pfx_sid, dict) else 'SPF'
                                    with configurations.submode_context(f'prefix-sid {algorithm}'):
                                        sid_type = ipv6_pfx_sid.get('sid_type') if isinstance(ipv6_pfx_sid, dict) else None
                                        value = ipv6_pfx_sid.get('value') if isinstance(ipv6_pfx_sid, dict) else None
                                        label_option = ipv6_pfx_sid.get('label_option') if isinstance(ipv6_pfx_sid, dict) else None
                                        clear_n_flag = ipv6_pfx_sid.get('clear_n_flag') if isinstance(ipv6_pfx_sid, dict) else None
                                        if sid_type:
                                            configurations.append_line(f'sid-type     {sid_type}')
                                        if value is not None:
                                            configurations.append_line(f'value        {value}')
                                        if label_option:
                                            configurations.append_line(f'label-option {label_option}')
                                        if clear_n_flag is not None:
                                            flag_str = 'true' if clear_n_flag else 'false'
                                            configurations.append_line(f'clear-n-flag {flag_str}')
                                    configurations.append_line('!')
                            configurations.append_line('!')

                        # IPv4 UNICAST with SR-MPLS attributes
                        ipv4_enabled = attributes.value('ipv4_unicast_enabled')
                        if ipv4_enabled is None or ipv4_enabled:
                            with configurations.submode_context('af IPV4 UNICAST'):
                                configurations.append_line('enabled true')

                                # IPv4 TI-LFA SR-MPLS fast-reroute
                                ipv4_ti_lfa = attributes.value('ipv4_ti_lfa_sr_mpls_enabled')
                                if ipv4_ti_lfa is not None:
                                    enabled_str = 'true' if ipv4_ti_lfa else 'false'
                                    configurations.append_line(
                                        f'fast-reroute ti-lfa sr-mpls enabled {enabled_str}'
                                    )

                                # IPv4 Adjacency-SID
                                ipv4_adj_sid = attributes.value('ipv4_adjacency_sid')
                                if ipv4_adj_sid:
                                    adj_type = ipv4_adj_sid.get('adjacency_type', 'POINT_TO_POINT') if isinstance(ipv4_adj_sid, dict) else 'POINT_TO_POINT'
                                    with configurations.submode_context(f'adjacency-sid {adj_type}'):
                                        sid_type = ipv4_adj_sid.get('sid_type') if isinstance(ipv4_adj_sid, dict) else None
                                        value = ipv4_adj_sid.get('value') if isinstance(ipv4_adj_sid, dict) else None
                                        if sid_type:
                                            configurations.append_line(f'sid-type {sid_type}')
                                        if value is not None:
                                            configurations.append_line(f'value    {value}')
                                    configurations.append_line('!')

                                # IPv4 Prefix-SID
                                ipv4_pfx_sid = attributes.value('ipv4_prefix_sid')
                                if ipv4_pfx_sid:
                                    algorithm = ipv4_pfx_sid.get('algorithm', 'SPF') if isinstance(ipv4_pfx_sid, dict) else 'SPF'
                                    with configurations.submode_context(f'prefix-sid {algorithm}'):
                                        sid_type = ipv4_pfx_sid.get('sid_type') if isinstance(ipv4_pfx_sid, dict) else None
                                        value = ipv4_pfx_sid.get('value') if isinstance(ipv4_pfx_sid, dict) else None
                                        label_option = ipv4_pfx_sid.get('label_option') if isinstance(ipv4_pfx_sid, dict) else None
                                        clear_n_flag = ipv4_pfx_sid.get('clear_n_flag') if isinstance(ipv4_pfx_sid, dict) else None
                                        if sid_type:
                                            configurations.append_line(f'sid-type     {sid_type}')
                                        if value is not None:
                                            configurations.append_line(f'value        {value}')
                                        if label_option:
                                            configurations.append_line(f'label-option {label_option}')
                                        if clear_n_flag is not None:
                                            flag_str = 'true' if clear_n_flag else 'false'
                                            configurations.append_line(f'clear-n-flag {flag_str}')
                                    configurations.append_line('!')
                            configurations.append_line('!')

                    # Timers
                    hello_interval = attributes.value('hello_interval')
                    if hello_interval:
                        configurations.append_line(
                            f'timers hello-interval {hello_interval}'
                        )

                    hello_multiplier = attributes.value('hello_multiplier')
                    if hello_multiplier:
                        configurations.append_line(
                            'timers hello-multiplier '
                            f'{hello_multiplier}'
                        )

                    # Metrics
                    metric_l1 = attributes.value('metric_level1')
                    if metric_l1:
                        configurations.append_line(
                            f'level 1 metric {metric_l1}'
                        )

                    metric_l2 = attributes.value('metric_level2')
                    if metric_l2:
                        configurations.append_line(
                            f'level 2 metric {metric_l2}'
                        )

                    # Interface authentication
                    hello_auth_enabled = attributes.value('hello_authentication')
                    auth_password = attributes.value('auth_password')
                    crypto_algorithm = attributes.value('crypto_algorithm')

                    if (
                        hello_auth_enabled is not None
                        or auth_password
                        or crypto_algorithm
                    ):
                        if hello_auth_enabled is not None:
                            hello_str = 'true' if hello_auth_enabled else 'false'
                            configurations.append_line(
                                'authentication hello-authentication '
                                f'{hello_str}'
                            )

                        if auth_password:
                            configurations.append_line(
                                'authentication key auth-password '
                                f'{auth_password}'
                            )

                        if crypto_algorithm:
                            configurations.append_line(
                                'authentication key crypto-algorithm '
                                f'{crypto_algorithm}'
                            )
                    else:
                        hello_auth_mode = attributes.value(
                            'hello_authentication_mode'
                        )
                        hello_auth_key = attributes.value(
                            'hello_authentication_key'
                        )
                        if hello_auth_mode and hello_auth_key:
                            if hello_auth_mode == 'md5':
                                configurations.append_line('authentication mode MD5')
                                configurations.append_line(
                                    'authentication key '
                                    f'{hello_auth_key}'
                                )
                            elif hello_auth_mode == 'text':
                                configurations.append_line('authentication mode TEXT')
                                configurations.append_line(
                                    'authentication key '
                                    f'{hello_auth_key}'
                                )

                    # Level configuration (interface-level)
                    if levels:
                        for lvl in levels:
                            with configurations.submode_context(f'level {lvl}'):
                                configurations.append_line('enabled true')
                                # Optional flexible-algorithm TE and delay metrics per level
                                flex_te = attributes.value(
                                    f'flex_algo_te_metric_level{lvl}'
                                )
                                flex_delay = attributes.value(
                                    f'flex_algo_delay_metric_level{lvl}'
                                )
                                if flex_te is not None:
                                    configurations.append_line(
                                        f'flexible-algorithm te-metric {flex_te}'
                                    )
                                if flex_delay is not None:
                                    configurations.append_line(
                                        f'flexible-algorithm delay-metric {flex_delay}'
                                    )
                            configurations.append_line('!')

                configurations.append_line('!')

                return CliConfig(
                    device=self.device, unconfig=unconfig, cli_config=configurations
                )

            def build_unconfig(self, apply=True, attributes=None, **kwargs):
                """Build interface-level ISIS unconfiguration."""
                return self.build_config(
                    apply=apply, attributes=attributes, unconfig=True, **kwargs
                )
