#!/usr/bin/env python3
"""
Native ArcOS OSPFv3 configuration plugin for Genie.

This implementation provides full ArcOS OSPFv3 CLI generation under the
standard Genie conf OSPFv3 abstraction.  It mirrors the OSPFv2 conf object
(``ospf/arcos/ospf.py``) with the following key differences:

  - Protocol token is ``OSPF3`` (not ``OSPF``)
  - IPv6 prefixes in redistribute-aggregate and summary-aggregate
  - Interface ``instance-id`` (0-255) for per-link instance separation
  - Interface ``interface-id`` (auto or manual 32-bit ID)
  - No OSPFv3 per-interface authentication commands (IPsec handled externally)

Hierarchy::

    network-instance <ni>
     protocol OSPF3 <pid>
      global ...
      area <area_id>
       ...
       interface <name>
        ...

All three phases of attributes are included:
  Phase 1 -- Core (adjacency formation & routing)
  Phase 2 -- Hardening (BFD, priority, route-preference, summary-aggregate)
  Phase 3 -- Advanced (SPF throttle, LSA timers, max-LSA, maintenance mode,
             redistribute-aggregate)
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


class Ospfv3(ABC):
    """ArcOS-specific OSPFv3 implementation for Genie (native plugin)."""

    class DeviceAttributes(ABC):
        """Device-level OSPFv3 attributes for ArcOS."""

        # ============================================================
        # Phase 1 -- Core global attributes
        # ============================================================

        router_id = managedattribute(
            name='router_id',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='OSPF router-id (dotted quad, e.g. "1.1.1.1")')

        max_ecmp_paths = managedattribute(
            name='max_ecmp_paths',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Maximum ECMP paths (1-128, default 128)')

        auto_cost_enabled = managedattribute(
            name='auto_cost_enabled',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable auto-cost interface metric calculation')

        auto_cost_reference_bandwidth = managedattribute(
            name='auto_cost_reference_bandwidth',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Auto-cost reference bandwidth in Gbps (default 3200)')

        log_adjacency_changes = managedattribute(
            name='log_adjacency_changes',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Log adjacency changes: LOG_ADJ_DISABLE, '
                'LOG_ADJ_ENABLE_LIMITED, LOG_ADJ_ENABLE_DETAILED')

        # ============================================================
        # Phase 2 -- Route preference
        # ============================================================

        route_preference_intra_area = managedattribute(
            name='route_preference_intra_area',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='RIB route preference for intra-area routes (0-255)')

        route_preference_inter_area = managedattribute(
            name='route_preference_inter_area',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='RIB route preference for inter-area routes (0-255)')

        route_preference_external = managedattribute(
            name='route_preference_external',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='RIB route preference for external routes (0-255)')

        # ============================================================
        # Phase 3 -- SPF throttle timers
        # ============================================================

        spf_initial_delay = managedattribute(
            name='spf_initial_delay',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='SPF initial delay in ms (default 50)')

        spf_short_delay = managedattribute(
            name='spf_short_delay',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='SPF short delay in ms (default 200)')

        spf_long_delay = managedattribute(
            name='spf_long_delay',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='SPF long delay in ms (default 5000)')

        spf_time_to_learn = managedattribute(
            name='spf_time_to_learn',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='SPF time-to-learn interval in ms (default 500)')

        spf_holddown = managedattribute(
            name='spf_holddown',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='SPF holddown interval in ms (default 10000)')

        # Phase 3 -- SPF logging
        spf_log_max_logs = managedattribute(
            name='spf_log_max_logs',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Maximum number of SPF logs to store (default 16)')

        spf_log_max_triggers = managedattribute(
            name='spf_log_max_triggers',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Maximum triggers per SPF log (default 8)')

        # ============================================================
        # Phase 3 -- LSA timers
        # ============================================================

        lsa_min_arrival = managedattribute(
            name='lsa_min_arrival',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Minimum arrival interval between same LSA instances in ms')

        lsa_origination_start = managedattribute(
            name='lsa_origination_start',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='LSA origination start interval in ms (default 50)')

        lsa_origination_hold = managedattribute(
            name='lsa_origination_hold',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='LSA origination hold interval in ms (default 200)')

        lsa_origination_max = managedattribute(
            name='lsa_origination_max',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='LSA origination max interval in ms (default 5000)')

        # ============================================================
        # Phase 3 -- Max-LSA
        # ============================================================

        max_lsa_limit = managedattribute(
            name='max_lsa_limit',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Remote LSA limit')

        max_lsa_warning_threshold = managedattribute(
            name='max_lsa_warning_threshold',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Warning threshold percentage (1-100, default 75)')

        max_lsa_warning_only = managedattribute(
            name='max_lsa_warning_only',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Warning-only mode (default false)')

        max_lsa_avoid_down_state = managedattribute(
            name='max_lsa_avoid_down_state',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Avoid DOWN state (default false)')

        max_lsa_limit_monitor_time = managedattribute(
            name='max_lsa_limit_monitor_time',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='LIMIT state monitor timer in seconds (default 0)')

        max_lsa_down_recovery_time = managedattribute(
            name='max_lsa_down_recovery_time',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='DOWN state recovery timer in seconds (default 300)')

        # ============================================================
        # Phase 3 -- Maintenance mode
        # ============================================================

        maintenance_mode_always = managedattribute(
            name='maintenance_mode_always',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Unconditionally enter maintenance mode')

        maintenance_mode_on_startup = managedattribute(
            name='maintenance_mode_on_startup',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Enter maintenance mode on startup for N seconds (default 300)')

        maintenance_mode_router_lsa_metric = managedattribute(
            name='maintenance_mode_router_lsa_metric',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Router LSA metric during maintenance (default 65535)')

        maintenance_mode_router_lsa_set_link_metric = managedattribute(
            name='maintenance_mode_router_lsa_set_link_metric',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Set metric for non-stub links (default false)')

        maintenance_mode_router_lsa_set_stub_metric = managedattribute(
            name='maintenance_mode_router_lsa_set_stub_metric',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Set metric for stub networks (default false)')

        maintenance_mode_summary_lsa_metric = managedattribute(
            name='maintenance_mode_summary_lsa_metric',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Summary LSA metric during maintenance (default 16711680)')

        maintenance_mode_summary_lsa_set_metric = managedattribute(
            name='maintenance_mode_summary_lsa_set_metric',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable sending summary LSA metric (default false)')

        maintenance_mode_external_lsa_metric = managedattribute(
            name='maintenance_mode_external_lsa_metric',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='External LSA metric during maintenance (default 16711680)')

        maintenance_mode_external_lsa_set_metric = managedattribute(
            name='maintenance_mode_external_lsa_set_metric',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable sending external LSA metric (default false)')

        # ============================================================
        # Phase 3 -- Redistribute aggregates (global level, IPv6)
        # ============================================================

        redistribute_aggregates = managedattribute(
            name='redistribute_aggregates',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Dict of IPv6 prefix -> {advertise: str, import_policy: str}')

        # ============================================================
        # build_config / build_unconfig
        # ============================================================

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build OSPFv3 configuration for an ArcOS device.

            Hierarchy:
                network-instance <instance_name>
                 protocol OSPF3 <pid>
                  global ...
                  area <area_id>
                   ...
                   interface <name>
                    ...
            """
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            instance_name = getattr(self.device, 'custom', {}).get(
                'instance_name', 'default'
            )
            pid = attributes.value('pid') or 'default'

            if unconfig:
                configurations.append_line(
                    f'network-instance {instance_name} protocol OSPF3 {pid}'
                )
            else:
                with configurations.submode_context(
                    f'network-instance {instance_name}'
                ):
                    with configurations.submode_context(
                        f'protocol OSPF3 {pid}'
                    ):
                        # ========================================
                        # PHASE 1 -- Core global config
                        # ========================================

                        router_id = attributes.value('router_id')
                        if router_id:
                            configurations.append_line(
                                f'global router-id {router_id}'
                            )

                        max_ecmp = attributes.value('max_ecmp_paths')
                        if max_ecmp is not None:
                            configurations.append_line(
                                f'global max-ecmp-paths {max_ecmp}'
                            )

                        auto_cost_en = attributes.value('auto_cost_enabled')
                        if auto_cost_en is not None:
                            enabled_str = 'true' if auto_cost_en else 'false'
                            configurations.append_line(
                                f'global auto-cost enabled {enabled_str}'
                            )

                        auto_cost_bw = attributes.value(
                            'auto_cost_reference_bandwidth'
                        )
                        if auto_cost_bw is not None:
                            configurations.append_line(
                                f'global auto-cost reference-bandwidth '
                                f'{auto_cost_bw}'
                            )

                        log_adj = attributes.value('log_adjacency_changes')
                        if log_adj:
                            configurations.append_line(
                                f'global log-adjacency-changes {log_adj}'
                            )

                        # ========================================
                        # PHASE 2 -- Route preference
                        # ========================================

                        rp_intra = attributes.value(
                            'route_preference_intra_area'
                        )
                        if rp_intra is not None:
                            configurations.append_line(
                                f'global route-preference intra-area '
                                f'{rp_intra}'
                            )

                        rp_inter = attributes.value(
                            'route_preference_inter_area'
                        )
                        if rp_inter is not None:
                            configurations.append_line(
                                f'global route-preference inter-area '
                                f'{rp_inter}'
                            )

                        rp_ext = attributes.value(
                            'route_preference_external'
                        )
                        if rp_ext is not None:
                            configurations.append_line(
                                f'global route-preference external {rp_ext}'
                            )

                        # ========================================
                        # PHASE 3 -- SPF throttle timers
                        # ========================================

                        spf_init = attributes.value('spf_initial_delay')
                        if spf_init is not None:
                            configurations.append_line(
                                'global spf throttle timers '
                                f'spf-initial-delay {spf_init}'
                            )

                        spf_short = attributes.value('spf_short_delay')
                        if spf_short is not None:
                            configurations.append_line(
                                'global spf throttle timers '
                                f'spf-short-delay {spf_short}'
                            )

                        spf_long = attributes.value('spf_long_delay')
                        if spf_long is not None:
                            configurations.append_line(
                                'global spf throttle timers '
                                f'spf-long-delay {spf_long}'
                            )

                        spf_ttl = attributes.value('spf_time_to_learn')
                        if spf_ttl is not None:
                            configurations.append_line(
                                'global spf throttle timers '
                                f'time-to-learn-interval {spf_ttl}'
                            )

                        spf_hd = attributes.value('spf_holddown')
                        if spf_hd is not None:
                            configurations.append_line(
                                'global spf throttle timers '
                                f'holddown-interval {spf_hd}'
                            )

                        # Phase 3 -- SPF logging
                        spf_max_logs = attributes.value('spf_log_max_logs')
                        if spf_max_logs is not None:
                            configurations.append_line(
                                f'global spf logging maximum-logs '
                                f'{spf_max_logs}'
                            )

                        spf_max_trig = attributes.value(
                            'spf_log_max_triggers'
                        )
                        if spf_max_trig is not None:
                            configurations.append_line(
                                'global spf logging '
                                f'maximum-triggers-per-log {spf_max_trig}'
                            )

                        # ========================================
                        # PHASE 3 -- LSA timers
                        # ========================================

                        lsa_min = attributes.value('lsa_min_arrival')
                        if lsa_min is not None:
                            configurations.append_line(
                                f'global timers lsa min-arrival {lsa_min}'
                            )

                        lsa_start = attributes.value('lsa_origination_start')
                        lsa_hold = attributes.value('lsa_origination_hold')
                        lsa_max = attributes.value('lsa_origination_max')
                        if lsa_start is not None:
                            parts = [str(lsa_start)]
                            if lsa_hold is not None:
                                parts.append(str(lsa_hold))
                            if lsa_max is not None:
                                parts.append(str(lsa_max))
                            configurations.append_line(
                                'global timers lsa origination-delay '
                                + ' '.join(parts)
                            )

                        # ========================================
                        # PHASE 3 -- Max-LSA
                        # ========================================

                        max_lsa = attributes.value('max_lsa_limit')
                        if max_lsa is not None:
                            configurations.append_line(
                                f'global max-lsa lsa-limit {max_lsa}'
                            )

                        max_lsa_warn = attributes.value(
                            'max_lsa_warning_threshold'
                        )
                        if max_lsa_warn is not None:
                            configurations.append_line(
                                'global max-lsa warning-threshold '
                                f'{max_lsa_warn}'
                            )

                        max_lsa_wo = attributes.value('max_lsa_warning_only')
                        if max_lsa_wo is not None:
                            wo_str = 'true' if max_lsa_wo else 'false'
                            configurations.append_line(
                                f'global max-lsa warning-only {wo_str}'
                            )

                        max_lsa_ads = attributes.value(
                            'max_lsa_avoid_down_state'
                        )
                        if max_lsa_ads is not None:
                            ads_str = 'true' if max_lsa_ads else 'false'
                            configurations.append_line(
                                f'global max-lsa avoid-down-state {ads_str}'
                            )

                        max_lsa_lmt = attributes.value(
                            'max_lsa_limit_monitor_time'
                        )
                        if max_lsa_lmt is not None:
                            configurations.append_line(
                                'global max-lsa limit-monitor-time '
                                f'{max_lsa_lmt}'
                            )

                        max_lsa_drt = attributes.value(
                            'max_lsa_down_recovery_time'
                        )
                        if max_lsa_drt is not None:
                            configurations.append_line(
                                'global max-lsa down-recovery-time '
                                f'{max_lsa_drt}'
                            )

                        # ========================================
                        # PHASE 3 -- Maintenance mode
                        # ========================================

                        mm_always = attributes.value(
                            'maintenance_mode_always'
                        )
                        if mm_always is not None:
                            mm_str = 'true' if mm_always else 'false'
                            configurations.append_line(
                                'global maintenance-mode trigger always '
                                f'{mm_str}'
                            )

                        mm_startup = attributes.value(
                            'maintenance_mode_on_startup'
                        )
                        if mm_startup is not None:
                            configurations.append_line(
                                'global maintenance-mode trigger on-startup '
                                f'{mm_startup}'
                            )

                        mm_rlsa_metric = attributes.value(
                            'maintenance_mode_router_lsa_metric'
                        )
                        if mm_rlsa_metric is not None:
                            configurations.append_line(
                                'global maintenance-mode router-lsa metric '
                                f'{mm_rlsa_metric}'
                            )

                        mm_rlsa_link = attributes.value(
                            'maintenance_mode_router_lsa_set_link_metric'
                        )
                        if mm_rlsa_link is not None:
                            link_str = 'true' if mm_rlsa_link else 'false'
                            configurations.append_line(
                                'global maintenance-mode router-lsa '
                                f'set-link-metric {link_str}'
                            )

                        mm_rlsa_stub = attributes.value(
                            'maintenance_mode_router_lsa_set_stub_metric'
                        )
                        if mm_rlsa_stub is not None:
                            stub_str = 'true' if mm_rlsa_stub else 'false'
                            configurations.append_line(
                                'global maintenance-mode router-lsa '
                                f'set-stub-metric {stub_str}'
                            )

                        mm_slsa_metric = attributes.value(
                            'maintenance_mode_summary_lsa_metric'
                        )
                        if mm_slsa_metric is not None:
                            configurations.append_line(
                                'global maintenance-mode summary-lsa metric '
                                f'{mm_slsa_metric}'
                            )

                        mm_slsa_set = attributes.value(
                            'maintenance_mode_summary_lsa_set_metric'
                        )
                        if mm_slsa_set is not None:
                            set_str = 'true' if mm_slsa_set else 'false'
                            configurations.append_line(
                                'global maintenance-mode summary-lsa '
                                f'set-metric {set_str}'
                            )

                        mm_elsa_metric = attributes.value(
                            'maintenance_mode_external_lsa_metric'
                        )
                        if mm_elsa_metric is not None:
                            configurations.append_line(
                                'global maintenance-mode external-lsa metric '
                                f'{mm_elsa_metric}'
                            )

                        mm_elsa_set = attributes.value(
                            'maintenance_mode_external_lsa_set_metric'
                        )
                        if mm_elsa_set is not None:
                            eset_str = 'true' if mm_elsa_set else 'false'
                            configurations.append_line(
                                'global maintenance-mode external-lsa '
                                f'set-metric {eset_str}'
                            )

                        # ========================================
                        # PHASE 3 -- Redistribute aggregates (IPv6)
                        # ========================================

                        redist_aggs = attributes.value(
                            'redistribute_aggregates'
                        )
                        if redist_aggs and isinstance(redist_aggs, dict):
                            for prefix in sorted(redist_aggs.keys()):
                                agg_attrs = redist_aggs[prefix]
                                if not isinstance(agg_attrs, dict):
                                    configurations.append_line(
                                        'global redistribute-aggregate '
                                        f'{prefix}'
                                    )
                                    configurations.append_line('!')
                                    continue
                                with configurations.submode_context(
                                    'global redistribute-aggregate '
                                    f'{prefix}'
                                ):
                                    advertise = agg_attrs.get('advertise')
                                    if advertise:
                                        configurations.append_line(
                                            f'advertise {advertise}'
                                        )
                                    import_policy = agg_attrs.get(
                                        'import_policy'
                                    )
                                    if import_policy:
                                        configurations.append_line(
                                            f'import-policy {import_policy}'
                                        )
                                configurations.append_line('!')

                        # ========================================
                        # AREA CONFIGURATION
                        # ========================================

                        for sub, area_attributes in attributes.mapping_values(
                            'area_attr', sort=True
                        ):
                            area_config = sub.build_config(
                                apply=False,
                                attributes=area_attributes,
                                unconfig=unconfig,
                            )
                            if area_config:
                                configurations.append_block(area_config)

                    # End protocol OSPF3
                    configurations.append_line('!')
                # End network-instance
                configurations.append_line('!')

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
            """Build unconfiguration commands."""
            return self.build_config(
                apply=apply, attributes=attributes, unconfig=True, **kwargs
            )

        # ============================================================
        # AREA ATTRIBUTES
        # ============================================================

        class AreaAttributes(ABC):
            """Area-level OSPFv3 attributes for ArcOS."""

            # Phase 1 -- Core area attributes
            area_type = managedattribute(
                name='area_type',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Area type: AREA_TYPE_NORMAL or AREA_TYPE_STUB')

            stub_default_cost = managedattribute(
                name='stub_default_cost',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Metric for default route into stub area (default 1)')

            advertise_summary_lsas = managedattribute(
                name='advertise_summary_lsas',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Advertise summary LSAs into this area (default true)')

            # Phase 2 -- Summary aggregates (area level, IPv6)
            summary_aggregates = managedattribute(
                name='summary_aggregates',
                default=None,
                type=(None, managedattribute.test_istype(dict)),
                doc='Dict of IPv6 prefix -> {advertise: str, import_policy: str}')

            def build_config(
                self,
                apply=True,
                attributes=None,
                unconfig=False,
                **kwargs,
            ):
                """Build area-level OSPFv3 configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                area_id = str(self.area_id)

                with configurations.submode_context(f'area {area_id}'):

                    # Phase 1 -- Area type
                    a_type = attributes.value('area_type')
                    if a_type:
                        configurations.append_line(f'area-type {a_type}')

                    # Phase 1 -- Stub default cost
                    stub_cost = attributes.value('stub_default_cost')
                    if stub_cost is not None:
                        configurations.append_line(
                            f'stub-default-cost {stub_cost}'
                        )

                    # Phase 1 -- Advertise summary LSAs
                    adv_summary = attributes.value('advertise_summary_lsas')
                    if adv_summary is not None:
                        adv_str = 'true' if adv_summary else 'false'
                        configurations.append_line(
                            f'advertise-summary-lsas {adv_str}'
                        )

                    # Phase 2 -- Summary aggregates (IPv6)
                    sum_aggs = attributes.value('summary_aggregates')
                    if sum_aggs and isinstance(sum_aggs, dict):
                        for prefix in sorted(sum_aggs.keys()):
                            agg_attrs = sum_aggs[prefix]
                            if not isinstance(agg_attrs, dict):
                                configurations.append_line(
                                    f'summary-aggregate {prefix}'
                                )
                                configurations.append_line('!')
                                continue
                            with configurations.submode_context(
                                f'summary-aggregate {prefix}'
                            ):
                                advertise = agg_attrs.get('advertise')
                                if advertise:
                                    configurations.append_line(
                                        f'advertise {advertise}'
                                    )
                                import_policy = agg_attrs.get('import_policy')
                                if import_policy:
                                    configurations.append_line(
                                        f'import-policy {import_policy}'
                                    )
                            configurations.append_line('!')

                    # Interface configuration within this area
                    for sub, intf_attributes in attributes.mapping_values(
                        'interface_attr', sort=True
                    ):
                        intf_config = sub.build_config(
                            apply=False,
                            attributes=intf_attributes,
                            unconfig=unconfig,
                        )
                        if intf_config:
                            configurations.append_block(intf_config)

                configurations.append_line('!')

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=True, attributes=None, **kwargs):
                """Build area-level unconfiguration."""
                return self.build_config(
                    apply=apply,
                    attributes=attributes,
                    unconfig=True,
                    **kwargs,
                )

            # ========================================================
            # INTERFACE ATTRIBUTES (within an area)
            # ========================================================

            class InterfaceAttributes(ABC):
                """Interface-specific OSPFv3 attributes for ArcOS."""

                # Phase 1 -- Core interface attributes
                metric = managedattribute(
                    name='metric',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='Interface metric/cost (1-65535, default 10)')

                network_type = managedattribute(
                    name='network_type',
                    default=None,
                    type=(None, managedattribute.test_istype(str)),
                    doc='Network type: BROADCAST_NETWORK or '
                        'POINT_TO_POINT_NETWORK')

                passive = managedattribute(
                    name='passive',
                    default=None,
                    type=(None, managedattribute.test_istype(bool)),
                    doc='Passive interface (default false)')

                hello_interval = managedattribute(
                    name='hello_interval',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='Hello interval in seconds (default 10)')

                dead_interval = managedattribute(
                    name='dead_interval',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='Dead interval in seconds (default 40)')

                retransmit_interval = managedattribute(
                    name='retransmit_interval',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='Retransmission interval in seconds (default 5)')

                transmission_delay = managedattribute(
                    name='transmission_delay',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='Transmission delay in seconds (default 1)')

                # Phase 2 -- Hardening interface attributes
                priority = managedattribute(
                    name='priority',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='DR priority (0-255, default 1)')

                ignore_mtu = managedattribute(
                    name='ignore_mtu',
                    default=None,
                    type=(None, managedattribute.test_istype(bool)),
                    doc='Bypass DB exchange MTU check (default false)')

                # OSPFv3-specific: instance-id
                instance_id = managedattribute(
                    name='instance_id',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='OSPFv3 instance ID per interface (0-255, default 0)')

                # OSPFv3-specific: interface-id
                interface_id_value = managedattribute(
                    name='interface_id_value',
                    default=None,
                    type=(None, managedattribute.test_istype(int)),
                    doc='OSPFv3 interface ID (0-4294967295, auto-generated '
                        'if not set)')

                # BFD
                bfd_enabled = managedattribute(
                    name='bfd_enabled',
                    default=None,
                    type=(None, managedattribute.test_istype(bool)),
                    doc='Enable BFD on this interface (default false)')

                bfd_profile = managedattribute(
                    name='bfd_profile',
                    default=None,
                    type=(None, managedattribute.test_istype(str)),
                    doc='BFD profile name (default GLOBAL)')

                def build_config(
                    self,
                    apply=True,
                    attributes=None,
                    unconfig=False,
                    **kwargs,
                ):
                    """Build interface-specific OSPFv3 configuration."""
                    assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                    attributes = AttributesHelper(self, attributes)
                    configurations = CliConfigBuilder(unconfig=unconfig)

                    intf_name = (
                        attributes.value('interface_name_value')
                        or self.interface_name
                    )

                    with configurations.submode_context(
                        f'interface {intf_name}'
                    ):
                        # Phase 1 -- metric
                        metric = attributes.value('metric')
                        if metric is not None:
                            configurations.append_line(f'metric {metric}')

                        # Phase 1 -- network type
                        net_type = attributes.value('network_type')
                        if net_type:
                            configurations.append_line(
                                f'network-type {net_type}'
                            )

                        # Phase 1 -- passive
                        passive = attributes.value('passive')
                        if passive is not None:
                            passive_str = 'true' if passive else 'false'
                            configurations.append_line(
                                f'passive {passive_str}'
                            )

                        # Phase 2 -- priority
                        prio = attributes.value('priority')
                        if prio is not None:
                            configurations.append_line(f'priority {prio}')

                        # Phase 2 -- ignore-mtu
                        ign_mtu = attributes.value('ignore_mtu')
                        if ign_mtu is not None:
                            mtu_str = 'true' if ign_mtu else 'false'
                            configurations.append_line(
                                f'ignore-mtu {mtu_str}'
                            )

                        # OSPFv3-specific: instance-id
                        inst_id = attributes.value('instance_id')
                        if inst_id is not None:
                            configurations.append_line(
                                f'instance-id {inst_id}'
                            )

                        # OSPFv3-specific: interface-id
                        intf_id_val = attributes.value('interface_id_value')
                        if intf_id_val is not None:
                            configurations.append_line(
                                f'interface-id {intf_id_val}'
                            )

                        # Phase 1 -- timers
                        hello = attributes.value('hello_interval')
                        if hello is not None:
                            configurations.append_line(
                                f'timers hello-interval {hello}'
                            )

                        dead = attributes.value('dead_interval')
                        if dead is not None:
                            configurations.append_line(
                                f'timers dead-interval {dead}'
                            )

                        retx = attributes.value('retransmit_interval')
                        if retx is not None:
                            configurations.append_line(
                                f'timers retransmission-interval {retx}'
                            )

                        tx_delay = attributes.value('transmission_delay')
                        if tx_delay is not None:
                            configurations.append_line(
                                f'timers transmission-delay {tx_delay}'
                            )

                        # Phase 2 -- BFD
                        bfd_en = attributes.value('bfd_enabled')
                        if bfd_en is not None:
                            bfd_str = 'true' if bfd_en else 'false'
                            configurations.append_line(
                                f'bfd enabled {bfd_str}'
                            )

                        bfd_prof = attributes.value('bfd_profile')
                        if bfd_prof:
                            configurations.append_line(
                                f'bfd profile {bfd_prof}'
                            )

                    configurations.append_line('!')

                    return CliConfig(
                        device=self.device,
                        unconfig=unconfig,
                        cli_config=configurations,
                    )

                def build_unconfig(
                    self, apply=True, attributes=None, **kwargs
                ):
                    """Build interface-level OSPFv3 unconfiguration."""
                    return self.build_config(
                        apply=apply,
                        attributes=attributes,
                        unconfig=True,
                        **kwargs,
                    )
