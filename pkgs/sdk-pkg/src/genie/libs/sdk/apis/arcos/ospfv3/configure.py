"""ArcOS OSPFv3 configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_CTX = 'network-instance default protocol OSPF3 default'


def configure_ospfv3_router_id(device, router_id):
    """Configure OSPFv3 router-id."""
    log.info(f"Configuring OSPFv3 router-id {router_id} on {device.name}")
    try:
        device.configure([_CTX, f'global router-id {router_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 router-id failed on {device.name}: {e}")


def unconfigure_ospfv3_router_id(device):
    """Remove OSPFv3 router-id."""
    log.info(f"Removing OSPFv3 router-id from {device.name}")
    try:
        device.configure([_CTX, 'no global router-id', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 router-id removal failed on {device.name}: {e}")


def configure_ospfv3_area(device, area_id, area_type='AREA_TYPE_NORMAL',
                          stub_default_cost=None):
    """Configure OSPFv3 area."""
    log.info(f"Configuring OSPFv3 area {area_id} on {device.name}")
    config = [f'{_CTX} area {area_id}', f'area-type {area_type}']
    if stub_default_cost is not None:
        config.append(f'stub-default-cost {stub_default_cost}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 area failed on {device.name}: {e}")


def unconfigure_ospfv3_area(device, area_id):
    """Remove OSPFv3 area."""
    log.info(f"Removing OSPFv3 area {area_id} from {device.name}")
    try:
        device.configure([f'no {_CTX} area {area_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 area removal failed on {device.name}: {e}")


def configure_ospfv3_interface(device, area_id, interface, network_type=None,
                               passive=None, hello_interval=None,
                               dead_interval=None, instance_id=None,
                               metric=None, priority=None,
                               retransmission_interval=None,
                               transmission_delay=None,
                               bfd_enabled=None, bfd_profile=None,
                               ignore_mtu=None, interface_id=None,
                               network_instance='default',
                               protocol_instance='default'):
    """Configure OSPFv3 interface in an area.

    Extended (v3 sanity/features parity with v2 + v3-specific fields).
    """
    log.info(
        f"Configuring OSPFv3 interface {interface} in area {area_id} on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance) \
        if (network_instance != 'default' or protocol_instance != 'default') else _CTX
    config = [
        ctx,
        f'area {area_id}',
        f'interface {interface}',
    ]
    if network_type:
        config.append(f'network-type {network_type}')
    if passive is not None:
        config.append(f'passive {"true" if passive else "false"}')
    if metric is not None:
        config.append(f'metric {metric}')
    if priority is not None:
        config.append(f'priority {priority}')
    if hello_interval is not None:
        config.append(f'timers hello-interval {hello_interval}')
    if dead_interval is not None:
        config.append(f'timers dead-interval {dead_interval}')
    if retransmission_interval is not None:
        config.append(f'timers retransmission-interval {retransmission_interval}')
    if transmission_delay is not None:
        config.append(f'timers transmission-delay {transmission_delay}')
    if bfd_enabled is not None:
        config.append(f'bfd enabled {"true" if bfd_enabled else "false"}')
    if bfd_profile is not None:
        config.append(f'bfd profile {bfd_profile}')
    if ignore_mtu is not None:
        config.append(f'ignore-mtu {"true" if ignore_mtu else "false"}')
    if instance_id is not None:
        config.append(f'instance-id {instance_id}')
    if interface_id is not None:
        config.append(f'interface-id {interface_id}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 interface failed on {device.name}: {e}")


def unconfigure_ospfv3_interface(device, area_id, interface):
    """Remove OSPFv3 interface from area."""
    log.info(f"Removing OSPFv3 interface {interface} from area {area_id} on {device.name}")
    try:
        device.configure([f'{_CTX} area {area_id}', f'no interface {interface}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 interface removal failed on {device.name}: {e}")


def unconfigure_ospfv3(device):
    """Remove entire OSPFv3 configuration."""
    log.info(f"Removing OSPFv3 from {device.name}")
    try:
        device.configure([f'no {_CTX}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 removal failed on {device.name}: {e}")


# ---------------------------------------------------------------------------
# Batch A — sanity-plan blockers (mirrors OSPFv2 batch A)
# ---------------------------------------------------------------------------

def _build_ospfv3_context(network_instance='default', protocol_instance='default'):
    """Build OSPFv3 protocol-instance configuration context."""
    return f'network-instance {network_instance} protocol OSPF3 {protocol_instance}'


def configure_ospfv3_max_ecmp_paths(device, paths,
                                     network_instance='default',
                                     protocol_instance='default'):
    """Configure OSPFv3 global max-ecmp-paths (1..128)."""
    log.info(f"Configuring OSPFv3 max-ecmp-paths {paths} on {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, f'global max-ecmp-paths {paths}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 max-ecmp-paths failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_max_ecmp_paths(device,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Remove OSPFv3 max-ecmp-paths."""
    log.info(f"Removing OSPFv3 max-ecmp-paths from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global max-ecmp-paths', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 max-ecmp-paths removal failed on {device.name}: {e}"
        )


def configure_ospfv3_auto_cost(device, enabled=True, reference_bandwidth=None,
                                network_instance='default',
                                protocol_instance='default'):
    """Configure OSPFv3 auto-cost."""
    log.info(
        f"Configuring OSPFv3 auto-cost (enabled={enabled}, "
        f"ref-bw={reference_bandwidth}) on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx, f'global auto-cost enabled {"true" if enabled else "false"}']
    if reference_bandwidth is not None:
        cfg.append(f'global auto-cost reference-bandwidth {reference_bandwidth}')
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 auto-cost failed on {device.name}: {e}")


def unconfigure_ospfv3_auto_cost(device,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Remove OSPFv3 auto-cost."""
    log.info(f"Removing OSPFv3 auto-cost from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global auto-cost', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 auto-cost removal failed on {device.name}: {e}"
        )


def configure_ospfv3_stub_default_cost(device, area_id, cost,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure stub-default-cost for an OSPFv3 stub area."""
    log.info(
        f"Configuring OSPFv3 area {area_id} stub-default-cost {cost} on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'area {area_id}', f'stub-default-cost {cost}', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 stub-default-cost failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_stub_default_cost(device, area_id,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove stub-default-cost for an OSPFv3 stub area."""
    log.info(
        f"Removing OSPFv3 area {area_id} stub-default-cost from {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'area {area_id}', 'no stub-default-cost', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 stub-default-cost removal failed on {device.name}: {e}"
        )


def configure_ospfv3_advertise_summary_lsas(device, area_id, enabled,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure advertise-summary-lsas for an OSPFv3 area."""
    val = "true" if enabled else "false"
    log.info(
        f"Configuring OSPFv3 area {area_id} advertise-summary-lsas {val} on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'area {area_id}',
            f'advertise-summary-lsas {val}', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 advertise-summary-lsas failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_advertise_summary_lsas(device, area_id,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove advertise-summary-lsas (revert to default true)."""
    log.info(
        f"Removing OSPFv3 area {area_id} advertise-summary-lsas from {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'area {area_id}', 'no advertise-summary-lsas', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 advertise-summary-lsas removal failed on {device.name}: {e}"
        )


def configure_ospfv3_spf_throttle(device, initial_delay=None, short_delay=None,
                                   long_delay=None, time_to_learn=None,
                                   holddown=None,
                                   network_instance='default',
                                   protocol_instance='default'):
    """Configure OSPFv3 SPF throttle timers (RFC 8405)."""
    log.info(f"Configuring OSPFv3 SPF throttle on {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx]
    if initial_delay is not None:
        cfg.append(f'global spf throttle timers spf-initial-delay {initial_delay}')
    if short_delay is not None:
        cfg.append(f'global spf throttle timers spf-short-delay {short_delay}')
    if long_delay is not None:
        cfg.append(f'global spf throttle timers spf-long-delay {long_delay}')
    if time_to_learn is not None:
        cfg.append(f'global spf throttle timers time-to-learn-interval {time_to_learn}')
    if holddown is not None:
        cfg.append(f'global spf throttle timers holddown-interval {holddown}')
    if len(cfg) == 1:
        log.warning(
            "configure_ospfv3_spf_throttle: no timer values provided; nothing to configure"
        )
        return
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 SPF throttle failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_spf_throttle(device,
                                     network_instance='default',
                                     protocol_instance='default'):
    """Remove all OSPFv3 SPF throttle timer config (revert to defaults)."""
    log.info(f"Removing OSPFv3 SPF throttle from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [
        ctx,
        'no global spf throttle timers spf-initial-delay',
        'no global spf throttle timers spf-short-delay',
        'no global spf throttle timers spf-long-delay',
        'no global spf throttle timers time-to-learn-interval',
        'no global spf throttle timers holddown-interval',
        '!',
    ]
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 SPF throttle removal failed on {device.name}: {e}"
        )


# ---------------------------------------------------------------------------
# Batch B — features-plan blockers (mirrors OSPFv2 batch B; auth dropped)
# ---------------------------------------------------------------------------

def configure_ospfv3_interface_ignore_mtu(device, area_id, interface, enabled,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Enable or disable OSPFv3 DD-packet MTU checking on an interface."""
    val = "true" if enabled else "false"
    log.info(
        f"Configuring OSPFv3 ignore-mtu {val} on {interface} area {area_id} on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'area {area_id}', f'interface {interface}',
            f'ignore-mtu {val}', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 ignore-mtu failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_interface_ignore_mtu(device, area_id, interface,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove ignore-mtu (revert to default false)."""
    log.info(
        f"Removing OSPFv3 ignore-mtu from {interface} area {area_id} on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'area {area_id}', f'interface {interface}',
            'no ignore-mtu', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 ignore-mtu removal failed on {device.name}: {e}"
        )


def configure_ospfv3_table_connection(device, src_protocol, afi="IPV6",
                                       src_dst_instance=None,
                                       import_policy=None,
                                       network_instance='default'):
    """Configure redistribution INTO OSPFv3 via table-connection.

    Thin wrapper around ``configure_network_instance_table_connection``
    with ``dst_proto="OSPF3"``. Default ``afi="IPV6"`` for v3.
    """
    from genie.libs.sdk.apis.arcos.network_instance.configure import (
        configure_network_instance_table_connection,
    )
    return configure_network_instance_table_connection(
        device, ni_name=network_instance, src_proto=src_protocol,
        dst_proto="OSPF3", af=afi,
        src_dst_instance=src_dst_instance, import_policy=import_policy,
    )


def unconfigure_ospfv3_table_connection(device, src_protocol, afi="IPV6",
                                         network_instance='default'):
    """Remove redistribution INTO OSPFv3 (table-connection)."""
    from genie.libs.sdk.apis.arcos.network_instance.configure import (
        unconfigure_network_instance_table_connection,
    )
    return unconfigure_network_instance_table_connection(
        device, ni_name=network_instance, src_proto=src_protocol,
        dst_proto="OSPF3", af=afi,
    )


def configure_ospfv3_redistribute_aggregate(device, prefix,
                                             advertise=None,
                                             import_policy=None,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure OSPFv3 global redistribute-aggregate."""
    log.info(
        f"Configuring OSPFv3 redistribute-aggregate {prefix} on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx, f'global redistribute-aggregate {prefix}']
    if advertise is not None:
        cfg.append(f'advertise {advertise}')
    if import_policy is not None:
        cfg.append(f'import-policy {import_policy}')
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 redistribute-aggregate failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_redistribute_aggregate(device, prefix,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Remove an OSPFv3 global redistribute-aggregate prefix."""
    log.info(
        f"Removing OSPFv3 redistribute-aggregate {prefix} from {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'global no redistribute-aggregate {prefix}', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 redistribute-aggregate removal failed on {device.name}: {e}"
        )


def configure_ospfv3_summary_aggregate(device, area_id, prefix,
                                        advertise=None,
                                        import_policy=None,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Configure an OSPFv3 area-level summary-aggregate prefix."""
    log.info(
        f"Configuring OSPFv3 area {area_id} summary-aggregate {prefix} on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx, f'area {area_id}', f'summary-aggregate {prefix}']
    if advertise is not None:
        cfg.append(f'advertise {advertise}')
    if import_policy is not None:
        cfg.append(f'import-policy {import_policy}')
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 summary-aggregate failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_summary_aggregate(device, area_id, prefix,
                                          network_instance='default',
                                          protocol_instance='default'):
    """Remove an OSPFv3 area summary-aggregate prefix."""
    log.info(
        f"Removing OSPFv3 area {area_id} summary-aggregate {prefix} from {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, f'area {area_id}', f'no summary-aggregate {prefix}', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 summary-aggregate removal failed on {device.name}: {e}"
        )


def configure_ospfv3_route_preference(device,
                                       intra_area=None,
                                       inter_area=None,
                                       external=None,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure OSPFv3 RIB route-preferences (0..255 per type)."""
    log.info(
        f"Configuring OSPFv3 route-preference (intra={intra_area}, "
        f"inter={inter_area}, external={external}) on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    parts = []
    if intra_area is not None:
        parts.append(f'intra-area {intra_area}')
    if inter_area is not None:
        parts.append(f'inter-area {inter_area}')
    if external is not None:
        parts.append(f'external {external}')
    if not parts:
        log.warning(
            "configure_ospfv3_route_preference: no preferences supplied; nothing to configure"
        )
        return
    cfg = [ctx, 'global route-preference ' + ' '.join(parts), '!']
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 route-preference failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_route_preference(device,
                                         intra_area=False,
                                         inter_area=False,
                                         external=False,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Remove OSPFv3 route-preference settings."""
    log.info(f"Removing OSPFv3 route-preference from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx]
    if intra_area:
        cfg.append('global no route-preference intra-area')
    if inter_area:
        cfg.append('global no route-preference inter-area')
    if external:
        cfg.append('global no route-preference external')
    if len(cfg) == 1:
        cfg.extend([
            'global no route-preference intra-area',
            'global no route-preference inter-area',
            'global no route-preference external',
        ])
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 route-preference removal failed on {device.name}: {e}"
        )


def configure_ospfv3_max_lsa(device,
                              lsa_limit=None,
                              warning_threshold=None,
                              warning_only=None,
                              avoid_down_state=None,
                              limit_monitor_time=None,
                              down_recovery_time=None,
                              network_instance='default',
                              protocol_instance='default'):
    """Configure OSPFv3 global max-lsa parameters."""
    log.info(f"Configuring OSPFv3 max-lsa on {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx]
    if lsa_limit is not None:
        cfg.append(f'global max-lsa lsa-limit {lsa_limit}')
    if warning_threshold is not None:
        cfg.append(f'global max-lsa warning-threshold {warning_threshold}')
    if warning_only is not None:
        cfg.append(f'global max-lsa warning-only {"true" if warning_only else "false"}')
    if avoid_down_state is not None:
        cfg.append(
            f'global max-lsa avoid-down-state {"true" if avoid_down_state else "false"}'
        )
    if limit_monitor_time is not None:
        cfg.append(f'global max-lsa limit-monitor-time {limit_monitor_time}')
    if down_recovery_time is not None:
        cfg.append(f'global max-lsa down-recovery-time {down_recovery_time}')
    if len(cfg) == 1:
        log.warning("configure_ospfv3_max_lsa: nothing to configure")
        return
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 max-lsa failed on {device.name}: {e}")


def unconfigure_ospfv3_max_lsa(device,
                                network_instance='default',
                                protocol_instance='default'):
    """Remove OSPFv3 max-lsa configuration entirely."""
    log.info(f"Removing OSPFv3 max-lsa from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global max-lsa', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPFv3 max-lsa removal failed on {device.name}: {e}")


def configure_ospfv3_maintenance_mode(device,
                                       router_lsa_metric=None,
                                       router_lsa_set_link_metric=None,
                                       router_lsa_set_stub_metric=None,
                                       summary_lsa_metric=None,
                                       summary_lsa_set_metric=None,
                                       external_lsa_metric=None,
                                       external_lsa_set_metric=None,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure OSPFv3 maintenance-mode LSA metric parameters."""
    log.info(f"Configuring OSPFv3 maintenance-mode LSA params on {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx]
    if router_lsa_metric is not None:
        cfg.append(f'global maintenance-mode router-lsa metric {router_lsa_metric}')
    if router_lsa_set_link_metric is not None:
        cfg.append(
            f'global maintenance-mode router-lsa set-link-metric '
            f'{"true" if router_lsa_set_link_metric else "false"}'
        )
    if router_lsa_set_stub_metric is not None:
        cfg.append(
            f'global maintenance-mode router-lsa set-stub-metric '
            f'{"true" if router_lsa_set_stub_metric else "false"}'
        )
    if summary_lsa_metric is not None:
        cfg.append(f'global maintenance-mode summary-lsa metric {summary_lsa_metric}')
    if summary_lsa_set_metric is not None:
        cfg.append(
            f'global maintenance-mode summary-lsa set-metric '
            f'{"true" if summary_lsa_set_metric else "false"}'
        )
    if external_lsa_metric is not None:
        cfg.append(f'global maintenance-mode external-lsa metric {external_lsa_metric}')
    if external_lsa_set_metric is not None:
        cfg.append(
            f'global maintenance-mode external-lsa set-metric '
            f'{"true" if external_lsa_set_metric else "false"}'
        )
    if len(cfg) == 1:
        log.warning("configure_ospfv3_maintenance_mode: nothing to configure")
        return
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 maintenance-mode failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_maintenance_mode(device,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Remove all OSPFv3 maintenance-mode configuration."""
    log.info(f"Removing OSPFv3 maintenance-mode from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global maintenance-mode', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 maintenance-mode removal failed on {device.name}: {e}"
        )


def configure_ospfv3_maintenance_mode_trigger(device,
                                                always=None,
                                                on_startup=None,
                                                network_instance='default',
                                                protocol_instance='default'):
    """Configure OSPFv3 maintenance-mode trigger."""
    log.info(
        f"Configuring OSPFv3 maintenance-mode trigger "
        f"(always={always}, on_startup={on_startup}) on {device.name}"
    )
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    cfg = [ctx]
    if always is not None:
        cfg.append(
            f'global maintenance-mode trigger always {"true" if always else "false"}'
        )
    if on_startup is not None:
        cfg.append(f'global maintenance-mode trigger on-startup {on_startup}')
    if len(cfg) == 1:
        log.warning("configure_ospfv3_maintenance_mode_trigger: nothing to configure")
        return
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 maintenance-mode trigger failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_maintenance_mode_trigger(device,
                                                  network_instance='default',
                                                  protocol_instance='default'):
    """Remove OSPFv3 maintenance-mode trigger."""
    log.info(f"Removing OSPFv3 maintenance-mode trigger from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, 'no global maintenance-mode trigger', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 maintenance-mode trigger removal failed on {device.name}: {e}"
        )


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-05 — OSPFv3 logging, SPF-log and LSA timers
# (arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md)
#
# Leaf names and enums confirmed by `?` capture on rtr1 2026-08-17. The audit's
# "triggers-per-log" is really `maximum-triggers-per-log`.
# ---------------------------------------------------------------------------


#: Accepted values for ``configure_ospfv3_log_adjacency_changes(mode=...)``.
#: Device-confirmed enum (`global log-adjacency-changes ?` on rtr1 2026-08-17).
OSPFV3_LOG_ADJ_MODES = (
    'LOG_ADJ_DISABLE',
    'LOG_ADJ_ENABLE_LIMITED',
    'LOG_ADJ_ENABLE_DETAILED',
)


def _spf_logging_lines(maximum_logs, maximum_triggers_per_log):
    """Build the `global spf logging` leaf lines. Raises if both are None."""
    if maximum_logs is None and maximum_triggers_per_log is None:
        raise ValueError(
            "spf_logging requires at least one of 'maximum_logs' or "
            "'maximum_triggers_per_log'"
        )
    lines = []
    if maximum_logs is not None:
        lines.append(f'global spf logging maximum-logs {maximum_logs}')
    if maximum_triggers_per_log is not None:
        lines.append(
            f'global spf logging maximum-triggers-per-log {maximum_triggers_per_log}')
    return lines


def _lsa_timer_lines(min_arrival):
    """Build the `global timers lsa` leaf lines.

    Only ``min-arrival`` is settable. ``origination-delay`` appears in the CLI's
    own `?` completions with a value type (`<unsignedInt, 0..600000>[50]`), but
    the device REJECTS every assignment to it:

        global timers lsa origination-delay 50   -> syntax error: unknown argument
        global timers lsa origination-delay 50 60 -> syntax error: incomplete path

    Confirmed on rtr1 2026-08-17 for BOTH OSPF and OSPF3, on a clean instance
    with no config lock held. No API is offered for it rather than one that
    always fails.
    """
    if min_arrival is None:
        raise ValueError("timers_lsa requires 'min_arrival'")
    return [f'global timers lsa min-arrival {min_arrival}']


def configure_ospfv3_log_adjacency_changes(device, mode, network_instance='default',
                                           protocol_instance='default'):
    """Configure OSPFv3 global log-adjacency-changes.

    ``mode`` is one of :data:`OSPFV3_LOG_ADJ_MODES`.
    """
    if mode not in OSPFV3_LOG_ADJ_MODES:
        raise ValueError(
            f"Invalid mode '{mode}'. Must be one of: "
            f"{', '.join(OSPFV3_LOG_ADJ_MODES)}"
        )
    log.info(f"Configuring OSPFv3 global log-adjacency-changes on {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'global log-adjacency-changes {mode}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 global log-adjacency-changes failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_log_adjacency_changes(device, network_instance='default',
                                             protocol_instance='default'):
    """Remove OSPFv3 global log-adjacency-changes."""
    log.info(f"Removing OSPFv3 global log-adjacency-changes from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global log-adjacency-changes', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPFv3 global log-adjacency-changes failed on {device.name}: {e}"
        )


def configure_ospfv3_spf_logging(device, maximum_logs=None, maximum_triggers_per_log=None, network_instance='default',
                                 protocol_instance='default'):
    """Configure OSPFv3 global SPF logging.

    At least one of ``maximum_logs`` (device default 16) or
    ``maximum_triggers_per_log`` (device default 8) must be given.
    """
    log.info(f"Configuring OSPFv3 global SPF logging on {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            *_spf_logging_lines(maximum_logs, maximum_triggers_per_log),
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 global SPF logging failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_spf_logging(device, network_instance='default',
                                   protocol_instance='default'):
    """Remove OSPFv3 global SPF logging.

    Emits the container form ``no global spf logging``, which clears BOTH
    ``maximum-logs`` and ``maximum-triggers-per-log`` regardless of which the
    caller set.
    """
    log.info(f"Removing OSPFv3 global SPF logging from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global spf logging', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPFv3 global SPF logging failed on {device.name}: {e}"
        )


def configure_ospfv3_timers_lsa(device, min_arrival, network_instance='default',
                                protocol_instance='default'):
    """Configure OSPFv3 global LSA timers.

    Only ``min_arrival`` is offered — ``origination-delay`` is advertised by the
    CLI's `?` output but rejected on assignment (see :func:`_lsa_timer_lines`).
    """
    log.info(f"Configuring OSPFv3 global LSA timers on {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            *_lsa_timer_lines(min_arrival),
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPFv3 global LSA timers failed on {device.name}: {e}"
        )


def unconfigure_ospfv3_timers_lsa(device, network_instance='default',
                                  protocol_instance='default'):
    """Remove OSPFv3 global LSA timers."""
    log.info(f"Removing OSPFv3 global LSA timers from {device.name}")
    ctx = _build_ospfv3_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global timers lsa', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPFv3 global LSA timers failed on {device.name}: {e}"
        )
