"""ArcOS OSPF configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_CTX = 'network-instance default protocol OSPF default'


def configure_ospf_router_id(device, router_id):
    """Configure OSPF router-id."""
    log.info(f"Configuring OSPF router-id {router_id} on {device.name}")
    try:
        device.configure([_CTX, f'global router-id {router_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF router-id failed on {device.name}: {e}")


def unconfigure_ospf_router_id(device):
    """Remove OSPF router-id."""
    log.info(f"Removing OSPF router-id from {device.name}")
    try:
        device.configure([_CTX, 'no global router-id', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF router-id removal failed on {device.name}: {e}")


def configure_ospf_area(device, area_id, area_type='AREA_TYPE_NORMAL',
                         stub_default_cost=None):
    """Configure OSPF area."""
    log.info(f"Configuring OSPF area {area_id} on {device.name}")
    config = [f'{_CTX} area {area_id}', f'area-type {area_type}']
    if stub_default_cost is not None:
        config.append(f'stub-default-cost {stub_default_cost}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF area failed on {device.name}: {e}")


def unconfigure_ospf_area(device, area_id):
    """Remove OSPF area."""
    log.info(f"Removing OSPF area {area_id} from {device.name}")
    try:
        device.configure([f'no {_CTX} area {area_id}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF area removal failed on {device.name}: {e}")


def configure_ospf_interface(device, area_id, interface, network_type=None,
                              passive=None, hello_interval=None,
                              dead_interval=None,
                              metric=None, priority=None,
                              retransmission_interval=None,
                              transmission_delay=None,
                              bfd_enabled=None, bfd_profile=None,
                              network_instance='default',
                              protocol_instance='default'):
    """Configure OSPF interface in an area.

    On arcOS, loopback interfaces are passive by default.

    The CLI hierarchy is::

        network-instance <ni> protocol OSPF <pi>
         area <area_id>
          interface <interface>
           network-type <type>                          (optional)
           passive {true|false}                         (optional)
           metric <value>                               (optional, 1..65535)
           priority <value>                             (optional, 0..255)
           timers hello-interval <seconds>              (optional)
           timers dead-interval <seconds>               (optional)
           timers retransmission-interval <seconds>     (optional)
           timers transmission-delay <seconds>          (optional)
           bfd enabled {true|false}                     (optional)
           bfd profile <name>                           (optional)
          !
    """
    log.info(
        f"Configuring OSPF interface {interface} in area {area_id} on {device.name}"
    )

    ctx = _build_ospf_context(network_instance, protocol_instance) \
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

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF interface failed on {device.name}: {e}")


def unconfigure_ospf_interface(device, area_id, interface):
    """Remove OSPF interface from area."""
    log.info(f"Removing OSPF interface {interface} from area {area_id} on {device.name}")
    try:
        device.configure([f'{_CTX} area {area_id}', f'no interface {interface}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF interface removal failed on {device.name}: {e}")


def unconfigure_ospf(device):
    """Remove entire OSPF configuration."""
    log.info(f"Removing OSPF from {device.name}")
    try:
        device.configure([f'no {_CTX}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF removal failed on {device.name}: {e}")


# ---------------------------------------------------------------------------
# Batch A — sanity-plan blockers
# ---------------------------------------------------------------------------

def _build_ospf_context(network_instance='default', protocol_instance='default'):
    """Build OSPF protocol-instance configuration context."""
    return f'network-instance {network_instance} protocol OSPF {protocol_instance}'


def configure_ospf_max_ecmp_paths(device, paths,
                                   network_instance='default',
                                   protocol_instance='default'):
    """Configure OSPF global max-ecmp-paths (1..128)."""
    log.info(f"Configuring OSPF max-ecmp-paths {paths} on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, f'global max-ecmp-paths {paths}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF max-ecmp-paths failed on {device.name}: {e}"
        )


def unconfigure_ospf_max_ecmp_paths(device,
                                     network_instance='default',
                                     protocol_instance='default'):
    """Remove OSPF max-ecmp-paths (revert to default 128)."""
    log.info(f"Removing OSPF max-ecmp-paths from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global max-ecmp-paths', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF max-ecmp-paths removal failed on {device.name}: {e}"
        )


def configure_ospf_auto_cost(device, enabled=True, reference_bandwidth=None,
                              network_instance='default',
                              protocol_instance='default'):
    """Configure OSPF auto-cost.

    Args:
        enabled: True/False to enable/disable auto-cost calculation.
        reference_bandwidth: Reference bandwidth in Gbps (optional).
    """
    log.info(
        f"Configuring OSPF auto-cost (enabled={enabled}, "
        f"ref-bw={reference_bandwidth}) on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    cfg = [ctx, f'global auto-cost enabled {"true" if enabled else "false"}']
    if reference_bandwidth is not None:
        cfg.append(f'global auto-cost reference-bandwidth {reference_bandwidth}')
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"OSPF auto-cost failed on {device.name}: {e}")


def unconfigure_ospf_auto_cost(device,
                                network_instance='default',
                                protocol_instance='default'):
    """Remove OSPF auto-cost configuration."""
    log.info(f"Removing OSPF auto-cost from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global auto-cost', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF auto-cost removal failed on {device.name}: {e}"
        )


def configure_ospf_stub_default_cost(device, area_id, cost,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Configure stub-default-cost for an OSPF stub area (0..16777215)."""
    log.info(
        f"Configuring OSPF area {area_id} stub-default-cost {cost} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'stub-default-cost {cost}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF stub-default-cost failed on {device.name}: {e}"
        )


def unconfigure_ospf_stub_default_cost(device, area_id,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Remove stub-default-cost for an OSPF stub area (revert to default 1)."""
    log.info(
        f"Removing OSPF area {area_id} stub-default-cost from {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            'no stub-default-cost',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF stub-default-cost removal failed on {device.name}: {e}"
        )


def configure_ospf_advertise_summary_lsas(device, area_id, enabled,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure advertise-summary-lsas for an OSPF area (default true)."""
    val = "true" if enabled else "false"
    log.info(
        f"Configuring OSPF area {area_id} advertise-summary-lsas {val} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'advertise-summary-lsas {val}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF advertise-summary-lsas failed on {device.name}: {e}"
        )


def unconfigure_ospf_advertise_summary_lsas(device, area_id,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove advertise-summary-lsas for an OSPF area (revert to default true)."""
    log.info(
        f"Removing OSPF area {area_id} advertise-summary-lsas from {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            'no advertise-summary-lsas',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF advertise-summary-lsas removal failed on {device.name}: {e}"
        )


def configure_ospf_spf_throttle(device, initial_delay=None, short_delay=None,
                                 long_delay=None, time_to_learn=None,
                                 holddown=None,
                                 network_instance='default',
                                 protocol_instance='default'):
    """Configure OSPF SPF throttle timers (RFC 8405).

    All timer params are optional and in milliseconds; only non-None values
    are emitted. If all are None, no configuration is sent.

    Args:
        initial_delay (int, optional): SPF initial delay (default 50 ms).
        short_delay (int, optional): SPF short delay (default 200 ms).
        long_delay (int, optional): SPF long delay (default 5000 ms).
        time_to_learn (int, optional): Time-to-learn interval (default 500 ms).
        holddown (int, optional): Holddown interval (default 10000 ms).
    """
    log.info(f"Configuring OSPF SPF throttle on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    cfg = [ctx]
    if initial_delay is not None:
        cfg.append(f'global spf throttle timers spf-initial-delay {initial_delay}')
    if short_delay is not None:
        cfg.append(f'global spf throttle timers spf-short-delay {short_delay}')
    if long_delay is not None:
        cfg.append(f'global spf throttle timers spf-long-delay {long_delay}')
    if time_to_learn is not None:
        cfg.append(
            f'global spf throttle timers time-to-learn-interval {time_to_learn}'
        )
    if holddown is not None:
        cfg.append(f'global spf throttle timers holddown-interval {holddown}')

    if len(cfg) == 1:
        log.warning(
            "configure_ospf_spf_throttle: no timer values provided; nothing to configure"
        )
        return

    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF SPF throttle failed on {device.name}: {e}"
        )


def unconfigure_ospf_spf_throttle(device,
                                   network_instance='default',
                                   protocol_instance='default'):
    """Remove all OSPF SPF throttle timer configuration (revert to defaults)."""
    log.info(f"Removing OSPF SPF throttle from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
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
            f"OSPF SPF throttle removal failed on {device.name}: {e}"
        )


# ---------------------------------------------------------------------------
# Batch B — features-plan blockers
# ---------------------------------------------------------------------------

# Authentication ------------------------------------------------------------

def configure_ospf_interface_auth(device, area_id, interface, auth_type,
                                   network_instance='default',
                                   protocol_instance='default'):
    """Configure OSPF interface authentication type.

    Args:
        auth_type: ``OSPF_AUTH_NULL`` or ``OSPF_AUTH_CRYPTO_KEY``.
    """
    log.info(
        f"Configuring OSPF interface {interface} (area {area_id}) auth-type "
        f"{auth_type} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'interface {interface}',
            f'authentication auth-type {auth_type}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF interface auth failed on {device.name}: {e}"
        )


def configure_ospf_interface_auth_md5(device, area_id, interface,
                                       key_id, key_string,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Configure OSPF interface MD5 cryptographic authentication.

    Sets auth-type=OSPF_AUTH_CRYPTO_KEY, algorithm=MD5, plus key-id/key-string.
    """
    log.info(
        f"Configuring OSPF MD5 auth (key-id {key_id}) on {interface} "
        f"area {area_id} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'interface {interface}',
            'authentication auth-type OSPF_AUTH_CRYPTO_KEY',
            'authentication crypto-key algorithm OSPF_CRYPTO_ALGO_MD5',
            f'authentication crypto-key key-id {key_id}',
            f'authentication crypto-key key-string {key_string}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF MD5 auth failed on {device.name}: {e}"
        )


def unconfigure_ospf_interface_auth(device, area_id, interface,
                                     network_instance='default',
                                     protocol_instance='default'):
    """Remove all OSPF authentication configuration from an interface."""
    log.info(
        f"Removing OSPF auth from {interface} area {area_id} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'interface {interface}',
            'no authentication',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF auth removal failed on {device.name}: {e}"
        )


# Ignore-MTU ----------------------------------------------------------------

def configure_ospf_interface_ignore_mtu(device, area_id, interface, enabled,
                                         network_instance='default',
                                         protocol_instance='default'):
    """Enable or disable OSPF DD-packet MTU checking on an interface."""
    val = "true" if enabled else "false"
    log.info(
        f"Configuring OSPF ignore-mtu {val} on {interface} area {area_id} "
        f"on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'interface {interface}',
            f'ignore-mtu {val}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF ignore-mtu failed on {device.name}: {e}"
        )


def unconfigure_ospf_interface_ignore_mtu(device, area_id, interface,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Remove ignore-mtu (revert to default false)."""
    log.info(
        f"Removing OSPF ignore-mtu from {interface} area {area_id} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'interface {interface}',
            'no ignore-mtu',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF ignore-mtu removal failed on {device.name}: {e}"
        )


# Table-connection (redistribution) ----------------------------------------

def configure_ospf_table_connection(device, src_protocol, afi="IPV4",
                                     src_dst_instance=None,
                                     import_policy=None,
                                     network_instance='default'):
    """Configure redistribution INTO OSPF via network-instance table-connection.

    Thin wrapper around ``configure_network_instance_table_connection`` with
    ``dst_proto="OSPF"``.

    Args:
        src_protocol: Source protocol — ``STATIC``, ``DIRECTLY_CONNECTED``,
            ``BGP``, or ``ISIS``.
        afi: Address family, default ``IPV4``.
        src_dst_instance: Optional ``"<src_inst> <ospf_inst>"`` string.
        import_policy: Optional routing-policy name.
        network_instance: Network instance name.
    """
    from genie.libs.sdk.apis.arcos.network_instance.configure import (
        configure_network_instance_table_connection,
    )
    return configure_network_instance_table_connection(
        device, ni_name=network_instance, src_proto=src_protocol,
        dst_proto="OSPF", af=afi,
        src_dst_instance=src_dst_instance, import_policy=import_policy,
    )


def unconfigure_ospf_table_connection(device, src_protocol, afi="IPV4",
                                       network_instance='default'):
    """Remove redistribution INTO OSPF (table-connection)."""
    from genie.libs.sdk.apis.arcos.network_instance.configure import (
        unconfigure_network_instance_table_connection,
    )
    return unconfigure_network_instance_table_connection(
        device, ni_name=network_instance, src_proto=src_protocol,
        dst_proto="OSPF", af=afi,
    )


# Redistribute-aggregate (global) ------------------------------------------

def configure_ospf_redistribute_aggregate(device, prefix,
                                           advertise=None,
                                           import_policy=None,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure OSPF global redistribute-aggregate.

    Args:
        prefix: Aggregate prefix (e.g. "10.0.0.0/8").
        advertise: ``AGGREGATE_ADVERTISE`` or ``AGGREGATE_DONT_ADVERTISE``
            (optional; default = AGGREGATE_ADVERTISE per CLI).
        import_policy: Optional routing-policy name.
    """
    log.info(
        f"Configuring OSPF redistribute-aggregate {prefix} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
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
            f"OSPF redistribute-aggregate failed on {device.name}: {e}"
        )


def unconfigure_ospf_redistribute_aggregate(device, prefix,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove an OSPF global redistribute-aggregate prefix."""
    log.info(
        f"Removing OSPF redistribute-aggregate {prefix} from {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'global no redistribute-aggregate {prefix}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF redistribute-aggregate removal failed on {device.name}: {e}"
        )


# Summary-aggregate (per-area) ---------------------------------------------

def configure_ospf_summary_aggregate(device, area_id, prefix,
                                      advertise=None,
                                      import_policy=None,
                                      network_instance='default',
                                      protocol_instance='default'):
    """Configure an OSPF area-level summary-aggregate prefix.

    Args:
        area_id: Area identifier.
        prefix: Aggregate prefix.
        advertise: ``AGGREGATE_ADVERTISE`` or ``AGGREGATE_DONT_ADVERTISE``.
        import_policy: Optional routing-policy name.
    """
    log.info(
        f"Configuring OSPF area {area_id} summary-aggregate {prefix} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    cfg = [
        ctx,
        f'area {area_id}',
        f'summary-aggregate {prefix}',
    ]
    if advertise is not None:
        cfg.append(f'advertise {advertise}')
    if import_policy is not None:
        cfg.append(f'import-policy {import_policy}')
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF summary-aggregate failed on {device.name}: {e}"
        )


def unconfigure_ospf_summary_aggregate(device, area_id, prefix,
                                        network_instance='default',
                                        protocol_instance='default'):
    """Remove an OSPF area summary-aggregate prefix."""
    log.info(
        f"Removing OSPF area {area_id} summary-aggregate {prefix} from {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'no summary-aggregate {prefix}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF summary-aggregate removal failed on {device.name}: {e}"
        )


# Route-preference ---------------------------------------------------------

def configure_ospf_route_preference(device,
                                     intra_area=None,
                                     inter_area=None,
                                     external=None,
                                     network_instance='default',
                                     protocol_instance='default'):
    """Configure OSPF RIB route-preferences (0..255 per type).

    Any subset of ``intra_area``, ``inter_area``, ``external`` may be set;
    omitted params are not changed.
    """
    log.info(
        f"Configuring OSPF route-preference (intra={intra_area}, "
        f"inter={inter_area}, external={external}) on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    parts = []
    if intra_area is not None:
        parts.append(f'intra-area {intra_area}')
    if inter_area is not None:
        parts.append(f'inter-area {inter_area}')
    if external is not None:
        parts.append(f'external {external}')

    if not parts:
        log.warning(
            "configure_ospf_route_preference: no preferences supplied; nothing to configure"
        )
        return

    cfg = [ctx, 'global route-preference ' + ' '.join(parts), '!']
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF route-preference failed on {device.name}: {e}"
        )


def unconfigure_ospf_route_preference(device,
                                       intra_area=False,
                                       inter_area=False,
                                       external=False,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Remove OSPF route-preference settings (revert to default 110)."""
    log.info(f"Removing OSPF route-preference from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    cfg = [ctx]
    if intra_area:
        cfg.append('global no route-preference intra-area')
    if inter_area:
        cfg.append('global no route-preference inter-area')
    if external:
        cfg.append('global no route-preference external')
    if len(cfg) == 1:
        # Default: remove all
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
            f"OSPF route-preference removal failed on {device.name}: {e}"
        )


# Max-LSA -----------------------------------------------------------------

def configure_ospf_max_lsa(device,
                            lsa_limit=None,
                            warning_threshold=None,
                            warning_only=None,
                            avoid_down_state=None,
                            limit_monitor_time=None,
                            down_recovery_time=None,
                            network_instance='default',
                            protocol_instance='default'):
    """Configure OSPF global max-lsa parameters."""
    log.info(f"Configuring OSPF max-lsa on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    cfg = [ctx]
    if lsa_limit is not None:
        cfg.append(f'global max-lsa lsa-limit {lsa_limit}')
    if warning_threshold is not None:
        cfg.append(f'global max-lsa warning-threshold {warning_threshold}')
    if warning_only is not None:
        cfg.append(
            f'global max-lsa warning-only {"true" if warning_only else "false"}'
        )
    if avoid_down_state is not None:
        cfg.append(
            f'global max-lsa avoid-down-state '
            f'{"true" if avoid_down_state else "false"}'
        )
    if limit_monitor_time is not None:
        cfg.append(f'global max-lsa limit-monitor-time {limit_monitor_time}')
    if down_recovery_time is not None:
        cfg.append(f'global max-lsa down-recovery-time {down_recovery_time}')

    if len(cfg) == 1:
        log.warning(
            "configure_ospf_max_lsa: no parameters supplied; nothing to configure"
        )
        return

    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF max-lsa failed on {device.name}: {e}"
        )


def unconfigure_ospf_max_lsa(device,
                              network_instance='default',
                              protocol_instance='default'):
    """Remove OSPF max-lsa configuration entirely."""
    log.info(f"Removing OSPF max-lsa from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global max-lsa', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF max-lsa removal failed on {device.name}: {e}"
        )


# Maintenance-mode --------------------------------------------------------

def configure_ospf_maintenance_mode(device,
                                     router_lsa_metric=None,
                                     router_lsa_set_link_metric=None,
                                     router_lsa_set_stub_metric=None,
                                     summary_lsa_metric=None,
                                     summary_lsa_set_metric=None,
                                     external_lsa_metric=None,
                                     external_lsa_set_metric=None,
                                     network_instance='default',
                                     protocol_instance='default'):
    """Configure OSPF maintenance-mode LSA metric parameters.

    Note: This only configures *what* maintenance mode does to LSAs. Use
    :func:`configure_ospf_maintenance_mode_trigger` to *activate* maintenance
    mode (trigger=always or on-startup).
    """
    log.info(f"Configuring OSPF maintenance-mode LSA params on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    cfg = [ctx]

    if router_lsa_metric is not None:
        cfg.append(
            f'global maintenance-mode router-lsa metric {router_lsa_metric}'
        )
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
        cfg.append(
            f'global maintenance-mode summary-lsa metric {summary_lsa_metric}'
        )
    if summary_lsa_set_metric is not None:
        cfg.append(
            f'global maintenance-mode summary-lsa set-metric '
            f'{"true" if summary_lsa_set_metric else "false"}'
        )
    if external_lsa_metric is not None:
        cfg.append(
            f'global maintenance-mode external-lsa metric {external_lsa_metric}'
        )
    if external_lsa_set_metric is not None:
        cfg.append(
            f'global maintenance-mode external-lsa set-metric '
            f'{"true" if external_lsa_set_metric else "false"}'
        )

    if len(cfg) == 1:
        log.warning(
            "configure_ospf_maintenance_mode: no parameters supplied; nothing to configure"
        )
        return

    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF maintenance-mode failed on {device.name}: {e}"
        )


def unconfigure_ospf_maintenance_mode(device,
                                       network_instance='default',
                                       protocol_instance='default'):
    """Remove all OSPF maintenance-mode configuration."""
    log.info(f"Removing OSPF maintenance-mode from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx, 'no global maintenance-mode', '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF maintenance-mode removal failed on {device.name}: {e}"
        )


def configure_ospf_maintenance_mode_trigger(device,
                                             always=None,
                                             on_startup=None,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Configure OSPF maintenance-mode trigger.

    Args:
        always: True/False to enable unconditional maintenance mode.
        on_startup: Integer seconds (5..86400) to maintain maintenance mode
            on startup; pass an integer to enable, None to skip.
    """
    log.info(
        f"Configuring OSPF maintenance-mode trigger "
        f"(always={always}, on_startup={on_startup}) on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    cfg = [ctx]
    if always is not None:
        cfg.append(
            f'global maintenance-mode trigger always '
            f'{"true" if always else "false"}'
        )
    if on_startup is not None:
        cfg.append(
            f'global maintenance-mode trigger on-startup {on_startup}'
        )
    if len(cfg) == 1:
        log.warning(
            "configure_ospf_maintenance_mode_trigger: no trigger supplied"
        )
        return
    cfg.append('!')
    try:
        device.configure(cfg)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF maintenance-mode trigger failed on {device.name}: {e}"
        )


def unconfigure_ospf_maintenance_mode_trigger(device,
                                               network_instance='default',
                                               protocol_instance='default'):
    """Remove OSPF maintenance-mode trigger configuration."""
    log.info(f"Removing OSPF maintenance-mode trigger from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            'no global maintenance-mode trigger',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF maintenance-mode trigger removal failed on {device.name}: {e}"
        )


# ---------------------------------------------------------------------------
# Missing-API backlog batch T1-05 — OSPF logging, SPF-log and LSA timers
# (arcos_pyats_sanity/docs/config-coverage/03-ospf-ldp-bfd-static.md)
#
# Leaf names and enums confirmed by `?` capture on rtr1 2026-08-17. The audit's
# "triggers-per-log" is really `maximum-triggers-per-log`.
# ---------------------------------------------------------------------------


#: Accepted values for ``configure_ospf_log_adjacency_changes(mode=...)``.
#: Device-confirmed enum (`global log-adjacency-changes ?` on rtr1 2026-08-17).
OSPF_LOG_ADJ_MODES = (
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


def configure_ospf_log_adjacency_changes(device, mode, network_instance='default',
                                         protocol_instance='default'):
    """Configure OSPF global log-adjacency-changes.

    ``mode`` is one of :data:`OSPF_LOG_ADJ_MODES`.
    """
    if mode not in OSPF_LOG_ADJ_MODES:
        raise ValueError(
            f"Invalid mode '{mode}'. Must be one of: "
            f"{', '.join(OSPF_LOG_ADJ_MODES)}"
        )
    log.info(f"Configuring OSPF global log-adjacency-changes on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'global log-adjacency-changes {mode}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF global log-adjacency-changes failed on {device.name}: {e}"
        )


def unconfigure_ospf_log_adjacency_changes(device, network_instance='default',
                                           protocol_instance='default'):
    """Remove OSPF global log-adjacency-changes."""
    log.info(f"Removing OSPF global log-adjacency-changes from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global log-adjacency-changes', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPF global log-adjacency-changes failed on {device.name}: {e}"
        )


def configure_ospf_spf_logging(device, maximum_logs=None, maximum_triggers_per_log=None, network_instance='default',
                               protocol_instance='default'):
    """Configure OSPF global SPF logging.

    At least one of ``maximum_logs`` (device default 16) or
    ``maximum_triggers_per_log`` (device default 8) must be given.
    """
    log.info(f"Configuring OSPF global SPF logging on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            *_spf_logging_lines(maximum_logs, maximum_triggers_per_log),
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF global SPF logging failed on {device.name}: {e}"
        )


def unconfigure_ospf_spf_logging(device, network_instance='default',
                                 protocol_instance='default'):
    """Remove OSPF global SPF logging."""
    log.info(f"Removing OSPF global SPF logging from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global spf logging', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPF global SPF logging failed on {device.name}: {e}"
        )


def configure_ospf_timers_lsa(device, min_arrival, network_instance='default',
                              protocol_instance='default'):
    """Configure OSPF global LSA timers.

    Only ``min_arrival`` is offered — ``origination-delay`` is advertised by the
    CLI's `?` output but rejected on assignment (see :func:`_lsa_timer_lines`).
    """
    log.info(f"Configuring OSPF global LSA timers on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            *_lsa_timer_lines(min_arrival),
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF global LSA timers failed on {device.name}: {e}"
        )


def unconfigure_ospf_timers_lsa(device, network_instance='default',
                                protocol_instance='default'):
    """Remove OSPF global LSA timers."""
    log.info(f"Removing OSPF global LSA timers from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, 'no global timers lsa', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPF global LSA timers failed on {device.name}: {e}"
        )


#: OSPFv2 SNMP traps that `global snmp send-trap <trap> <bool>` can enable.
#: Device-confirmed (`global snmp send-trap ?` on rtr1 2026-08-17); every one
#: defaults to false/disabled.
OSPF_SNMP_TRAPS = (
    'if-auth-failure',
    'if-config-error',
    'if-rx-bad-packet',
    'if-state-change',
    'lsdb-approaching-overflow',
    'lsdb-overflow',
    'max-age-lsa',
    'nbr-state-change',
    'originate-lsa',
    'tx-retransmit',
)


def configure_ospf_snmp_send_trap(device, trap, enabled=True,
                                  network_instance='default',
                                  protocol_instance='default'):
    """Enable or disable one OSPFv2 SNMP trap.

    ``trap`` is one of :data:`OSPF_SNMP_TRAPS`. All traps default to disabled.
    """
    if trap not in OSPF_SNMP_TRAPS:
        raise ValueError(
            f"Invalid OSPF SNMP trap '{trap}'. Must be one of: "
            f"{', '.join(OSPF_SNMP_TRAPS)}"
        )
    log.info(f"Configuring OSPF snmp send-trap {trap} on {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'global snmp send-trap {trap} {str(enabled).lower()}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF snmp send-trap {trap} failed on {device.name}: {e}"
        )


def unconfigure_ospf_snmp_send_trap(device, trap,
                                    network_instance='default',
                                    protocol_instance='default'):
    """Remove one OSPFv2 SNMP trap setting (reverts to the disabled default)."""
    if trap not in OSPF_SNMP_TRAPS:
        raise ValueError(
            f"Invalid OSPF SNMP trap '{trap}'. Must be one of: "
            f"{', '.join(OSPF_SNMP_TRAPS)}"
        )
    log.info(f"Removing OSPF snmp send-trap {trap} from {device.name}")
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([ctx, f'no global snmp send-trap {trap}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPF snmp send-trap {trap} failed on {device.name}: {e}"
        )


def configure_ospf_interface_auth_keychain(device, area_id, interface, keychain,
                                           network_instance='default',
                                           protocol_instance='default'):
    """Configure OSPF interface keychain authentication.

    Sets auth-type=OSPF_AUTH_KEYCHAIN and binds the named keychain, mirroring
    :func:`configure_ospf_interface_auth_md5`.

    Graceful key rollover is NOT configured here — it is emergent from the
    keychain's own overlapping send-lifetimes. Use
    ``configure_keychain_key(send_lifetime_start_time=..., send_lifetime_end_time=...)``
    in ``apis.arcos.keychain.configure`` for that.
    """
    log.info(
        f"Configuring OSPF keychain auth ({keychain}) on {interface} "
        f"area {area_id} on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'interface {interface}',
            'authentication auth-type OSPF_AUTH_KEYCHAIN',
            f'authentication crypto-keychain keychain {keychain}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"OSPF keychain auth failed on {device.name}: {e}"
        )


def unconfigure_ospf_interface_auth_keychain(device, area_id, interface,
                                             network_instance='default',
                                             protocol_instance='default'):
    """Remove OSPF interface keychain authentication."""
    log.info(
        f"Removing OSPF keychain auth on {interface} area {area_id} "
        f"on {device.name}"
    )
    ctx = _build_ospf_context(network_instance, protocol_instance)
    try:
        device.configure([
            ctx,
            f'area {area_id}',
            f'interface {interface}',
            'no authentication crypto-keychain',
            'no authentication auth-type',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Removing OSPF keychain auth failed on {device.name}: {e}"
        )
