"""ArcOS SLA (IP SLA ICMP) configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_sla_icmp_session(device, session_name, target_address,
                                session_interval, probe_count,
                                probe_interval, source_address=None,
                                payload_size=None, dscp=None,
                                excessive_rtd=None, successive_loss=None,
                                network_instance='default'):
    """Configure SLA ICMP session.

    Args:
        device: Device object.
        session_name: Session name.
        target_address: Target IPv4/IPv6 address.
        session_interval: Session interval in seconds.
        probe_count: Number of probes per session.
        probe_interval: Interval between probes in microseconds.
        source_address: Optional source address.
        payload_size: Optional payload size (default 256).
        dscp: Optional DSCP value (0-63).
        excessive_rtd: Optional excessive RTD threshold in nanoseconds.
        successive_loss: Optional successive loss threshold count.
        network_instance: Network instance name (default 'default').
    """
    log.info(f"Configuring SLA ICMP session {session_name} on {device.name}")
    config = [
        f'network-instance {network_instance} sla icmp icmp-session {session_name}',
        'admin-state true',
        f'target-address {target_address}',
        f'session-interval {session_interval}',
        f'probe probe-count {probe_count}',
        f'probe probe-interval {probe_interval}',
    ]
    if source_address:
        config.append(f'source-address {source_address}')
    if payload_size is not None:
        config.append(f'probe payload-size {payload_size}')
    if dscp is not None:
        config.append(f'dscp {dscp}')
    if excessive_rtd is not None:
        config.append(f'threshold excessive-rtd {excessive_rtd}')
    if successive_loss is not None:
        config.append(f'threshold successive-loss {successive_loss}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SLA ICMP session failed on {device.name}: {e}")


def unconfigure_sla_icmp_session(device, session_name,
                                   network_instance='default'):
    """Remove SLA ICMP session."""
    log.info(f"Removing SLA ICMP session {session_name} from {device.name}")
    try:
        device.configure([
            f'network-instance {network_instance} sla icmp',
            f'no icmp-session {session_name}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SLA ICMP session removal failed on {device.name}: {e}")


def configure_sla_icmp_admin_state(device, enabled=True,
                                     network_instance='default'):
    """Enable/disable SLA ICMP master admin state."""
    log.info(f"Setting SLA ICMP admin-state on {device.name}")
    flag = 'true' if enabled else 'false'
    try:
        device.configure([
            f'network-instance {network_instance} sla icmp',
            f'admin-state {flag}',
            '!',
        ])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SLA ICMP admin-state failed on {device.name}: {e}")
