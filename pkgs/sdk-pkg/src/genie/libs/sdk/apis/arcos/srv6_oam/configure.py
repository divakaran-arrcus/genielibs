"""ArcOS SRv6 OAM configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_srv6_oam_profile(device, profile_name='global', enabled=True,
                                latency=None, pkt_loss_percent=None,
                                dampening_multiplier=None,
                                max_consecutive_pkt_loss=None,
                                monitor_interval=None):
    """Configure SRv6 OAM profile.

    Args:
        device: Device object.
        profile_name: Profile name (default 'global').
        enabled: Enable OAM (default True).
        latency: Latency threshold in ms.
        pkt_loss_percent: Packet loss threshold percentage.
        dampening_multiplier: Dampening multiplier.
        max_consecutive_pkt_loss: Max consecutive packet loss.
        monitor_interval: Monitor interval (e.g., 'OAM_MONITOR_INTERVAL_10s').
    """
    log.info(f"Configuring SRv6 OAM profile {profile_name} on {device.name}")
    config = [f'oam profile {profile_name}']
    config.append(f'enable {"true" if enabled else "false"}')
    if latency is not None:
        config.append(f'latency {latency}')
    if pkt_loss_percent is not None:
        config.append(f'pkt-loss-percent {pkt_loss_percent}')
    if dampening_multiplier is not None:
        config.append(f'dampening-multiplier {dampening_multiplier}')
    if max_consecutive_pkt_loss is not None:
        config.append(f'maximum-consecutive-pkt-loss {max_consecutive_pkt_loss}')
    if monitor_interval:
        config.append(f'monitor-interval {monitor_interval}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SRv6 OAM profile failed on {device.name}: {e}")


def unconfigure_srv6_oam_profile(device, profile_name='global'):
    """Remove SRv6 OAM profile."""
    log.info(f"Removing SRv6 OAM profile {profile_name} from {device.name}")
    try:
        device.configure([f'no oam profile {profile_name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"SRv6 OAM profile removal failed on {device.name}: {e}")
