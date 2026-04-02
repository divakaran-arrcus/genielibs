"""ArcOS MPLS OAM (LSP Ping/Traceroute) APIs.

These are operational commands (not configuration).
They execute ping/traceroute and return the output.
"""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def mpls_lsp_ping(device, fec, fec_type='ldp', count=5, timeout=2,
                   src_ip=None, ttl=None, size=None, verbose=False):
    """Execute MPLS LSP ping.

    Args:
        device: Device object.
        fec: FEC address (e.g., '2.2.2.2/32').
        fec_type: FEC type (ldp, bgp, generic, sr-isis, sr-igp-generic).
        count: Number of echo requests (default 5).
        timeout: Timeout in seconds (default 2).
        src_ip: Optional source IP.
        ttl: Optional MPLS TTL.
        size: Optional packet size.
        verbose: Enable verbose output.

    Returns:
        str: Command output.
    """
    log.info(f"Executing MPLS LSP ping to {fec} on {device.name}")
    cmd = f'ping mpls {fec} fec-type {fec_type} -c {count} -t {timeout}'
    if src_ip:
        cmd += f' -S {src_ip}'
    if ttl is not None:
        cmd += f' -T {ttl}'
    if size is not None:
        cmd += f' -s {size}'
    if verbose:
        cmd += ' -v'
    try:
        return device.execute(cmd, timeout=count * timeout + 30)
    except Exception as exc:
        log.warning("MPLS LSP ping failed: %s", exc)
        return str(exc)


def mpls_lsp_traceroute(device, fec, fec_type='ldp', max_ttl=30,
                          timeout=2, src_ip=None, verbose=False):
    """Execute MPLS LSP traceroute.

    Args:
        device: Device object.
        fec: FEC address (e.g., '2.2.2.2/32').
        fec_type: FEC type (ldp, bgp, generic).
        max_ttl: Max TTL (default 30).
        timeout: Timeout in seconds (default 2).
        src_ip: Optional source IP.
        verbose: Enable verbose output.

    Returns:
        str: Command output.
    """
    log.info(f"Executing MPLS LSP traceroute to {fec} on {device.name}")
    cmd = f'traceroute mpls {fec} fec-type {fec_type} -T {max_ttl} -t {timeout}'
    if src_ip:
        cmd += f' -S {src_ip}'
    if verbose:
        cmd += ' -v'
    try:
        return device.execute(cmd, timeout=max_ttl * timeout + 30)
    except Exception as exc:
        log.warning("MPLS LSP traceroute failed: %s", exc)
        return str(exc)
