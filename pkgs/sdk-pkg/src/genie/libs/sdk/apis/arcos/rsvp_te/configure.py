"""ArcOS RSVP-TE configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)

_MPLS_TE_CTX = 'network-instance default mpls mpls-te'
_RSVP_CTX = 'network-instance default protocol RSVP default'


def configure_rsvp_te_interface(device, interface, metric=None, enabled=True):
    """Configure MPLS-TE on an interface.

    Args:
        device: Device object.
        interface: Interface name.
        metric: Optional TE metric (0-4294967295).
        enabled: Enable or DISABLE MPLS-TE on the interface. Defaults to True.

    Note:
        The ``enabled`` parameter was added by missing-API batch T1-06. This
        function previously hardcoded ``enable true``, so there was no way to
        emit ``enable false`` — the gap the config-coverage audit flagged as a
        partial API. The default is True, so existing callers are unaffected.
        Device help confirms the leaf's own default is also true
        (`mpls mpls-te interface <i> ?` on rtr1 2026-08-17).
    """
    log.info(
        f"{'Enabling' if enabled else 'Disabling'} MPLS-TE interface {interface} "
        f"on {device.name}"
    )
    config = [f'{_MPLS_TE_CTX} interface {interface}',
              f'enable {str(enabled).lower()}']
    if metric is not None:
        config.append(f'metric {metric}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"MPLS-TE interface failed on {device.name}: {e}")


def unconfigure_rsvp_te_interface(device, interface):
    """Remove MPLS-TE from an interface."""
    log.info(f"Removing MPLS-TE interface {interface} from {device.name}")
    try:
        device.configure([f'no {_MPLS_TE_CTX} interface {interface}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"MPLS-TE interface removal failed on {device.name}: {e}")


def configure_rsvp_global(device, hello_supported=None, hello_interval=None,
                           refresh_reduction=None):
    """Configure RSVP-TE global settings.

    Args:
        device: Device object.
        hello_supported: Enable Hello support (bool).
        hello_interval: Hello interval in seconds.
        refresh_reduction: Enable refresh reduction (bool).
    """
    log.info(f"Configuring RSVP global on {device.name}")
    config = [_RSVP_CTX]
    if hello_supported is not None:
        flag = 'true' if hello_supported else 'false'
        config.append(f'global hello-supported {flag}')
    if hello_interval is not None:
        config.append(f'global hello-interval {hello_interval}')
    if refresh_reduction is not None:
        flag = 'true' if refresh_reduction else 'false'
        config.append(f'global refresh-reduction {flag}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"RSVP global config failed on {device.name}: {e}")


def unconfigure_rsvp_global(device):
    """Remove RSVP-TE global configuration."""
    log.info(f"Removing RSVP global config from {device.name}")
    try:
        device.configure([f'no {_RSVP_CTX}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"RSVP global removal failed on {device.name}: {e}")


def configure_rsvp_interface(device, interface, hello_supported=None,
                              bandwidth_subscription=None):
    """Configure RSVP-TE on an interface.

    Args:
        device: Device object.
        interface: Interface name.
        hello_supported: Enable Hello on interface (bool).
        bandwidth_subscription: Max reservable bandwidth percentage (0-100).
    """
    log.info(f"Configuring RSVP interface {interface} on {device.name}")
    config = [f'{_RSVP_CTX} interface {interface}', 'enable true']
    if hello_supported is not None:
        flag = 'true' if hello_supported else 'false'
        config.append(f'hello-supported {flag}')
    if bandwidth_subscription is not None:
        config.append(f'bandwidth subscription {bandwidth_subscription}')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"RSVP interface failed on {device.name}: {e}")


def unconfigure_rsvp_interface(device, interface):
    """Remove RSVP-TE from an interface."""
    log.info(f"Removing RSVP interface {interface} from {device.name}")
    try:
        device.configure([f'{_RSVP_CTX}', f'no interface {interface}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"RSVP interface removal failed on {device.name}: {e}")
