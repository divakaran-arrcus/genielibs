"""ArcOS FQDN Filter configure APIs."""

import logging
from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_fqdn_filter(device, zero_trust=True, discovery=True,
                           trusted_dns_servers=None):
    """Configure FQDN filter global settings.

    Args:
        device: Device object.
        zero_trust: Enable zero-trust mode (default True).
        discovery: Enable FQDN discovery (default True).
        trusted_dns_servers: List of trusted DNS server IPs.
    """
    log.info(f"Configuring FQDN filter on {device.name}")
    config = [
        f'fqdn-filter zero-trust-enabled {"true" if zero_trust else "false"}',
        f'fqdn-filter enable-fqdn-discovery {"true" if discovery else "false"}',
    ]
    if trusted_dns_servers:
        if isinstance(trusted_dns_servers, (list, tuple)):
            dns_str = ' '.join(trusted_dns_servers)
        else:
            dns_str = trusted_dns_servers
        config.append(f'fqdn-filter trusted-dns-servers [ {dns_str} ]')
    config.append('!')
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"FQDN filter config failed on {device.name}: {e}")


def unconfigure_fqdn_filter(device):
    """Remove FQDN filter configuration."""
    log.info(f"Removing FQDN filter from {device.name}")
    try:
        device.configure(['no fqdn-filter', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"FQDN filter removal failed on {device.name}: {e}")


def configure_fqdn_policy(device, name, fqdns):
    """Configure an FQDN policy with domain list.

    Args:
        device: Device object.
        name: Policy name.
        fqdns: List of FQDNs.
    """
    log.info(f"Configuring FQDN policy {name} on {device.name}")
    if isinstance(fqdns, (list, tuple)):
        fqdn_str = ' '.join(fqdns)
    else:
        fqdn_str = fqdns
    config = [f'fqdn-filter fqdn-policy {name} fqdns [ {fqdn_str} ]', '!']
    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(f"FQDN policy failed on {device.name}: {e}")


def unconfigure_fqdn_policy(device, name):
    """Remove an FQDN policy."""
    log.info(f"Removing FQDN policy {name} from {device.name}")
    try:
        device.configure([f'no fqdn-filter fqdn-policy {name}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"FQDN policy removal failed on {device.name}: {e}")


def configure_fqdn_active_policies(device, policies):
    """Activate FQDN policies.

    Args:
        device: Device object.
        policies: List of policy names to activate.
    """
    log.info(f"Activating FQDN policies on {device.name}")
    if isinstance(policies, (list, tuple)):
        pol_str = ' '.join(policies)
    else:
        pol_str = policies
    try:
        device.configure([f'fqdn-filter active-fqdn-policies [ {pol_str} ]', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(f"FQDN active policies failed on {device.name}: {e}")
