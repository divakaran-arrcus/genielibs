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
                              dead_interval=None):
    """Configure OSPF interface in an area."""
    log.info(f"Configuring OSPF interface {interface} in area {area_id} on {device.name}")
    config = [f'{_CTX} area {area_id} interface {interface}']
    if network_type:
        config.append(f'network-type {network_type}')
    if passive is not None:
        config.append(f'passive {"true" if passive else "false"}')
    if hello_interval is not None:
        config.append(f'timers hello-interval {hello_interval}')
    if dead_interval is not None:
        config.append(f'timers dead-interval {dead_interval}')
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
