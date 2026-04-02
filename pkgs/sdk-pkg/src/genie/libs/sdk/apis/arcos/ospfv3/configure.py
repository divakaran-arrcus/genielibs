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
                               dead_interval=None, instance_id=None):
    """Configure OSPFv3 interface in an area."""
    log.info(f"Configuring OSPFv3 interface {interface} in area {area_id} on {device.name}")
    config = [f'{_CTX} area {area_id} interface {interface}']
    if network_type:
        config.append(f'network-type {network_type}')
    if passive is not None:
        config.append(f'passive {"true" if passive else "false"}')
    if hello_interval is not None:
        config.append(f'timers hello-interval {hello_interval}')
    if dead_interval is not None:
        config.append(f'timers dead-interval {dead_interval}')
    if instance_id is not None:
        config.append(f'instance-id {instance_id}')
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
