
__all__ = (
        'SegmentRouting',
        'PrefixSidMapEntry',
        'ReservedLabelBlock',
        )

import ipaddress
import collections
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, IPv4Network

from genie.utils.cisco_collections import typedset

from genie.decorator import managedattribute
from genie.conf.base import Base, DeviceFeature, Interface
import genie.conf.base.attributes
from genie.conf.base.attributes import SubAttributes, SubAttributesDict, AttributesHelper

from genie.libs.conf.base import Routing
from genie.libs.conf.address_family import AddressFamily, AddressFamilySubAttributes

class PrefixSidMapEntry(Base):

    prefix = managedattribute(
        name='prefix',
        default=None,
        type=(None, managedattribute.test_istype(IPv4Network)))

    index = managedattribute(
        name='index',
        default=None,
        type=(None, managedattribute.test_istype(int)))

    range = managedattribute(
        name='range',
        default=None,
        type=(None, managedattribute.test_istype(int)))

    attach = managedattribute(
        name='attach',
        default=None,
        type=(None, managedattribute.test_istype(bool)))
    
    absolute = managedattribute(
        name='absolute',
        default=None,
        type=(None, managedattribute.test_istype(int)))

    def __hash__(self):
        return hash((self.prefix,self.index,self.range,self.attach,self.absolute))


class ReservedLabelBlock(Base):
    """MPLS reserved label block entry (SRGB/SRLB) for SR-MPLS.

    Attributes:
        local_id: Block identifier (e.g., 'rb1', 'rb2')
        lower_bound: Starting label value
        upper_bound: Ending label value
        usage: Block usage type (ISIS_SRGB, ISIS_SRLB)
        protocol_identifier: Protocol type (ISIS)
        protocol_name: Protocol instance name (default)
    """

    local_id = managedattribute(
        name='local_id',
        default=None,
        type=(None, managedattribute.test_istype(str)))

    lower_bound = managedattribute(
        name='lower_bound',
        default=None,
        type=(None, managedattribute.test_istype(int)))

    upper_bound = managedattribute(
        name='upper_bound',
        default=None,
        type=(None, managedattribute.test_istype(int)))

    usage = managedattribute(
        name='usage',
        default=None,
        type=(None, managedattribute.test_istype(str)),
        doc='Block usage: ISIS_SRGB, ISIS_SRLB')

    protocol_identifier = managedattribute(
        name='protocol_identifier',
        default=None,
        type=(None, managedattribute.test_istype(str)),
        doc='Protocol type: ISIS')

    protocol_name = managedattribute(
        name='protocol_name',
        default=None,
        type=(None, managedattribute.test_istype(str)),
        doc='Protocol instance name')

    def __hash__(self):
        return hash((self.local_id, self.lower_bound, self.upper_bound,
                     self.usage, self.protocol_identifier, self.protocol_name))

    def __repr__(self):
        return f"ReservedLabelBlock(local_id={self.local_id!r}, lower={self.lower_bound}, upper={self.upper_bound})"


class SegmentRouting(Routing, DeviceFeature):

    address_families = managedattribute(
        name='address_families',
        finit=typedset(AddressFamily, {AddressFamily.ipv4_unicast}).copy,
        type=typedset(AddressFamily)._from_iterable)

    shutdown = managedattribute(
        name='shutdown',
        default=None,
        type=(None, managedattribute.test_istype(bool)))

    global_block = managedattribute(
        name='global_block',
        default=None,
        type=(None, managedattribute.test_istype(range)))

    sr_label_preferred = managedattribute(
        name='sr_label_preferred',
        default=None,
        type=(None, managedattribute.test_istype(bool)))

    explicit_null = managedattribute(
        name='explicit_null',
        default=None,
        type=(None, managedattribute.test_istype(bool)))

    mapping_server = managedattribute(
        name='mapping_server',
        default=None,
        type=(None, managedattribute.test_istype(bool)))

    connected_prefix_sid_map = managedattribute(
        name='connected_prefix_sid_map',
        finit=set,
        type=managedattribute.test_set_of(
            managedattribute.test_isinstance(PrefixSidMapEntry)),
        gettype=frozenset,
        doc='A `set` of connected_prefix_sid_map entries')

    prefix_sid_map = managedattribute(
        name='prefix_sid_map',
        finit=set,
        type=managedattribute.test_set_of(
            managedattribute.test_isinstance(PrefixSidMapEntry)),
        gettype=frozenset,
        doc='A `set` of prefix_sid_map entries')

    # SR-MPLS: MPLS reserved label blocks (SRGB/SRLB)
    # Mapping of block_id -> block attributes dict or ReservedLabelBlock
    mpls_reserved_label_blocks = managedattribute(
        name='mpls_reserved_label_blocks',
        default=None,
        type=(None, managedattribute.test_istype(dict)),
        doc='MPLS reserved label blocks for SR-MPLS (SRGB/SRLB)')

    class DeviceAttributes(genie.conf.base.attributes.DeviceSubAttributes):

        address_families = managedattribute(
            name='address_families',
            type=typedset(AddressFamily)._from_iterable)

        @address_families.initter
        def address_families(self):
            return frozenset(self.parent.address_families)

        class AddressFamilyAttributes(AddressFamilySubAttributes):

            def __init__(self, parent, key):
                super().__init__(parent, key)

            def add_prefix_sid_map_entry(self,entry):
                self.prefix_sid_map |= {entry}

            def add_connected_prefix_sid_map_entry(self,entry):
                self.connected_prefix_sid_map |= {entry}

            def remove_prefix_sid_map_entry(self,entry):
                self.prefix_sid_map.remove(entry)

            def remove_connected_prefix_sid_map_entry(self,entry):
                self.connected_prefix_sid_map.remove(entry)

        address_family_attr = managedattribute(
            name='address_family_attr',
            read_only=True,
            doc=AddressFamilyAttributes.__doc__)

        @address_family_attr.initter
        def address_family_attr(self):
            return SubAttributesDict(self.AddressFamilyAttributes, parent=self)

        def __init__(self, parent, key):
            super().__init__(parent, key)

    device_attr = managedattribute(
        name='device_attr',
        read_only=True,
        doc=DeviceAttributes.__doc__)

    @device_attr.initter
    def device_attr(self):
        return SubAttributesDict(self.DeviceAttributes, parent=self)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def build_config(self, devices=None, apply=True, attributes=None,
                     **kwargs):
        cfgs = {}
        assert not kwargs, kwargs
        attributes = AttributesHelper(self, attributes)

        if devices is None:
            devices = self.devices
        devices = set(devices)

        for key, sub, attributes2 in attributes.mapping_items(
                'device_attr',
                keys=devices, sort=True):
            cfgs[key] = sub.build_config(apply=False, attributes=attributes2)

        if apply:
            self.testbed.config_on_devices(cfgs, fail_invalid=True)
        else:
            return cfgs

    def build_unconfig(self, devices=None, apply=True, attributes=None,
                       **kwargs):
        cfgs = {}
        assert not kwargs, kwargs
        attributes = AttributesHelper(self, attributes)

        if devices is None:
            devices = self.devices
        devices = set(devices)

        for key, sub, attributes2 in attributes.mapping_items(
                'device_attr',
                keys=devices, sort=True):
            cfgs[key] = sub.build_unconfig(apply=False, attributes=attributes2)

        if apply:
            self.testbed.config_on_devices(cfgs, fail_invalid=True)
        else:
            return cfgs

