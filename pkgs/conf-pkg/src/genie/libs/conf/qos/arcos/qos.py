#!/usr/bin/env python3
"""
Native ArcOS QoS configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles QoS tablemaps, classifiers, policies, and interface bindings.

Building blocks:
  - Tablemaps: code-point mapping (DSCP/COS/MPLS_TC → LOCAL_TC)
  - Classifiers: traffic classification filters
  - Policies: classifier → action mappings (police, queue, mark)
  - Interface bindings: attach policy/tablemap to interface
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


def _build_tablemap(cfg, name, tm):
    """Render a tablemap definition."""
    with cfg.submode_context(f'qos tablemap {name}'):
        from_type = tm.get("from_type")
        to_type = tm.get("to_type")
        if from_type:
            cfg.append_line(f'from-type {from_type}')
        if to_type:
            cfg.append_line(f'to-type {to_type}')

        for entry in tm.get("entries") or []:
            local_tc = entry.get("local_tc")
            dp = entry.get("dp", 0)
            from_values = entry.get("from_values")
            if local_tc is not None and from_values is not None:
                with cfg.submode_context(f'local-tc-entry {local_tc} {dp}'):
                    if isinstance(from_values, (list, tuple)):
                        vals = ' '.join(str(v) for v in from_values)
                    else:
                        vals = str(from_values)
                    cfg.append_line(f'from-value [ {vals} ]')


def _build_classifier(cfg, name, cls):
    """Render a classifier definition."""
    with cfg.submode_context(f'qos classifier {name}'):
        filter_type = cls.get("filter_type")
        if filter_type == "DSCP":
            values = cls.get("dscp_values")
            if values:
                if isinstance(values, (list, tuple)):
                    vals = ' '.join(str(v) for v in values)
                else:
                    vals = str(values)
                cfg.append_line(f'filter DSCP dscp-value [ {vals} ]')
        elif filter_type == "MPLS_TC":
            values = cls.get("mpls_tc_values")
            if values:
                if isinstance(values, (list, tuple)):
                    vals = ' '.join(str(v) for v in values)
                else:
                    vals = str(values)
                cfg.append_line(f'filter MPLS_TC mpls-tc-value [ {vals} ]')
        elif filter_type == "LOCAL_TC":
            value = cls.get("local_tc_value")
            if value is not None:
                cfg.append_line(f'filter LOCAL_TC local-tc-value {value}')
        elif filter_type == "ACL_IPV4":
            acl_name = cls.get("acl_name")
            if acl_name:
                cfg.append_line(f'filter ACL_IPV4 acl-name {acl_name}')
        elif filter_type == "ACL_IPV6":
            acl_name = cls.get("acl_name")
            if acl_name:
                cfg.append_line(f'filter ACL_IPV6 acl-name {acl_name}')
        elif filter_type == "ANY":
            cfg.append_line('filter ANY')


def _build_policy(cfg, name, pol):
    """Render a policy definition."""
    with cfg.submode_context(f'qos policy {name}'):
        for cls_entry in pol.get("classifiers") or []:
            cls_name = cls_entry.get("classifier")
            if not cls_name:
                continue

            cfg.append_line(f'classifier {cls_name}')

            for action in cls_entry.get("actions") or []:
                action_type = action.get("type")
                if not action_type:
                    continue

                if action_type == "POLICE":
                    rate_val = action.get("rate_value")
                    rate_unit = action.get("rate_unit", "mbps")
                    if rate_val is not None:
                        cfg.append_line(
                            f'action POLICE committed rate '
                            f'value {rate_val} unit {rate_unit}'
                        )
                elif action_type == "MARKING":
                    local_tc = action.get("local_tc")
                    if local_tc is not None:
                        cfg.append_line(
                            f'action MARKING local-tc {local_tc}'
                        )
                elif action_type == "PRIORITY":
                    level = action.get("level", 1)
                    cfg.append_line(f'action PRIORITY level {level}')
                elif action_type == "RATE_MAX":
                    rate_val = action.get("rate_value")
                    rate_unit = action.get("rate_unit", "mbps")
                    if rate_val is not None:
                        cfg.append_line(
                            f'action RATE_MAX value {rate_val} '
                            f'unit {rate_unit}'
                        )
                elif action_type == "RATE_MIN":
                    rate_val = action.get("rate_value")
                    rate_unit = action.get("rate_unit", "mbps")
                    if rate_val is not None:
                        cfg.append_line(
                            f'action RATE_MIN value {rate_val} '
                            f'unit {rate_unit}'
                        )
                elif action_type == "RATE_EXCESS":
                    ratio = action.get("ratio")
                    if ratio is not None:
                        cfg.append_line(
                            f'action RATE_EXCESS ratio {ratio}'
                        )
                elif action_type == "RANDOM_DETECT":
                    profile = action.get("profile")
                    if profile:
                        cfg.append_line(
                            f'action RANDOM_DETECT random-detect '
                            f'profile {profile}'
                        )


def _build_interface_binding(cfg, binding):
    """Render an interface QoS binding."""
    interface = binding.get("interface")
    if not interface:
        return

    with cfg.submode_context(f'interface {interface}'):
        # Service-policy binding
        direction = binding.get("policy_direction")
        policy_name = binding.get("policy_name")
        if direction and policy_name:
            cfg.append_line(
                f'qos service-policy {direction} name {policy_name}'
            )

        # Service-tablemap binding
        tm_direction = binding.get("tablemap_direction")
        tm_name = binding.get("tablemap_name")
        if tm_direction and tm_name:
            cfg.append_line(
                f'qos service-tablemap {tm_direction} name {tm_name}'
            )


class Qos(ABC):
    """ArcOS-specific QoS implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level QoS attributes for ArcOS."""

        tablemaps = managedattribute(
            name='tablemaps',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Tablemap definitions keyed by name')

        classifiers = managedattribute(
            name='classifiers',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Classifier definitions keyed by name')

        policies = managedattribute(
            name='policies',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Policy definitions keyed by name')

        interface_bindings = managedattribute(
            name='interface_bindings',
            default=None,
            type=(None, managedattribute.test_istype(list)),
            doc='List of interface QoS bindings')

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build QoS configuration for an ArcOS device."""
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Tablemaps
            tms = attributes.value('tablemaps')
            if tms:
                for name in sorted(tms.keys()):
                    _build_tablemap(configurations, name, tms[name])

            # Classifiers
            clss = attributes.value('classifiers')
            if clss:
                for name in sorted(clss.keys()):
                    _build_classifier(configurations, name, clss[name])

            # Policies
            pols = attributes.value('policies')
            if pols:
                for name in sorted(pols.keys()):
                    _build_policy(configurations, name, pols[name])

            # Interface bindings
            bindings = attributes.value('interface_bindings')
            if bindings:
                for binding in bindings:
                    _build_interface_binding(configurations, binding)

            if apply:
                if configurations:
                    self.device.configure(str(configurations),
                                          fail_invalid=True)
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build QoS unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )
