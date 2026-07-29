#!/usr/bin/env python3
"""
Native ArcOS SR-Policy configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles segment-list definitions, dynamic-policy-color mappings,
and static SR-Policy with candidate paths (explicit and dynamic).

All SR-Policy config is under:
    network-instance default sr-policy ...

Note: SR-Policy is only supported in the default network-instance.
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


def _build_segments(cfg, segments, ni_prefix, sl_name):
    """Render segment-list segments."""
    with cfg.submode_context(f'{ni_prefix} sr-policy segment-list {sl_name}'):
        for seg in segments:
            idx = seg.get("index")
            if idx is None:
                continue
            with cfg.submode_context(f'segment {idx}'):
                seg_type = seg.get("type")
                if seg_type:
                    cfg.append_line(f'type {seg_type}')
                # SRv6 SID
                srv6_sid = seg.get("srv6_sid") or seg.get("srv6-sid")
                if srv6_sid:
                    cfg.append_line(f'srv6-sid {srv6_sid}')
                # MPLS label
                mpls_label = seg.get("mpls_label") or seg.get("mpls-label")
                if mpls_label is not None:
                    cfg.append_line(f'mpls-label {mpls_label}')
                # Validate
                validate = seg.get("validate")
                if validate is not None:
                    cfg.append_line(
                        f'validate {"true" if validate else "false"}'
                    )


def _build_candidate_path(cfg, cp):
    """Render a single candidate-path within a policy context."""
    disc = cp.get("discriminator")
    if disc is None:
        return

    with cfg.submode_context(f'candidate-path {disc}'):
        pref = cp.get("preference")
        if pref is not None:
            cfg.append_line(f'preference {pref}')

        cp_name = cp.get("name")
        if cp_name:
            cfg.append_line(f'name {cp_name}')

        desc = cp.get("description")
        if desc:
            cfg.append_line(f'description "{desc}"')

        path_type = cp.get("path_type") or cp.get("type")
        if path_type:
            cfg.append_line(f'type {path_type}')

        # Explicit segment-list reference
        explicit_sl = cp.get("explicit_segment_list")
        if explicit_sl:
            cfg.append_line(f'explicit segment-list {explicit_sl}')

        # Dynamic settings
        dp = cp.get("dynamic_dataplane")
        if dp:
            cfg.append_line(f'dynamic dataplane {dp}')

        algo = cp.get("dynamic_sid_algorithm")
        if algo is not None:
            cfg.append_line(
                f'dynamic constraints segment-rules sid-algorithm {algo}'
            )

        metric_type = cp.get("dynamic_metric_type")
        if metric_type:
            cfg.append_line(
                f'dynamic constraints path-calculation '
                f'metric-type {metric_type}'
            )

        # Affinities
        affinities = cp.get("dynamic_affinities") or {}
        for aff_type in ("include-any", "exclude-any", "include-all"):
            aff_key = aff_type.replace("-", "_")
            groups = affinities.get(aff_key) or affinities.get(aff_type)
            if groups:
                if isinstance(groups, (list, tuple)):
                    groups_str = ' '.join(str(g) for g in groups)
                else:
                    groups_str = str(groups)
                cfg.append_line(
                    f'dynamic constraints affinities '
                    f'{aff_type} [ {groups_str} ]'
                )

        # Upper bounds
        ub = cp.get("dynamic_upper_bounds") or {}
        cum_metric = ub.get("cumulative_metric")
        if cum_metric is not None:
            cfg.append_line(
                'dynamic constraints upper-bounds '
                'cumulative-metric PATH_CALCULATION_METRIC'
            )
            cfg.append_line(f'metric {cum_metric}')

        max_hops = ub.get("max_hops")
        if max_hops is not None:
            cfg.append_line(
                f'dynamic constraints upper-bounds '
                f'maximum-hop-count {max_hops}'
            )

        max_segs = ub.get("max_segments")
        if max_segs is not None:
            cfg.append_line(
                f'dynamic constraints upper-bounds '
                f'maximum-segments {max_segs}'
            )


class SrPolicy(ABC):
    """ArcOS-specific SR-Policy implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level SR-Policy attributes for ArcOS."""

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build SR-Policy configuration for an ArcOS device."""
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            ni_prefix = 'network-instance default'

            # --- Segment Lists ---
            for sub, sl_attributes in attributes.mapping_values(
                'segment_list_attr', sort=True
            ):
                sl_config = sub.build_config(
                    apply=False,
                    attributes=sl_attributes,
                    unconfig=unconfig,
                    ni_prefix=ni_prefix,
                )
                if sl_config:
                    configurations.append_block(sl_config)

            # --- Dynamic Policy Colors ---
            for sub, dpc_attributes in attributes.mapping_values(
                'dynamic_color_attr', sort=True
            ):
                dpc_config = sub.build_config(
                    apply=False,
                    attributes=dpc_attributes,
                    unconfig=unconfig,
                    ni_prefix=ni_prefix,
                )
                if dpc_config:
                    configurations.append_block(dpc_config)

            # --- Policies ---
            for sub, pol_attributes in attributes.mapping_values(
                'policy_attr', sort=True
            ):
                pol_config = sub.build_config(
                    apply=False,
                    attributes=pol_attributes,
                    unconfig=unconfig,
                    ni_prefix=ni_prefix,
                )
                if pol_config:
                    configurations.append_block(pol_config)

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
            """Build SR-Policy unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        # =============================================================
        # SEGMENT LIST ATTRIBUTES
        # =============================================================

        class SegmentListAttributes(ABC):
            """Per-segment-list attributes for ArcOS SR-Policy."""

            segments = managedattribute(
                name='segments',
                default=None,
                type=(None, managedattribute.test_istype(list)),
                doc='List of segment dicts: [{index, type, srv6_sid/mpls_label, validate}]')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, ni_prefix='', **kwargs):
                """Build segment-list configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                sl_name = self.segment_list_name
                segments = attributes.value('segments')

                if segments:
                    _build_segments(
                        configurations, segments, ni_prefix, sl_name
                    )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                return self.build_config(
                    apply=apply, attributes=attributes,
                    unconfig=True, **kwargs,
                )

        # =============================================================
        # DYNAMIC POLICY COLOR ATTRIBUTES
        # =============================================================

        class DynamicPolicyColorAttributes(ABC):
            """Per-color dynamic policy attributes for ArcOS SR-Policy."""

            sid_algorithm = managedattribute(
                name='sid_algorithm',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Flexible algorithm ID for this color')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, ni_prefix='', **kwargs):
                """Build dynamic-policy-color configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                color = self.color_id
                algo = attributes.value('sid_algorithm')

                if algo is not None:
                    with configurations.submode_context(
                        f'{ni_prefix} sr-policy dynamic-policy-color {color}'
                    ):
                        configurations.append_line(
                            f'dynamic constraints segment-rules '
                            f'sid-algorithm {algo}'
                        )

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                return self.build_config(
                    apply=apply, attributes=attributes,
                    unconfig=True, **kwargs,
                )

        # =============================================================
        # POLICY ATTRIBUTES
        # =============================================================

        class PolicyAttributes(ABC):
            """Per-policy attributes for ArcOS SR-Policy.

            Policy key format: '{endpoint} {color}'
            e.g., '100.1.2.3 100' or '2002:203::3 100'
            """

            policy_name = managedattribute(
                name='policy_name',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Administrative name for the policy')

            description = managedattribute(
                name='description',
                default=None,
                type=(None, managedattribute.test_istype(str)),
                doc='Policy description')

            enabled = managedattribute(
                name='enabled',
                default=None,
                type=(None, managedattribute.test_istype(bool)),
                doc='Enable/disable the policy')

            priority = managedattribute(
                name='priority',
                default=None,
                type=(None, managedattribute.test_istype(int)),
                doc='Policy priority')

            candidate_paths = managedattribute(
                name='candidate_paths',
                default=None,
                type=(None, managedattribute.test_istype(list)),
                doc='List of candidate path dicts with discriminator, '
                    'preference, type, constraints')

            def build_config(self, apply=False, attributes=None,
                             unconfig=False, ni_prefix='', **kwargs):
                """Build policy configuration."""
                assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
                attributes = AttributesHelper(self, attributes)
                configurations = CliConfigBuilder(unconfig=unconfig)

                policy_key = self.policy_key

                with configurations.submode_context(
                    f'{ni_prefix} sr-policy policy {policy_key}'
                ):
                    v = attributes.value('policy_name')
                    if v:
                        configurations.append_line(f'name {v}')

                    v = attributes.value('description')
                    if v:
                        configurations.append_line(f'description "{v}"')

                    v = attributes.value('enabled')
                    if v is not None:
                        configurations.append_line(
                            f'enabled {"true" if v else "false"}'
                        )

                    v = attributes.value('priority')
                    if v is not None:
                        configurations.append_line(f'priority {v}')

                    # Candidate paths
                    cps = attributes.value('candidate_paths')
                    if cps:
                        for cp in cps:
                            _build_candidate_path(configurations, cp)

                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            def build_unconfig(self, apply=False, attributes=None, **kwargs):
                return self.build_config(
                    apply=apply, attributes=attributes,
                    unconfig=True, **kwargs,
                )
