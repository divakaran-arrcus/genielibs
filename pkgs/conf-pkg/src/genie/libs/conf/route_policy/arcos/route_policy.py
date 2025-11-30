#!/usr/bin/env python3
"""ArcOS routing-policy configuration plugin for Genie.

This module implements an ArcOS-specific RoutePolicy config builder that
renders routing-policy *defined-sets* and *policy-definitions* from the
normalized Python model used by the ArcOS routing-policy parsers and Ops.

See also:
- ``genie.libs.parser.arcos.show_routing_policy``
- ``ROUTING_POLICY_GET_APIS_AND_CONFIG_PLAN.md`` in the isis_pyats repo
"""

from __future__ import annotations

from abc import ABC
import logging
from typing import Any, Dict

from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig


logger = logging.getLogger(__name__)


def _build_defined_sets(cfg: CliConfigBuilder, defined_sets: Dict[str, Any]) -> None:
    """Render ArcOS routing-policy defined-sets.

    Supported families in v1:
    - ``prefix_sets``
    - ``next_hop_sets``

    Other families (string-sets, tag-sets, BGP-defined-sets) can be added
    later as needed.
    """

    # Prefix-sets ------------------------------------------------------
    prefix_sets: Dict[str, Any] = defined_sets.get("prefix_sets") or {}
    for name in sorted(prefix_sets):
        entry = prefix_sets.get(name) or {}
        prefixes = entry.get("prefixes") or []
        if not prefixes:
            continue

        cfg.append_line(f"routing-policy defined-sets prefix-set {name}")

        for pref in prefixes:
            ip = pref.get("ip_prefix")
            mask = pref.get("masklength_range")
            if not ip or not mask:
                continue
            cfg.append_line(f" prefix {ip} {mask}")
            cfg.append_line(" !")

        cfg.append_line("!")

    # Next-hop-sets ----------------------------------------------------
    nh_sets: Dict[str, Any] = defined_sets.get("next_hop_sets") or {}
    for name in sorted(nh_sets):
        entry = nh_sets.get(name) or {}
        addrs = entry.get("addresses") or []
        if not addrs:
            continue

        addr_str = " ".join(str(a) for a in addrs)
        cfg.append_line(f"routing-policy defined-sets next-hop-set {name}")
        cfg.append_line(f" address [ {addr_str} ]")
        cfg.append_line("!")


def _build_policy_definitions(cfg: CliConfigBuilder, policy_defs: Dict[str, Any]) -> None:
    """Render ArcOS routing-policy policy-definitions.

    v1 handles:
    - Statement ordering (numeric-first, then lexicographic).
    - ``match-prefix-set``, ``match-next-hop-set``, and ``match-tag-set``
      conditions.
    - Basic actions: ``accept-route``, ``reject-route``, ``next-policy``.
    - IGP actions: ``set_tag`` and ISIS ``set_level``.

    More advanced BGP/IGP-related conditions and actions can be added
    incrementally while keeping the normalized model stable.
    """

    for pname in sorted(policy_defs):
        policy = policy_defs.get(pname) or {}
        stmts = policy.get("statements") or {}
        if not stmts:
            continue

        cfg.append_line(f"routing-policy policy-definition {pname}")

        # Sort statements numerically when possible, else lexicographically
        def _stmt_sort_key(key: str) -> tuple[int, Any]:
            try:
                return (0, int(key))
            except Exception:
                return (1, str(key))

        for sname in sorted(stmts, key=_stmt_sort_key):
            stmt = stmts.get(sname) or {}
            cfg.append_line(f" statement {sname}")

            conditions = stmt.get("conditions") or {}
            actions = stmt.get("actions") or {}

            # Match prefix-set -----------------------------------------
            mps = conditions.get("match_prefix_set") or {}
            prefix_set = mps.get("prefix_set")
            mps_opt = mps.get("match_set_options")

            if prefix_set:
                cfg.append_line(
                    f"  conditions match-prefix-set prefix-set {prefix_set}"
                )
            if mps_opt:
                cfg.append_line(
                    f"  conditions match-prefix-set match-set-options {mps_opt}"
                )

            # Match next-hop-set --------------------------------------
            mnh = conditions.get("match_next_hop_set") or {}
            nh_set = mnh.get("next_hop_set")
            mnh_opt = mnh.get("match_set_options")

            if nh_set:
                cfg.append_line(
                    f"  conditions match-next-hop-set next-hop-set {nh_set}"
                )
            if mnh_opt:
                cfg.append_line(
                    "  conditions match-next-hop-set match-set-options "
                    f"{mnh_opt}"
                )

            # Match tag-set -------------------------------------------
            mts = conditions.get("match_tag_set") or {}
            tag_set = mts.get("tag_set") or mts.get("tag_set_name")
            mts_opt = mts.get("match_set_options")

            if tag_set:
                cfg.append_line(
                    f"  conditions match-tag-set tag-set {tag_set}"
                )
            if mts_opt:
                cfg.append_line(
                    f"  conditions match-tag-set match-set-options {mts_opt}"
                )

            # TODO: bgp_conditions, igp_conditions, etc.

            # Actions --------------------------------------------------
            if actions.get("accept_route"):
                cfg.append_line("  actions accept-route")
            if actions.get("reject_route"):
                cfg.append_line("  actions reject-route")
            if actions.get("next_policy"):
                cfg.append_line("  actions next-policy")

            igp = actions.get("igp_actions") or {}
            if igp:
                set_tag = igp.get("set_tag")
                if set_tag is not None:
                    cfg.append_line(
                        f"  actions igp-actions set-tag {set_tag}"
                    )

                isis = igp.get("isis_actions") or {}
                set_level = isis.get("set_level")
                if set_level is not None:
                    cfg.append_line(
                        f"  actions igp-actions isis-actions set-level {set_level}"
                    )

            # TODO: ospf_actions (set_metric), bgp_actions (set-community,
            # med, local-pref, etc.)

            cfg.append_line(" !")

        cfg.append_line("!")


class RoutePolicy(ABC):
    """ArcOS-specific RoutePolicy config builder.

    This plugin expects a normalized ``routing_policy`` model attached to the
    ArcOS device attributes, with the following top-level shape::

        routing_policy = {
            "defined_sets": {...},
            "policy_definitions": {...},
        }

    The structure matches the ArcOS routing-policy parsers and Ops classes.
    """

    class DeviceAttributes(ABC):
        """Device-level RoutePolicy attributes for ArcOS."""

        def build_config(
            self,
            apply: bool = True,
            attributes=None,
            unconfig: bool = False,
            **kwargs: Any,
        ):
            """Build ArcOS routing-policy configuration.

            v1 behavior:
            - Uses a single ``routing_policy`` tree for the device.
            - Renders defined-sets (prefix-sets, next-hop-sets).
            - Renders policy-definitions (statements with basic conditions and
              actions).
            - Selective configuration (attributes filtering) is not fully
              supported yet; if a filtered attributes set is passed, only the
              visible parts of the tree will be rendered.
            - Unconfiguration is supported by emitting root-level routing-policy
              commands with "no " prefix.
            """

            assert not kwargs, f"Unexpected kwargs: {kwargs}"
            attributes = AttributesHelper(self, attributes)
            cfg = CliConfigBuilder(unconfig=unconfig)

            if unconfig:
                # Build unconfiguration by emitting root-level routing-policy
                # commands. CliConfigBuilder(unconfig=True) will prepend the
                # appropriate "no " prefix for us.
                rp: Dict[str, Any] | None = attributes.value("routing_policy")
                if not rp:
                    # Nothing to configure or unconfigure for this device.
                    if apply:
                        return
                    return CliConfig(device=self.device, unconfig=unconfig, cli_config=cfg)

                rp_root: Dict[str, Any] = rp or {}
                defined_sets: Dict[str, Any] = rp_root.get("defined_sets") or {}
                policy_defs: Dict[str, Any] = rp_root.get("policy_definitions") or {}

                prefix_sets: Dict[str, Any] = defined_sets.get("prefix_sets") or {}
                for name in sorted(prefix_sets):
                    cfg.append_line(
                        f"routing-policy defined-sets prefix-set {name}"
                    )

                nh_sets: Dict[str, Any] = defined_sets.get("next_hop_sets") or {}
                for name in sorted(nh_sets):
                    cfg.append_line(
                        f"routing-policy defined-sets next-hop-set {name}"
                    )

                for pname in sorted(policy_defs):
                    cfg.append_line(
                        f"routing-policy policy-definition {pname}"
                    )

                if apply:
                    if cfg:
                        self.device.configure(str(cfg))
                else:
                    return CliConfig(
                        device=self.device,
                        unconfig=True,
                        cli_config=cfg,
                    )
                return

            rp: Dict[str, Any] | None = attributes.value("routing_policy")
            if not rp:
                # Nothing to configure for this device.
                if apply:
                    return
                return CliConfig(device=self.device, unconfig=False, cli_config=cfg)

            rp_root: Dict[str, Any] = rp or {}
            defined_sets: Dict[str, Any] = rp_root.get("defined_sets") or {}
            policy_defs: Dict[str, Any] = rp_root.get("policy_definitions") or {}

            # ------------------------------------------------------------------
            # Defined-sets: prefix-sets and next-hop-sets
            # ------------------------------------------------------------------
            _build_defined_sets(cfg, defined_sets)

            # ------------------------------------------------------------------
            # Policy-definitions: statements, conditions, actions
            # ------------------------------------------------------------------
            _build_policy_definitions(cfg, policy_defs)

            if apply:
                if cfg:
                    self.device.configure(str(cfg))
            else:
                return CliConfig(device=self.device, unconfig=False, cli_config=cfg)

        def build_unconfig(self, apply: bool = True, attributes=None, **kwargs: Any):
            """Unconfiguration for ArcOS RoutePolicy.

            Delegates to :meth:`build_config` with ``unconfig=True``.
            """

            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

