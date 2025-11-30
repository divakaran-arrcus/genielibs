"""ArcOS RoutingPolicy Genie Ops Object.

Thin Ops wrapper around the ArcOS routing-policy parsers, exposing
``defined_sets`` and ``policy_definitions`` under ``self.info``.
"""

from genie.libs.ops.route_policy.route_policy import RoutePolicy as SuperRoutePolicy
from genie.libs.parser.arcos.show_routing_policy import (
    ShowRoutingPolicyDefinedSets,
    ShowRoutingPolicyPolicyDefinition,
)


class RoutePolicy(SuperRoutePolicy):
    """ArcOS RoutingPolicy Ops.

    ``self.info`` structure:

    .. code-block:: python

        info = {
            "defined_sets": {
                "prefix_sets": {...},
                "string_sets": {...},
                "tag_sets": {...},
                "next_hop_sets": {...},
            },
            "policy_definitions": {
                "<policy_name>": {
                    "name": "<policy_name>",
                    "statements": {
                        "<stmt_name>": {
                            "name": "<stmt_name>",
                            # optional
                            "auto_seq_num": <int>,
                            "conditions": {...},
                            "actions": {...},
                        },
                    },
                },
            },
        }

    This is a thin wrapper over the two operational parsers
    ``ShowRoutingPolicyDefinedSets`` and ``ShowRoutingPolicyPolicyDefinition``.
    """

    def learn(self):  # type: ignore[override]
        """Learn ArcOS routing-policy operational state.

        Populates ``self.info`` with ``defined_sets`` and
        ``policy_definitions`` as returned by the two ArcOS parsers.
        """

        info = {}

        # ------------------------------------------------------------------
        # Defined-sets (prefix/string/tag/next-hop)
        # ------------------------------------------------------------------
        ds_parser = ShowRoutingPolicyDefinedSets(device=self.device)
        ds_result = ds_parser.parse()
        ds_root = ds_result.get("routing_policy", {})
        defined_sets = ds_root.get("defined_sets") or {}
        if defined_sets:
            info["defined_sets"] = defined_sets

        # ------------------------------------------------------------------
        # Policy-definitions (statements, conditions, actions)
        # ------------------------------------------------------------------
        pd_parser = ShowRoutingPolicyPolicyDefinition(device=self.device)
        pd_result = pd_parser.parse()
        pd_root = pd_result.get("routing_policy", {})
        policy_definitions = pd_root.get("policy_definitions") or {}
        if policy_definitions:
            info["policy_definitions"] = policy_definitions

        self.info = info
