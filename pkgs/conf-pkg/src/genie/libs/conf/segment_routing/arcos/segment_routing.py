#!/usr/bin/env python3
"""ArcOS Segment Routing (SRv6 and SR-MPLS) configuration plugin for Genie.

Implements network-instance level SRv6 and SR-MPLS configuration for Arrcus devices.

Supported attributes on sr.device_attr[device]:

SRv6:
- srv6_encap_source_address: IPv6 source address string
- srv6_locators: dict mapping locator-name -> dict/attrs with keys:
      locator_node_length (int), prefix (str),
      function_length (int), algorithm (int, optional)

SR-MPLS:
- mpls_reserved_label_blocks: dict mapping block-id -> dict/attrs with keys:
      lower_bound (int), upper_bound (int), usage (str),
      protocol_identifier (str), protocol_name (str)
"""

from abc import ABC
import logging

from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

log = logging.getLogger(__name__)


class SegmentRouting(ABC):
    """ArcOS-specific SegmentRouting implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level SRv6 configuration for a single Arrcus device."""

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build SRv6 network-instance configuration for ArcOS.

            Generates configuration of the form:

                network-instance <instance_name>
                 srv6 encapsulation source-address <ipv6>
                 srv6 locator <name>
                  locator-node-length <len>
                  prefix              <prefix>
                  function-length     <len>
                  algorithm           <id>   (optional)
                 !
                !
            """

            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # Determine network-instance name (default if not set)
            device = getattr(self, "device", None)
            instance_name = getattr(getattr(device, "custom", {}), "get", lambda *_: "default")(
                "instance_name", "default"
            )

            if unconfig:
                # Simple unconfiguration - rely on CliConfigBuilder to prepend 'no'
                # and remove SRv6 configuration for this network instance.
                configurations.append_line(f"network-instance {instance_name} srv6")

            else:
                with configurations.submode_context(f"network-instance {instance_name}"):
                    # Encapsulation source-address
                    srv6_encap_source = attributes.value("srv6_encap_source_address")
                    srv6_locators = attributes.value("srv6_locators")

                    if srv6_encap_source:
                        configurations.append_line(
                            f"srv6 encapsulation source-address {srv6_encap_source}"
                        )

                    locator_items = []
                    if srv6_locators:
                        # Expect a mapping: {locator_name: locator_attrs}
                        # where locator_attrs can be either a plain dict or an
                        # attribute-style object.
                        if hasattr(srv6_locators, "items"):
                            locator_items = sorted(srv6_locators.items())

                    for locator_name, locator_attrs in locator_items:
                        if not locator_name or locator_attrs is None:
                            continue

                        def _get(attr_name):
                            if isinstance(locator_attrs, dict):
                                return locator_attrs.get(attr_name)
                            return getattr(locator_attrs, attr_name, None)

                        with configurations.submode_context(
                            f"srv6 locator {locator_name}"
                        ):
                            node_len = _get("locator_node_length")
                            if node_len is not None:
                                configurations.append_line(
                                    f"locator-node-length {node_len}"
                                )

                            prefix = _get("prefix")
                            if prefix:
                                configurations.append_line(f"prefix {prefix}")

                            func_len = _get("function_length")
                            if func_len is not None:
                                configurations.append_line(
                                    f"function-length {func_len}"
                                )

                            algorithm = _get("algorithm")
                            if algorithm is not None:
                                configurations.append_line(f"algorithm {algorithm}")

                        # Add explicit '!' after each locator block to match
                        # Arrcus running-config style.
                        configurations.append_line("!")

                    # ========================================
                    # SR-MPLS: MPLS Reserved Label Blocks
                    # ========================================
                    mpls_label_blocks = attributes.value("mpls_reserved_label_blocks")
                    if mpls_label_blocks and hasattr(mpls_label_blocks, "items"):
                        for block_id, block_attrs in sorted(mpls_label_blocks.items()):
                            if not block_id or block_attrs is None:
                                continue

                            def _get_block(attr_name):
                                if isinstance(block_attrs, dict):
                                    return block_attrs.get(attr_name)
                                return getattr(block_attrs, attr_name, None)

                            with configurations.submode_context(
                                f"mpls global reserved-label-block {block_id}"
                            ):
                                lower_bound = _get_block("lower_bound")
                                if lower_bound is not None:
                                    configurations.append_line(
                                        f"lower-bound         {lower_bound}"
                                    )

                                upper_bound = _get_block("upper_bound")
                                if upper_bound is not None:
                                    configurations.append_line(
                                        f"upper-bound         {upper_bound}"
                                    )

                                usage = _get_block("usage")
                                if usage:
                                    configurations.append_line(
                                        f"usage               {usage}"
                                    )

                                protocol_id = _get_block("protocol_identifier")
                                if protocol_id:
                                    configurations.append_line(
                                        f"protocol-identifier {protocol_id}"
                                    )

                                protocol_name = _get_block("protocol_name")
                                if protocol_name:
                                    configurations.append_line(
                                        f"protocol-name       {protocol_name}"
                                    )

                            # Add explicit '!' after each block
                            configurations.append_line("!")

                # Close network-instance
                configurations.append_line("!")

            if apply:
                if configurations and device is not None:
                    device.configure(str(configurations))
            else:
                return CliConfig(
                    device=device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build SRv6 unconfiguration commands."""

            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )
