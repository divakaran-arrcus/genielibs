#!/usr/bin/env python3
"""Unit tests for arcOS Segment Routing get APIs (full coverage).

The get helpers instantiate parser classes directly (not device.parse):
  - ShowSrv6Config       -> get_srv6_encap_source_address
  - ShowSrv6Locator      -> get_srv6_locators / get_srv6_locator / ...
  - ShowSrmsMappingsConfig -> get_srms_mappings / get_srms_mapping / ...
  - ShowSrv6LocalSids    -> get_srv6_local_sids / get_srv6_local_sid / ...

Each parser class is patched at its import site inside
genie.libs.sdk.apis.arcos.segment_routing.get, and its .parse() is mocked
to return canned OpenConfig-shaped dicts matching each parser's schema.
"""

import unittest
from unittest.mock import patch, Mock

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.segment_routing import get as sr_get
from genie.libs.sdk.apis.arcos.segment_routing.get import (
    get_srv6_locators,
    get_srv6_locator,
    get_srv6_locator_count,
    get_srv6_encap_source_address,
    is_srv6_locator_present,
    get_srms_mappings,
    get_srms_mapping,
    get_srms_mapping_count,
    is_srms_mapping_present,
    get_srv6_locator_prefix,
    get_srv6_locator_algorithm,
    get_srv6_locator_micro_segment_enabled,
    get_srv6_locator_node_length,
    get_srv6_locator_function_length,
    get_srv6_local_sids,
    get_srv6_local_sid,
    get_srv6_local_sid_behavior,
    get_srv6_local_sids_by_locator,
    get_mpls_reserved_label_blocks,
    get_mpls_reserved_label_block,
)

MOD = "genie.libs.sdk.apis.arcos.segment_routing.get"


# ---------------------------------------------------------------------------
# Canned parser output
# ---------------------------------------------------------------------------

SRV6_CONFIG_OUTPUT = {
    "network-instances": {
        "default": {
            "srv6": {
                "config": {
                    "encapsulation": {"source-address": "2001:db8::1"},
                }
            }
        }
    }
}

SRV6_CONFIG_NO_ENCAP_OUTPUT = {
    "network-instances": {
        "default": {
            "srv6": {"config": {}}
        }
    }
}

SRV6_LOCATOR_OUTPUT = {
    "network-instances": {
        "default": {
            "srv6": {
                "locators": {
                    "loc1": {
                        "name": "loc1",
                        "locator-node-length": 24,
                        "prefix": "fcbb:bb00:1::/48",
                        "function-length": 16,
                        "algorithm": 128,
                        "micro-segment-behavior-unode": True,
                    },
                    "loc2": {
                        "name": "loc2",
                        "locator-node-length": 24,
                        "prefix": "fcbb:bb00:2::/48",
                        "micro-segment-behavior-unode": False,
                    },
                }
            }
        }
    }
}

SRMS_MAPPINGS_OUTPUT = {
    "network-instances": {
        "default": {
            "srms": {
                "mappings": {
                    "100": {
                        "local-id": "100",
                        "ipv4-prefixes": [
                            {"prefix": "10.0.0.0/24", "sid": 16000, "range": 100}
                        ],
                    }
                }
            }
        }
    }
}

SRV6_LOCAL_SIDS_OUTPUT = {
    "network_instance": {
        "default": {
            "local_sids": {
                "fcbb:bb00:1:1::/64": {
                    "behavior": "END_PSP_USD",
                    "locator_name": "loc1",
                    "client_name": "isis",
                    "sid_paths": [
                        {"next_hop_address": "fcbb:bb00:2::1", "interface": "swp1"}
                    ],
                },
                "fcbb:bb00:2:1::/64": {
                    "behavior": "END_X",
                    "locator_name": "loc2",
                    "client_name": "isis",
                },
            }
        }
    }
}


def _mock_parser_class(return_value=None, side_effect=None):
    """Return a Mock that behaves like ``ParserClass(device=device)`` whose
    ``.parse(instance=ni)`` returns/raises as specified."""
    instance = Mock()
    if side_effect is not None:
        instance.parse = Mock(side_effect=side_effect)
    else:
        instance.parse = Mock(return_value=return_value)
    cls = Mock(return_value=instance)
    return cls, instance


# ---------------------------------------------------------------------------
# ShowSrv6Config -> get_srv6_encap_source_address
# ---------------------------------------------------------------------------

class TestSrv6ConfigGetApis(unittest.TestCase):
    """get_srv6_encap_source_address (backed by ShowSrv6Config)."""

    def test_encap_source_address_found(self):
        cls, _ = _mock_parser_class(return_value=SRV6_CONFIG_OUTPUT)
        with patch(f"{MOD}.ShowSrv6Config", cls):
            result = get_srv6_encap_source_address(object())
        self.assertEqual(result, "2001:db8::1")

    def test_encap_source_address_missing(self):
        cls, _ = _mock_parser_class(return_value=SRV6_CONFIG_NO_ENCAP_OUTPUT)
        with patch(f"{MOD}.ShowSrv6Config", cls):
            result = get_srv6_encap_source_address(object())
        self.assertIsNone(result)

    def test_encap_source_address_schema_empty(self):
        cls, _ = _mock_parser_class(
            side_effect=SchemaEmptyParserError("empty")
        )
        with patch(f"{MOD}.ShowSrv6Config", cls):
            result = get_srv6_encap_source_address(object())
        self.assertIsNone(result)

    def test_encap_source_address_subcommand_failure(self):
        cls, _ = _mock_parser_class(
            side_effect=SubCommandFailure("boom")
        )
        with patch(f"{MOD}.ShowSrv6Config", cls):
            result = get_srv6_encap_source_address(object())
        self.assertIsNone(result)

    def test_encap_source_address_generic_exception(self):
        cls, _ = _mock_parser_class(side_effect=ValueError("weird"))
        with patch(f"{MOD}.ShowSrv6Config", cls):
            result = get_srv6_encap_source_address(object())
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# ShowSrv6Locator -> locator getters
# ---------------------------------------------------------------------------

class TestSrv6LocatorGetApis(unittest.TestCase):
    """get_srv6_locators / get_srv6_locator / get_srv6_locator_count /
    is_srv6_locator_present / get_srv6_locator_prefix /
    get_srv6_locator_algorithm / get_srv6_locator_micro_segment_enabled /
    get_srv6_locator_node_length / get_srv6_locator_function_length
    (backed by ShowSrv6Locator)."""

    def setUp(self):
        self.cls, _ = _mock_parser_class(return_value=SRV6_LOCATOR_OUTPUT)
        self.patcher = patch(f"{MOD}.ShowSrv6Locator", self.cls)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_get_srv6_locators(self):
        locators = get_srv6_locators(object())
        self.assertEqual(set(locators), {"loc1", "loc2"})

    def test_get_srv6_locator_found(self):
        loc = get_srv6_locator(object(), "loc1")
        self.assertEqual(loc["prefix"], "fcbb:bb00:1::/48")

    def test_get_srv6_locator_missing(self):
        self.assertIsNone(get_srv6_locator(object(), "loc-none"))

    def test_get_srv6_locator_count(self):
        self.assertEqual(get_srv6_locator_count(object()), 2)

    def test_is_srv6_locator_present_true(self):
        self.assertTrue(is_srv6_locator_present(object(), "loc1"))

    def test_is_srv6_locator_present_false(self):
        self.assertFalse(is_srv6_locator_present(object(), "loc-none"))

    def test_get_srv6_locator_prefix(self):
        self.assertEqual(
            get_srv6_locator_prefix(object(), "loc1"), "fcbb:bb00:1::/48"
        )

    def test_get_srv6_locator_prefix_missing_locator(self):
        self.assertIsNone(get_srv6_locator_prefix(object(), "loc-none"))

    def test_get_srv6_locator_algorithm(self):
        self.assertEqual(get_srv6_locator_algorithm(object(), "loc1"), 128)

    def test_get_srv6_locator_algorithm_not_set(self):
        self.assertIsNone(get_srv6_locator_algorithm(object(), "loc2"))

    def test_get_srv6_locator_algorithm_missing_locator(self):
        self.assertIsNone(get_srv6_locator_algorithm(object(), "loc-none"))

    def test_get_srv6_locator_micro_segment_enabled_true(self):
        self.assertTrue(
            get_srv6_locator_micro_segment_enabled(object(), "loc1")
        )

    def test_get_srv6_locator_micro_segment_enabled_false(self):
        self.assertFalse(
            get_srv6_locator_micro_segment_enabled(object(), "loc2")
        )

    def test_get_srv6_locator_micro_segment_enabled_missing_locator(self):
        self.assertIsNone(
            get_srv6_locator_micro_segment_enabled(object(), "loc-none")
        )

    def test_get_srv6_locator_node_length(self):
        self.assertEqual(get_srv6_locator_node_length(object(), "loc1"), 24)

    def test_get_srv6_locator_node_length_missing_locator(self):
        self.assertIsNone(get_srv6_locator_node_length(object(), "loc-none"))

    def test_get_srv6_locator_function_length(self):
        self.assertEqual(
            get_srv6_locator_function_length(object(), "loc1"), 16
        )

    def test_get_srv6_locator_function_length_not_set(self):
        self.assertIsNone(get_srv6_locator_function_length(object(), "loc2"))

    def test_get_srv6_locator_function_length_missing_locator(self):
        self.assertIsNone(
            get_srv6_locator_function_length(object(), "loc-none")
        )


class TestSrv6LocatorGetApisDegraded(unittest.TestCase):
    """Empty/error paths for the ShowSrv6Locator-backed getters."""

    def test_get_srv6_locators_schema_empty(self):
        cls, _ = _mock_parser_class(side_effect=SchemaEmptyParserError("e"))
        with patch(f"{MOD}.ShowSrv6Locator", cls):
            self.assertEqual(get_srv6_locators(object()), {})

    def test_get_srv6_locators_subcommand_failure(self):
        cls, _ = _mock_parser_class(side_effect=SubCommandFailure("e"))
        with patch(f"{MOD}.ShowSrv6Locator", cls):
            self.assertEqual(get_srv6_locators(object()), {})

    def test_get_srv6_locators_generic_exception(self):
        cls, _ = _mock_parser_class(side_effect=RuntimeError("e"))
        with patch(f"{MOD}.ShowSrv6Locator", cls):
            self.assertEqual(get_srv6_locators(object()), {})

    def test_is_srv6_locator_present_false_when_empty(self):
        cls, _ = _mock_parser_class(side_effect=SchemaEmptyParserError("e"))
        with patch(f"{MOD}.ShowSrv6Locator", cls):
            self.assertFalse(is_srv6_locator_present(object(), "loc1"))


# ---------------------------------------------------------------------------
# ShowSrmsMappingsConfig -> SRMS mapping getters
# ---------------------------------------------------------------------------

class TestSrmsMappingGetApis(unittest.TestCase):
    """get_srms_mappings / get_srms_mapping / get_srms_mapping_count /
    is_srms_mapping_present (backed by ShowSrmsMappingsConfig)."""

    def setUp(self):
        self.cls, _ = _mock_parser_class(return_value=SRMS_MAPPINGS_OUTPUT)
        self.patcher = patch(f"{MOD}.ShowSrmsMappingsConfig", self.cls)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_get_srms_mappings(self):
        self.assertEqual(set(get_srms_mappings(object())), {"100"})

    def test_get_srms_mapping_found(self):
        mapping = get_srms_mapping(object(), "100")
        self.assertEqual(mapping["local-id"], "100")

    def test_get_srms_mapping_missing(self):
        self.assertIsNone(get_srms_mapping(object(), "999"))

    def test_get_srms_mapping_count(self):
        self.assertEqual(get_srms_mapping_count(object()), 1)

    def test_is_srms_mapping_present_true(self):
        self.assertTrue(is_srms_mapping_present(object(), "100"))

    def test_is_srms_mapping_present_false(self):
        self.assertFalse(is_srms_mapping_present(object(), "999"))


class TestSrmsMappingGetApisDegraded(unittest.TestCase):
    """Empty/error paths for the ShowSrmsMappingsConfig-backed getters."""

    def test_get_srms_mappings_schema_empty(self):
        cls, _ = _mock_parser_class(side_effect=SchemaEmptyParserError("e"))
        with patch(f"{MOD}.ShowSrmsMappingsConfig", cls):
            self.assertEqual(get_srms_mappings(object()), {})

    def test_get_srms_mappings_subcommand_failure(self):
        cls, _ = _mock_parser_class(side_effect=SubCommandFailure("e"))
        with patch(f"{MOD}.ShowSrmsMappingsConfig", cls):
            self.assertEqual(get_srms_mappings(object()), {})

    def test_get_srms_mappings_generic_exception(self):
        cls, _ = _mock_parser_class(side_effect=KeyError("e"))
        with patch(f"{MOD}.ShowSrmsMappingsConfig", cls):
            self.assertEqual(get_srms_mappings(object()), {})


# ---------------------------------------------------------------------------
# ShowSrv6LocalSids -> local-SID getters
# ---------------------------------------------------------------------------

class TestSrv6LocalSidsGetApis(unittest.TestCase):
    """get_srv6_local_sids / get_srv6_local_sid / get_srv6_local_sid_behavior
    / get_srv6_local_sids_by_locator (backed by ShowSrv6LocalSids)."""

    def setUp(self):
        self.cls, _ = _mock_parser_class(return_value=SRV6_LOCAL_SIDS_OUTPUT)
        self.patcher = patch(f"{MOD}.ShowSrv6LocalSids", self.cls)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_get_srv6_local_sids(self):
        sids = get_srv6_local_sids(object())
        self.assertEqual(
            set(sids), {"fcbb:bb00:1:1::/64", "fcbb:bb00:2:1::/64"}
        )

    def test_get_srv6_local_sid_found(self):
        entry = get_srv6_local_sid(object(), "fcbb:bb00:1:1::/64")
        self.assertEqual(entry["behavior"], "END_PSP_USD")

    def test_get_srv6_local_sid_missing(self):
        self.assertIsNone(
            get_srv6_local_sid(object(), "fcbb:bb00:9:9::/64")
        )

    def test_get_srv6_local_sid_behavior_found(self):
        self.assertEqual(
            get_srv6_local_sid_behavior(object(), "fcbb:bb00:1:1::/64"),
            "END_PSP_USD",
        )

    def test_get_srv6_local_sid_behavior_missing_sid(self):
        self.assertIsNone(
            get_srv6_local_sid_behavior(object(), "fcbb:bb00:9:9::/64")
        )

    def test_get_srv6_local_sids_by_locator(self):
        filtered = get_srv6_local_sids_by_locator(object(), "loc1")
        self.assertEqual(set(filtered), {"fcbb:bb00:1:1::/64"})

    def test_get_srv6_local_sids_by_locator_no_match(self):
        filtered = get_srv6_local_sids_by_locator(object(), "loc-none")
        self.assertEqual(filtered, {})


class TestSrv6LocalSidsGetApisDegraded(unittest.TestCase):
    """Empty/error paths for the ShowSrv6LocalSids-backed getters."""

    def test_get_srv6_local_sids_schema_empty(self):
        cls, _ = _mock_parser_class(side_effect=SchemaEmptyParserError("e"))
        with patch(f"{MOD}.ShowSrv6LocalSids", cls):
            self.assertEqual(get_srv6_local_sids(object()), {})

    def test_get_srv6_local_sids_subcommand_failure(self):
        cls, _ = _mock_parser_class(side_effect=SubCommandFailure("e"))
        with patch(f"{MOD}.ShowSrv6LocalSids", cls):
            self.assertEqual(get_srv6_local_sids(object()), {})

    def test_get_srv6_local_sids_generic_exception(self):
        cls, _ = _mock_parser_class(side_effect=TypeError("e"))
        with patch(f"{MOD}.ShowSrv6LocalSids", cls):
            self.assertEqual(get_srv6_local_sids(object()), {})



# ---------------------------------------------------------------------------
# MPLS reserved label blocks
# ---------------------------------------------------------------------------
#
# The `usage` leaf is Optional in the parser schema for a concrete reason:
# arcOS rejects an unknown usage enum as `syntax error: unknown element` but
# still commits the rest of the block, so a block created with a bad token
# exists on the box WITHOUT a usage leaf. RLB_NO_USAGE_OUTPUT is that state,
# as nightly build 1541 left it on six routers.

RLB_OUTPUT = {
    "network-instance": {
        "default": {
            "mpls": {
                "reserved-label-blocks": {
                    "SRGB_BLOCK": {
                        "local-id": "SRGB_BLOCK",
                        "lower-bound": 16000,
                        "upper-bound": 23999,
                        "usage": "ISIS_SRGB",
                        "protocol-identifier": "ISIS",
                        "protocol-name": "default",
                    },
                    "SRLB_BLOCK": {
                        "local-id": "SRLB_BLOCK",
                        "lower-bound": 15000,
                        "upper-bound": 15999,
                        "usage": "ISIS_SRLB",
                        "protocol-identifier": "ISIS",
                        "protocol-name": "default",
                    },
                }
            }
        }
    }
}

RLB_NO_USAGE_OUTPUT = {
    "network-instance": {
        "default": {
            "mpls": {
                "reserved-label-blocks": {
                    "SRGB_BLOCK": {
                        "local-id": "SRGB_BLOCK",
                        "lower-bound": 16000,
                        "upper-bound": 23999,
                        "protocol-identifier": "ISIS",
                        "protocol-name": "default",
                    },
                }
            }
        }
    }
}


class TestGetMplsReservedLabelBlocks(unittest.TestCase):
    """get_mpls_reserved_label_blocks / get_mpls_reserved_label_block"""

    def _patch(self, **kw):
        return patch(f"{MOD}.ShowMplsReservedLabelBlockConfig", **kw)

    def _parser(self, output):
        cls = Mock()
        cls.return_value.parse = Mock(return_value=output)
        return cls

    def test_get_blocks_returns_all(self):
        with self._patch(new=self._parser(RLB_OUTPUT)):
            blocks = get_mpls_reserved_label_blocks(Mock())
        self.assertEqual(sorted(blocks), ["SRGB_BLOCK", "SRLB_BLOCK"])
        self.assertEqual(blocks["SRGB_BLOCK"]["usage"], "ISIS_SRGB")
        self.assertEqual(blocks["SRLB_BLOCK"]["lower-bound"], 15000)

    def test_get_single_block(self):
        with self._patch(new=self._parser(RLB_OUTPUT)):
            block = get_mpls_reserved_label_block(Mock(), "SRLB_BLOCK")
        self.assertEqual(block["upper-bound"], 15999)

    def test_get_single_block_absent_is_none(self):
        with self._patch(new=self._parser(RLB_OUTPUT)):
            self.assertIsNone(
                get_mpls_reserved_label_block(Mock(), "NOPE_BLOCK"))

    def test_rejected_usage_leaf_is_simply_absent(self):
        """A block whose usage token arcOS refused has no usage key at all."""
        with self._patch(new=self._parser(RLB_NO_USAGE_OUTPUT)):
            block = get_mpls_reserved_label_block(Mock(), "SRGB_BLOCK")
        self.assertNotIn("usage", block)
        self.assertEqual(block["lower-bound"], 16000)

    def test_no_blocks_configured_returns_empty(self):
        cls = Mock()
        cls.return_value.parse = Mock(side_effect=SchemaEmptyParserError("x"))
        with self._patch(new=cls):
            self.assertEqual(get_mpls_reserved_label_blocks(Mock()), {})

    def test_subcommandfailure_returns_empty(self):
        cls = Mock()
        cls.return_value.parse = Mock(side_effect=SubCommandFailure("x"))
        with self._patch(new=cls):
            self.assertEqual(get_mpls_reserved_label_blocks(Mock()), {})

    def test_unexpected_parser_error_returns_empty(self):
        """Defensive: {} means "absent OR unreadable", never a raise."""
        cls = Mock()
        cls.return_value.parse = Mock(side_effect=ValueError("boom"))
        with self._patch(new=cls):
            self.assertEqual(get_mpls_reserved_label_blocks(Mock()), {})

    def test_ni_is_threaded_to_the_parser(self):
        cls = self._parser(RLB_OUTPUT)
        with self._patch(new=cls):
            get_mpls_reserved_label_blocks(Mock(), ni="vrf-red")
        cls.return_value.parse.assert_called_once_with(
            network_instance="vrf-red")


class TestSegmentRoutingGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    segment_routing/get.py must be referenced by name somewhere in this
    test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sr_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sr_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Segment Routing get functions: {missing}")

        print(
            f"\nSegment Routing get coverage: {len(names)} functions, "
            f"0 missing"
        )


if __name__ == "__main__":
    unittest.main()
