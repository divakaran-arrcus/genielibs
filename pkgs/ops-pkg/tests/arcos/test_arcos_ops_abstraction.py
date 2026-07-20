"""Dispatch test for arcOS Ops abstraction tokens.

This is a regression test for a bug where the ``os='arcos'`` abstraction
token was never declared in any of the 14 arcOS Ops feature packages
(``genie.libs.ops.<feature>.arcos``). Without ``abstract.declare_token(os='arcos')``
being called in that package's ``__init__.py``, ``genie.abstract.Lookup`` /
``device.learn()`` cannot resolve the arcos-specific Ops implementation for a
device with ``os='arcos'`` -- it silently falls back to the generic (non-OS)
base Ops module instead, with no error raised.

Two tiers of assertion are used per feature:

1. **End-to-end dispatch** (primary, strongest): build a mock device with
   ``os='arcos'`` and resolve the Ops module through the real
   ``genie.abstract.Lookup.from_device()`` machinery, exactly as
   ``device.learn()`` would. If the token is missing, this resolves to the
   generic base module (e.g. ``genie.libs.ops.acl.acl``) instead of the
   arcos module (``genie.libs.ops.acl.arcos.acl``), and the assertion on the
   resolved module name fails.

2. **Token registration** (direct root-cause check): import
   ``genie.libs.ops.<feature>.arcos`` directly and assert that
   ``declare_token`` actually ran by inspecting the module's
   ``__abstract_token`` attribute for ``{'os': 'arcos'}``. This is the
   fallback described for any feature where full Lookup wiring is not
   feasible, and also pinpoints the missing-token failure mode precisely.

If any of the 14 features loses its token declaration (or a token dict
that doesn't include ``os: arcos``), both assertions for that feature fail.
"""

import importlib
import unittest
from unittest.mock import Mock

import genie.abstract as abstract
import genie.libs.ops as ops_pkg

# (feature package name, expected arcos Ops class name)
FEATURES = [
    ("acl", "Acl"),
    ("bfd", "Bfd"),
    ("bgp", "Bgp"),
    ("lag", "Lag"),
    ("lldp", "Lldp"),
    ("ntp", "Ntp"),
    ("ospf", "Ospf"),
    ("static_routing", "StaticRouting"),
    ("stp", "Stp"),
    ("vlan", "Vlan"),
    ("vrrp", "Vrrp"),
    ("interface", "Interface"),
    ("isis", "Isis"),
    ("route_policy", "RoutePolicy"),
]


def _make_arcos_device():
    """A minimal mock device that satisfies Lookup.from_device()."""
    device = Mock()
    device.os = "arcos"
    device.custom = {}
    device.platform = None
    return device


class TestArcosOpsAbstractionDispatch(unittest.TestCase):
    """Prove that all 14 arcOS Ops features resolve via abstraction."""

    def setUp(self):
        self.device = _make_arcos_device()

    def test_all_14_features_covered(self):
        """Sanity check that this test's feature list matches the arcos Ops
        directories on disk, so a 15th feature added later doesn't slip
        through uncovered.
        """
        import os

        ops_root = os.path.dirname(ops_pkg.__file__)
        arcos_dirs = sorted(
            name
            for name in os.listdir(ops_root)
            if os.path.isdir(os.path.join(ops_root, name, "arcos"))
        )
        expected = sorted(name for name, _ in FEATURES)
        self.assertEqual(
            arcos_dirs,
            expected,
            "FEATURES list in this test is out of sync with the "
            "genie.libs.ops.<feature>.arcos directories on disk",
        )

    def test_dispatch_resolves_arcos_class_for_each_feature(self):
        """Tier 1: real genie.abstract.Lookup dispatch, per feature.

        Before the fix, this fails (or silently mis-resolves to the base
        module) because no feature declared os='arcos'.
        """
        for feat, class_name in FEATURES:
            with self.subTest(feature=feat):
                lookup = abstract.Lookup.from_device(
                    self.device, packages={"ops": ops_pkg}
                )
                expected_module_name = f"genie.libs.ops.{feat}.arcos.{feat}"

                try:
                    feat_pkg = getattr(lookup.ops, feat)
                    resolved_mod = getattr(feat_pkg, feat)
                except LookupError as e:
                    self.fail(
                        f"abstraction Lookup could not resolve "
                        f"genie.libs.ops.{feat} for os='arcos' -- the "
                        f"arcos token is not declared (or the package is "
                        f"broken): {e}"
                    )

                self.assertEqual(
                    resolved_mod.__name__,
                    expected_module_name,
                    f"device.os='arcos' resolved genie.libs.ops.{feat} to "
                    f"{resolved_mod.__name__!r} instead of "
                    f"{expected_module_name!r} -- the arcos ops module for "
                    f"'{feat}' is missing its abstraction token, so "
                    f"abstraction silently fell back to the generic base "
                    f"implementation instead of the arcos one",
                )

                resolved_cls = getattr(resolved_mod, class_name)
                arcos_module = importlib.import_module(expected_module_name)
                expected_cls = getattr(arcos_module, class_name)
                self.assertIs(
                    resolved_cls,
                    expected_cls,
                    f"resolved {class_name} for '{feat}' is not the same "
                    f"class object as genie.libs.ops.{feat}.arcos.{feat}.{class_name}",
                )

    def test_arcos_token_declared_for_each_feature(self):
        """Tier 2: direct root-cause check -- declare_token(os='arcos')
        actually ran in genie.libs.ops.<feature>.arcos's __init__.py.

        This is the fallback check called out for cases where full Lookup
        wiring may not be exercised (e.g. custom features with no XR/XE
        sibling), and it isolates the exact failure mode: a missing or
        wrong abstraction token on the package, independent of the Lookup
        wrapper's resolution mechanics.
        """
        for feat, class_name in FEATURES:
            with self.subTest(feature=feat):
                arcos_pkg = importlib.import_module(
                    f"genie.libs.ops.{feat}.arcos"
                )

                token = getattr(arcos_pkg, "__abstract_token", None)
                self.assertIsNotNone(
                    token,
                    f"genie.libs.ops.{feat}.arcos has no __abstract_token -- "
                    f"declare_token(os='arcos') was never called in its "
                    f"__init__.py",
                )
                self.assertEqual(
                    token.matches.get("os"),
                    "arcos",
                    f"genie.libs.ops.{feat}.arcos declared a token, but it "
                    f"does not match os='arcos': {token.matches!r}",
                )

                # The arcos Ops class must also be reachable from the
                # package that declares the token.
                self.assertTrue(
                    hasattr(arcos_pkg, class_name)
                    or hasattr(
                        importlib.import_module(
                            f"genie.libs.ops.{feat}.arcos.{feat}"
                        ),
                        class_name,
                    ),
                    f"could not find {class_name} via genie.libs.ops.{feat}.arcos",
                )


if __name__ == "__main__":
    unittest.main()
