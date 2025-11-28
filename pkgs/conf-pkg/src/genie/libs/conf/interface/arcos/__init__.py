from .interface import *
from .interface import Interface as _ArcosFeatureInterface

# Enable abstraction using this directory name as the abstraction token
try:
    from genie import abstract
    abstract.declare_token(os='arcos')
except Exception as e:  # pragma: no cover - defensive
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

import logging
import sys

log = logging.getLogger(__name__)

# Patch genie.libs.conf.interface.Interface so that for devices with os='arcos'
# build_config/build_unconfig delegate to the ArcOS implementation.
genie_iface_mod = sys.modules.get("genie.libs.conf.interface")
if genie_iface_mod is not None:
    BaseInterface = genie_iface_mod.Interface

    _ArcosInterfaceAttributes = (
        _ArcosFeatureInterface.DeviceAttributes.InterfaceAttributes
    )

    class ArcosAwareInterface(BaseInterface):
        """Enhanced Interface class with ArcOS support.

        For os='arcos' devices this overrides the normal abstract lookup and
        delegates CLI generation to the ArcOS-specific
        DeviceAttributes.InterfaceAttributes implementation. It also applies
        the resulting configuration when apply=True by calling
        ``device.configure(...)``.
        """

        def build_config(
            self,
            apply: bool = True,
            attributes=None,
            unconfig: bool = False,
            **kwargs,
        ):
            # Determine target devices (default to this interface's device).
            devices = kwargs.get(
                "devices",
                [self.device]
                if hasattr(self, "device") and self.device is not None
                else [],
            )

            if devices and getattr(devices[0], "os", None) == "arcos":
                # Build CLI for this interface using the ArcOS
                # InterfaceAttributes implementation.
                original_interface_attr = getattr(self, "interface", None)
                self.interface = self
                try:
                    cfg = _ArcosInterfaceAttributes.build_config(
                        self,
                        apply=False,  # never auto-apply at this level
                        attributes=attributes,
                        unconfig=unconfig,
                        **kwargs,
                    )
                finally:
                    if original_interface_attr is not None:
                        self.interface = original_interface_attr
                    elif hasattr(self, "interface"):
                        delattr(self, "interface")

                # cfg is a CliConfig (or similar) containing the CLI.
                if apply and hasattr(self, "device") and self.device is not None:
                    try:
                        cli_obj = getattr(cfg, "cli_config", cfg)
                        config_str = str(cli_obj)
                        log.debug("ArcOS interface config to apply:\n%s", config_str)
                        if not config_str.strip():
                            log.warning("Generated config is empty, nothing to apply")
                        else:
                            self.device.configure(config_str)
                    except Exception:
                        log.exception(
                            "Failed to apply ArcOS interface config on %s", self.device
                        )
                        raise

                return cfg

            # For non-ArcOS devices, fall back to the base implementation
            return BaseInterface.build_config(
                self,
                apply=apply,
                attributes=attributes,
                unconfig=unconfig,
                **kwargs,
            )

        def build_unconfig(self, apply: bool = True, attributes=None, **kwargs):
            """Build interface unconfiguration.

            This simply calls :meth:`build_config` with ``unconfig=True`` so the
            same ArcOS-specific logic is reused.
            """
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

    genie_iface_mod.Interface = ArcosAwareInterface
    sys.modules["genie.libs.conf.interface"].Interface = ArcosAwareInterface
