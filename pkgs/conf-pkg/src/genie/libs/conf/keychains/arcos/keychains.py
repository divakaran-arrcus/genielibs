#!/usr/bin/env python3
"""
Native ArcOS Keychain configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles keychain creation with key entries including secret-key,
crypto-algorithm, and send-lifetime configuration.

CLI structure:
    keychain <name>
     tolerance <seconds>
     key <key-id>
      secret-key <string>
      crypto-algorithm <algorithm>
      send-lifetime always true|false
      send-lifetime start-time <CCYY-MM-DDTHH:MM:SS>
      send-lifetime end-time <CCYY-MM-DDTHH:MM:SS>
     !
    !
"""

from abc import ABC
import logging

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


class Keychains(ABC):
    """ArcOS-specific Keychains implementation for Genie."""

    class DeviceAttributes(ABC):
        """Device-level Keychain attributes for ArcOS."""

        keychain_name = managedattribute(
            name='keychain_name',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Keychain name (e.g., isis-key, mykeychain)')

        tolerance = managedattribute(
            name='tolerance',
            default=None,
            type=(None, managedattribute.test_istype(int)),
            doc='Time before/after lifetime to accept received key (seconds)')

        keys = managedattribute(
            name='keys',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='Dictionary of key entries keyed by key_id')

        def build_config(self, apply=True, attributes=None, unconfig=False, **kwargs):
            """Build keychain configuration for ArcOS device."""
            assert not kwargs, f"Unexpected kwargs: {kwargs}"
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            kc_name = attributes.value('keychain_name')
            if not kc_name:
                logger.warning("No keychain_name set — skipping config")
                if apply:
                    return
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

            if unconfig:
                # Remove the entire keychain
                configurations.append_line(f'no keychain {kc_name}')
            else:
                with configurations.submode_context(f'keychain {kc_name}'):
                    # Tolerance
                    tol = attributes.value('tolerance')
                    if tol is not None:
                        configurations.append_line(f'tolerance {tol}')

                    # Key entries
                    keys_dict = attributes.value('keys')
                    if keys_dict:
                        for key_id in sorted(keys_dict.keys(), key=lambda k: int(k)):
                            key_entry = keys_dict[key_id]
                            self._build_key_config(
                                configurations, key_id, key_entry)

            # Apply or return
            if apply:
                if configurations:
                    self.device.configure(
                        str(configurations), fail_invalid=True)
            else:
                return CliConfig(
                    device=self.device,
                    unconfig=unconfig,
                    cli_config=configurations,
                )

        def build_unconfig(self, apply=True, attributes=None, **kwargs):
            """Build keychain unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )

        @staticmethod
        def _build_key_config(configurations, key_id, key_entry):
            """Build configuration for a single key entry.

            Args:
                configurations: CliConfigBuilder instance.
                key_id: Key ID (int or str).
                key_entry: Dict with key properties:
                    - secret_key (str): password/passphrase
                    - crypto_algorithm (str): HMAC algorithm
                    - send_lifetime_always (bool): permanent validity
                    - send_lifetime_start_time (str): start datetime
                    - send_lifetime_end_time (str): end datetime
            """
            if not isinstance(key_entry, dict):
                return

            with configurations.submode_context(f'key {key_id}'):
                # Secret key
                secret = key_entry.get('secret_key')
                if secret is not None:
                    configurations.append_line(f'secret-key {secret}')

                # Crypto algorithm
                algo = key_entry.get('crypto_algorithm')
                if algo is not None:
                    configurations.append_line(f'crypto-algorithm {algo}')

                # Send lifetime — always
                always = key_entry.get('send_lifetime_always')
                if always is not None:
                    val = 'true' if always else 'false'
                    configurations.append_line(f'send-lifetime always {val}')

                # Send lifetime — start-time
                start = key_entry.get('send_lifetime_start_time')
                if start is not None:
                    configurations.append_line(
                        f'send-lifetime start-time {start}')

                # Send lifetime — end-time
                end = key_entry.get('send_lifetime_end_time')
                if end is not None:
                    configurations.append_line(
                        f'send-lifetime end-time {end}')
