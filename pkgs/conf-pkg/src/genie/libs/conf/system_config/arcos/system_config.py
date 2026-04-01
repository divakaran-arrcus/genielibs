#!/usr/bin/env python3
"""
Native ArcOS System Configuration plugin for Genie.

Implements device-specific DeviceAttributes for ArcOS routers.
Handles system-level settings: hostname, banners, NTP, DNS, SSH,
logging, gRPC, and AAA.

All commands are under ``system ...`` (global scope).
"""

from abc import ABC
import logging
from typing import Any, Dict, List

from genie.decorator import managedattribute
from genie.conf.base.attributes import AttributesHelper
from genie.conf.base.cli import CliConfigBuilder
from genie.conf.base.config import CliConfig

logger = logging.getLogger(__name__)


def _build_ntp_servers(cfg, servers):
    """Render NTP server configurations."""
    for addr in sorted(servers.keys()):
        srv = servers[addr]
        with cfg.submode_context(f'system ntp server {addr}'):
            iburst = srv.get("iburst")
            if iburst is not None:
                cfg.append_line(
                    f'iburst {"true" if iburst else "false"}'
                )
            prefer = srv.get("prefer")
            if prefer is not None:
                cfg.append_line(
                    f'prefer {"true" if prefer else "false"}'
                )
            key_id = srv.get("key_id")
            if key_id is not None:
                cfg.append_line(f'key-id {key_id}')


def _build_aaa_server_groups(cfg, groups):
    """Render AAA server-group configurations."""
    for name in sorted(groups.keys()):
        grp = groups[name]
        with cfg.submode_context(f'system aaa server-group {name}'):
            grp_type = grp.get("type")
            if grp_type:
                cfg.append_line(f'type {grp_type}')

            for srv in grp.get("servers") or []:
                addr = srv.get("address")
                if not addr:
                    continue
                with cfg.submode_context(f'server {addr}'):
                    secret = srv.get("secret_key")
                    if secret:
                        cfg.append_line(
                            f'tacacs secret-key {secret}'
                        )


class SystemConfig(ABC):
    """ArcOS-specific System Configuration for Genie."""

    class DeviceAttributes(ABC):
        """Device-level system config attributes for ArcOS."""

        # === Basic ===

        hostname = managedattribute(
            name='hostname',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='System hostname')

        login_banner = managedattribute(
            name='login_banner',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Login banner text')

        motd_banner = managedattribute(
            name='motd_banner',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Message of the day banner')

        timezone = managedattribute(
            name='timezone',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='System timezone (e.g., America/Los_Angeles)')

        # === SSH ===

        ssh_server_enabled = managedattribute(
            name='ssh_server_enabled',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable SSH server')

        ssh_permit_root_login = managedattribute(
            name='ssh_permit_root_login',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Permit root SSH login')

        ssh_sftp_enabled = managedattribute(
            name='ssh_sftp_enabled',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable SFTP')

        # === NTP ===

        ntp_servers = managedattribute(
            name='ntp_servers',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='NTP servers keyed by address: {iburst, prefer, key_id}')

        ntp_listen_interface = managedattribute(
            name='ntp_listen_interface',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='NTP listen interface (e.g., loopback0)')

        ntp_network_instance = managedattribute(
            name='ntp_network_instance',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='NTP network-instance')

        # === DNS ===

        dns_servers = managedattribute(
            name='dns_servers',
            default=None,
            type=(None, managedattribute.test_istype(list)),
            doc='DNS server addresses')

        dns_search_domains = managedattribute(
            name='dns_search_domains',
            default=None,
            type=(None, managedattribute.test_istype(list)),
            doc='DNS search domain list')

        # === Logging ===

        logging_format = managedattribute(
            name='logging_format',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Logging format (e.g., SYSLOG_RFC_5424)')

        # === gRPC ===

        grpc_server_enabled = managedattribute(
            name='grpc_server_enabled',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Enable gRPC server')

        # === AAA ===

        aaa_server_groups = managedattribute(
            name='aaa_server_groups',
            default=None,
            type=(None, managedattribute.test_istype(dict)),
            doc='AAA server-groups keyed by name: {type, servers: [{address, secret_key}]}')

        aaa_auth_method = managedattribute(
            name='aaa_auth_method',
            default=None,
            type=(None, managedattribute.test_istype(list)),
            doc='Authentication methods (e.g., [TACACS_ALL, LOCAL])')

        aaa_auth_fallback_on_reject = managedattribute(
            name='aaa_auth_fallback_on_reject',
            default=None,
            type=(None, managedattribute.test_istype(bool)),
            doc='Authentication fallback-on-reject')

        aaa_remote_user_role = managedattribute(
            name='aaa_remote_user_role',
            default=None,
            type=(None, managedattribute.test_istype(str)),
            doc='Remote user role-override role (e.g., SYSTEM_ROLE_ADMIN)')

        aaa_authz_method = managedattribute(
            name='aaa_authz_method',
            default=None,
            type=(None, managedattribute.test_istype(list)),
            doc='Authorization methods')

        aaa_acct_method = managedattribute(
            name='aaa_acct_method',
            default=None,
            type=(None, managedattribute.test_istype(list)),
            doc='Accounting methods')

        def build_config(self, apply=True, attributes=None, unconfig=False,
                         **kwargs):
            """Build system configuration for an ArcOS device."""
            assert not kwargs, "Unexpected kwargs: {}".format(kwargs)
            attributes = AttributesHelper(self, attributes)
            configurations = CliConfigBuilder(unconfig=unconfig)

            # --- Basic ---
            v = attributes.value('hostname')
            if v is not None:
                configurations.append_line(f'system hostname {v}')

            v = attributes.value('login_banner')
            if v is not None:
                configurations.append_line(
                    f'system login-banner "{v}"'
                )

            v = attributes.value('motd_banner')
            if v is not None:
                configurations.append_line(
                    f'system motd-banner "{v}"'
                )

            v = attributes.value('timezone')
            if v is not None:
                configurations.append_line(
                    f'system clock timezone-name {v}'
                )

            # --- SSH ---
            v = attributes.value('ssh_server_enabled')
            if v is not None:
                configurations.append_line(
                    f'system ssh-server enable '
                    f'{"true" if v else "false"}'
                )

            v = attributes.value('ssh_permit_root_login')
            if v is not None:
                configurations.append_line(
                    f'system ssh-server permit-root-login '
                    f'{"true" if v else "false"}'
                )

            v = attributes.value('ssh_sftp_enabled')
            if v is not None:
                configurations.append_line(
                    f'system ssh-server sftp enable '
                    f'{"true" if v else "false"}'
                )

            # --- NTP ---
            v = attributes.value('ntp_servers')
            if v:
                _build_ntp_servers(configurations, v)

            v = attributes.value('ntp_listen_interface')
            if v is not None:
                configurations.append_line(
                    f'system ntp listen-interface {v}'
                )

            v = attributes.value('ntp_network_instance')
            if v is not None:
                configurations.append_line(
                    f'system ntp network-instance {v}'
                )

            # --- DNS ---
            dns_list = attributes.value('dns_servers')
            if dns_list:
                for dns in dns_list:
                    configurations.append_line(
                        f'system dns server {dns}'
                    )

            search = attributes.value('dns_search_domains')
            if search:
                if isinstance(search, (list, tuple)):
                    for domain in search:
                        configurations.append_line(
                            f'system dns search {domain}'
                        )
                else:
                    configurations.append_line(
                        f'system dns search {search}'
                    )

            # --- Logging ---
            v = attributes.value('logging_format')
            if v is not None:
                configurations.append_line(
                    f'system logging logging-format {v}'
                )

            # --- gRPC ---
            v = attributes.value('grpc_server_enabled')
            if v is not None:
                configurations.append_line(
                    f'system grpc-server enable '
                    f'{"true" if v else "false"}'
                )

            # --- AAA (server-groups first, then methods) ---
            v = attributes.value('aaa_server_groups')
            if v:
                _build_aaa_server_groups(configurations, v)

            v = attributes.value('aaa_auth_method')
            if v:
                if isinstance(v, (list, tuple)):
                    methods = ' '.join(str(m) for m in v)
                else:
                    methods = str(v)
                configurations.append_line(
                    f'system aaa authentication '
                    f'authentication-method [ {methods} ]'
                )

            v = attributes.value('aaa_auth_fallback_on_reject')
            if v is not None:
                configurations.append_line(
                    f'system aaa authentication fallback-on-reject '
                    f'{"true" if v else "false"}'
                )

            v = attributes.value('aaa_remote_user_role')
            if v is not None:
                configurations.append_line(
                    f'system aaa authentication remote-user '
                    f'role-override role {v}'
                )

            v = attributes.value('aaa_authz_method')
            if v:
                if isinstance(v, (list, tuple)):
                    methods = ' '.join(str(m) for m in v)
                else:
                    methods = str(v)
                configurations.append_line(
                    f'system aaa authorization '
                    f'authorization-method [ {methods} ]'
                )

            v = attributes.value('aaa_acct_method')
            if v:
                if isinstance(v, (list, tuple)):
                    methods = ' '.join(str(m) for m in v)
                else:
                    methods = str(v)
                configurations.append_line(
                    f'system aaa accounting '
                    f'accounting-method [ {methods} ]'
                )

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
            """Build system unconfiguration."""
            return self.build_config(
                apply=apply,
                attributes=attributes,
                unconfig=True,
                **kwargs,
            )
