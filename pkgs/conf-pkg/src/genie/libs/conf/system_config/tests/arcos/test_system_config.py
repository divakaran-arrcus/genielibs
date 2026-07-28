"""Unit tests for ArcOS System Configuration conf object.

``SystemConfig.DeviceAttributes`` is a plain-attribute (managedattribute)
class, not a Genie ``DeviceFeature`` -- there's no ``add_device_attributes``
wiring or per-device dict. Tests instantiate
``SystemConfig.DeviceAttributes()`` directly, set ``.device`` plus whichever
managedattributes are under test, then call ``build_config(apply=False)`` /
``build_unconfig(apply=False)`` and assert on the rendered CLI text
(``str(result.cli_config)``).
"""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.system_config.arcos.system_config import SystemConfig


class _BaseSystemConfigTest(TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _make(self, **attrs):
        """Create a DeviceAttributes instance bound to self.device."""
        da = SystemConfig.DeviceAttributes()
        da.device = self.device
        for key, value in attrs.items():
            setattr(da, key, value)
        return da


class TestBasicAttributes(_BaseSystemConfigTest):
    """hostname, login_banner, motd_banner, timezone."""

    def test_hostname(self):
        da = self._make(hostname="rtr1")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system hostname rtr1", out)

    def test_login_banner(self):
        da = self._make(login_banner="Authorized use only")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn('system login-banner "Authorized use only"', out)

    def test_motd_banner(self):
        da = self._make(motd_banner="Welcome")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn('system motd-banner "Welcome"', out)

    def test_timezone(self):
        da = self._make(timezone="America/Los_Angeles")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system clock timezone-name America/Los_Angeles", out)

    def test_basic_unconfig(self):
        da = self._make(hostname="rtr1", timezone="America/Los_Angeles")
        out = str(da.build_unconfig(apply=False).cli_config)
        self.assertIn("no system hostname rtr1", out)
        self.assertIn("no system clock timezone-name America/Los_Angeles", out)


class TestSshAttributes(_BaseSystemConfigTest):
    """ssh_server_enabled, ssh_permit_root_login, ssh_sftp_enabled."""

    def test_ssh_server_enabled_true(self):
        da = self._make(ssh_server_enabled=True)
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ssh-server enable true", out)

    def test_ssh_server_enabled_false(self):
        da = self._make(ssh_server_enabled=False)
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ssh-server enable false", out)

    def test_ssh_permit_root_login(self):
        da = self._make(ssh_permit_root_login=True)
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ssh-server permit-root-login true", out)

    def test_ssh_sftp_enabled(self):
        da = self._make(ssh_sftp_enabled=False)
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ssh-server sftp enable false", out)

    def test_ssh_unconfig(self):
        da = self._make(ssh_server_enabled=True, ssh_sftp_enabled=True)
        out = str(da.build_unconfig(apply=False).cli_config)
        self.assertIn("no system ssh-server enable true", out)
        self.assertIn("no system ssh-server sftp enable true", out)


class TestNtpAttributes(_BaseSystemConfigTest):
    """ntp_servers, ntp_listen_interface, ntp_network_instance."""

    def test_ntp_server_full(self):
        da = self._make(
            ntp_servers={
                "10.0.0.1": {"iburst": True, "prefer": False, "key_id": 5}
            }
        )
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ntp server 10.0.0.1", out)
        self.assertIn("iburst true", out)
        self.assertIn("prefer false", out)
        self.assertIn("key-id 5", out)

    def test_ntp_server_multiple_sorted(self):
        da = self._make(
            ntp_servers={
                "10.0.0.2": {"iburst": True},
                "10.0.0.1": {"prefer": True},
            }
        )
        out = str(da.build_config(apply=False).cli_config)
        # servers are rendered in sorted address order
        self.assertLess(
            out.index("10.0.0.1"), out.index("10.0.0.2")
        )

    def test_ntp_server_no_sub_attrs(self):
        """Server dict with no iburst/prefer/key_id still emits the block."""
        da = self._make(ntp_servers={"10.0.0.5": {}})
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ntp server 10.0.0.5", out)

    def test_ntp_listen_interface(self):
        da = self._make(ntp_listen_interface="loopback0")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ntp listen-interface loopback0", out)

    def test_ntp_network_instance(self):
        da = self._make(ntp_network_instance="mgmt")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system ntp network-instance mgmt", out)


class TestDnsAttributes(_BaseSystemConfigTest):
    """dns_servers, dns_search_domains."""

    def test_dns_servers(self):
        da = self._make(dns_servers=["8.8.8.8", "1.1.1.1"])
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system dns server 8.8.8.8", out)
        self.assertIn("system dns server 1.1.1.1", out)

    def test_dns_search_domains_list(self):
        da = self._make(dns_search_domains=["example.com", "corp.local"])
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system dns search example.com", out)
        self.assertIn("system dns search corp.local", out)

    def test_dns_unconfig(self):
        da = self._make(dns_servers=["8.8.8.8"])
        out = str(da.build_unconfig(apply=False).cli_config)
        self.assertIn("no system dns server 8.8.8.8", out)


class TestLoggingAndGrpcAttributes(_BaseSystemConfigTest):
    """logging_format, grpc_server_enabled."""

    def test_logging_format(self):
        da = self._make(logging_format="SYSLOG_RFC_5424")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system logging logging-format SYSLOG_RFC_5424", out)

    def test_grpc_server_enabled(self):
        da = self._make(grpc_server_enabled=True)
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system grpc-server enable true", out)

    def test_grpc_server_disabled(self):
        da = self._make(grpc_server_enabled=False)
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system grpc-server enable false", out)


class TestAaaAttributes(_BaseSystemConfigTest):
    """aaa_server_groups, aaa_auth_method, aaa_auth_fallback_on_reject,
    aaa_remote_user_role, aaa_authz_method, aaa_acct_method."""

    def test_aaa_server_groups_full(self):
        da = self._make(
            aaa_server_groups={
                "TAC1": {
                    "type": "TACACS",
                    "servers": [
                        {"address": "10.0.0.9", "secret_key": "abc"}
                    ],
                }
            }
        )
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system aaa server-group TAC1", out)
        self.assertIn("type TACACS", out)
        self.assertIn("server 10.0.0.9", out)
        self.assertIn("tacacs secret-key abc", out)

    def test_aaa_server_groups_no_servers(self):
        da = self._make(aaa_server_groups={"G1": {"type": "LOCAL"}})
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn("system aaa server-group G1", out)
        self.assertIn("type LOCAL", out)
        self.assertNotIn("server ", out.split("type LOCAL")[-1])

    def test_aaa_server_groups_multiple_sorted(self):
        da = self._make(
            aaa_server_groups={
                "ZGROUP": {"type": "LOCAL"},
                "AGROUP": {"type": "TACACS"},
            }
        )
        out = str(da.build_config(apply=False).cli_config)
        self.assertLess(out.index("AGROUP"), out.index("ZGROUP"))

    def test_aaa_auth_method(self):
        da = self._make(aaa_auth_method=["TACACS_ALL", "LOCAL"])
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "system aaa authentication authentication-method "
            "[ TACACS_ALL LOCAL ]",
            out,
        )

    def test_aaa_auth_fallback_on_reject(self):
        da = self._make(aaa_auth_fallback_on_reject=True)
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "system aaa authentication fallback-on-reject true", out
        )

    def test_aaa_remote_user_role(self):
        da = self._make(aaa_remote_user_role="SYSTEM_ROLE_ADMIN")
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "system aaa authentication remote-user role-override role "
            "SYSTEM_ROLE_ADMIN",
            out,
        )

    def test_aaa_authz_method(self):
        da = self._make(aaa_authz_method=["LOCAL"])
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "system aaa authorization authorization-method [ LOCAL ]", out
        )

    def test_aaa_acct_method(self):
        da = self._make(aaa_acct_method=["TACACS_ALL"])
        out = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "system aaa accounting accounting-method [ TACACS_ALL ]", out
        )

    def test_aaa_unconfig(self):
        da = self._make(aaa_auth_method=["LOCAL"])
        out = str(da.build_unconfig(apply=False).cli_config)
        self.assertIn(
            "no system aaa authentication authentication-method [ LOCAL ]",
            out,
        )


class TestFullAndEmptyConfig(_BaseSystemConfigTest):
    """Whole-object behavior: apply=True dispatch, empty attrs, build_unconfig
    delegation."""

    def test_no_attributes_set_produces_empty_config(self):
        da = self._make()
        result = da.build_config(apply=False)
        self.assertEqual(str(result.cli_config), "")

    def test_apply_true_calls_device_configure(self):
        da = self._make(ssh_server_enabled=True, grpc_server_enabled=False)
        ret = da.build_config(apply=True)
        self.assertIsNone(ret)
        self.device.configure.assert_called_once()
        args, kwargs = self.device.configure.call_args
        self.assertIn("system ssh-server enable true", args[0])
        self.assertIn("system grpc-server enable false", args[0])
        self.assertEqual(kwargs.get("fail_invalid"), True)

    def test_apply_true_with_no_attributes_does_not_call_configure(self):
        da = self._make()
        da.build_config(apply=True)
        self.device.configure.assert_not_called()

    def test_apply_false_returns_cliconfig_with_unconfig_flag(self):
        da = self._make(hostname="rtr1")
        result = da.build_config(apply=False, unconfig=False)
        self.assertFalse(result.cli_config.unconfig)

        result_un = da.build_config(apply=False, unconfig=True)
        self.assertTrue(result_un.cli_config.unconfig)

    def test_build_unconfig_delegates_to_build_config(self):
        da = self._make(hostname="rtr1", ssh_server_enabled=True)
        result = da.build_unconfig(apply=False)
        out = str(result.cli_config)
        self.assertIn("no system hostname rtr1", out)
        self.assertIn("no system ssh-server enable true", out)

    def test_combined_config_all_sections(self):
        """Sanity: build_config renders all sections together in one pass,
        in declaration order (basic -> ssh -> ntp -> dns -> logging -> grpc
        -> aaa)."""
        da = self._make(
            hostname="rtr1",
            ssh_server_enabled=True,
            ntp_listen_interface="loopback0",
            dns_servers=["8.8.8.8"],
            logging_format="SYSLOG_RFC_5424",
            grpc_server_enabled=True,
            aaa_auth_method=["LOCAL"],
        )
        out = str(da.build_config(apply=False).cli_config)
        for expected in (
            "system hostname rtr1",
            "system ssh-server enable true",
            "system ntp listen-interface loopback0",
            "system dns server 8.8.8.8",
            "system logging logging-format SYSLOG_RFC_5424",
            "system grpc-server enable true",
            "system aaa authentication authentication-method [ LOCAL ]",
        ):
            self.assertIn(expected, out)

        # declaration order check
        self.assertLess(out.index("hostname"), out.index("ssh-server"))
        self.assertLess(out.index("ssh-server"), out.index("ntp listen"))
        self.assertLess(out.index("ntp listen"), out.index("dns server"))
        self.assertLess(out.index("dns server"), out.index("logging-format"))
        self.assertLess(out.index("logging-format"), out.index("grpc-server"))
        self.assertLess(
            out.index("grpc-server"), out.index("aaa authentication")
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
