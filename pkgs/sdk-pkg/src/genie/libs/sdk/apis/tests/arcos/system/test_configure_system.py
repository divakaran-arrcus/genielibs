#!/usr/bin/env python3
"""Unit tests for arcOS system configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.system.configure builds a top-level `system ...`
(or `alias ...`) CLI config list and calls `device.configure(config)`. Tests
mock `device.configure` and assert on a distinctive substring of the emitted
CLI, plus a SubCommandFailure re-raise test per function.

The module also ships two higher-level helpers, `load_config_file` and
`rollback_configuration`, which drive `device.load()` / `device.rollback()`
(and, for load_config_file, an SFTP file transfer) rather than
`device.configure()`. These do not match the configure_*/unconfigure_*
naming convention and are outside the machine-checked coverage sweep below,
but are still exercised here for completeness since they live in the same
system/configure.py source file.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from genie.libs.sdk.apis.arcos.system import configure as system_configure
from genie.libs.sdk.apis.arcos.system.configure import (
    configure_system_hostname,
    unconfigure_system_hostname,
    configure_system_ntp_server,
    unconfigure_system_ntp_server,
    configure_system_dns_server,
    unconfigure_system_dns_server,
    configure_system_logging_format,
    unconfigure_system_logging_format,
    configure_system_login_banner,
    unconfigure_system_login_banner,
    configure_cli_alias,
    unconfigure_cli_alias,
    load_config_file,
    rollback_configuration,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)
        self.load = Mock(return_value=True)
        self.rollback = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestSystemHostnameApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_system_hostname(self):
        configure_system_hostname(self.d, "LeafX")
        self.assertIn("system hostname LeafX", self.d.cfg())

    def test_unconfigure_system_hostname(self):
        unconfigure_system_hostname(self.d)
        self.assertIn("no system hostname", self.d.cfg())


class TestSystemNtpServerApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_system_ntp_server_basic(self):
        configure_system_ntp_server(self.d, "10.1.1.1")
        c = self.d.cfg()
        self.assertIn("system ntp server 10.1.1.1", c)
        self.assertNotIn("iburst", c)
        self.assertNotIn("prefer", c)

    def test_configure_system_ntp_server_iburst_prefer_true(self):
        configure_system_ntp_server(self.d, "10.1.1.1", iburst=True, prefer=True)
        c = self.d.cfg()
        self.assertIn("system ntp server 10.1.1.1", c)
        self.assertIn("iburst true", c)
        self.assertIn("prefer true", c)

    def test_configure_system_ntp_server_iburst_prefer_false(self):
        configure_system_ntp_server(self.d, "10.1.1.1", iburst=False, prefer=False)
        c = self.d.cfg()
        self.assertIn("iburst false", c)
        self.assertIn("prefer false", c)

    def test_unconfigure_system_ntp_server(self):
        unconfigure_system_ntp_server(self.d, "10.1.1.1")
        self.assertIn("no system ntp server 10.1.1.1", self.d.cfg())


class TestSystemDnsServerApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_system_dns_server(self):
        configure_system_dns_server(self.d, "8.8.8.8")
        self.assertIn("system dns server 8.8.8.8", self.d.cfg())

    def test_unconfigure_system_dns_server(self):
        unconfigure_system_dns_server(self.d, "8.8.8.8")
        self.assertIn("no system dns server 8.8.8.8", self.d.cfg())


class TestSystemLoggingFormatApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_system_logging_format(self):
        configure_system_logging_format(self.d, "SYSLOG_RFC_5424")
        self.assertIn(
            "system logging logging-format SYSLOG_RFC_5424", self.d.cfg()
        )

    def test_unconfigure_system_logging_format(self):
        unconfigure_system_logging_format(self.d)
        self.assertIn("no system logging logging-format", self.d.cfg())


class TestSystemLoginBannerApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_system_login_banner(self):
        configure_system_login_banner(self.d, "Welcome")
        self.assertIn('system login-banner "Welcome"', self.d.cfg())

    def test_unconfigure_system_login_banner(self):
        unconfigure_system_login_banner(self.d)
        self.assertIn("no system login-banner", self.d.cfg())


class TestCliAliasApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_cli_alias(self):
        configure_cli_alias(self.d, "rr", "show ip route")
        self.assertIn('alias rr expansion "show ip route"', self.d.cfg())

    def test_unconfigure_cli_alias(self):
        unconfigure_cli_alias(self.d, "rr")
        self.assertIn("no alias rr", self.d.cfg())


class TestSystemConfigureErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context,
    for every configure_*/unconfigure_* function in system/configure.py."""

    def setUp(self):
        self.d = _CfgDevice()
        from unicon.core.errors import SubCommandFailure
        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))

    def test_configure_system_hostname_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            configure_system_hostname(self.d, "LeafX")

    def test_unconfigure_system_hostname_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            unconfigure_system_hostname(self.d)

    def test_configure_system_ntp_server_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            configure_system_ntp_server(self.d, "10.1.1.1")

    def test_unconfigure_system_ntp_server_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            unconfigure_system_ntp_server(self.d, "10.1.1.1")

    def test_configure_system_dns_server_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            configure_system_dns_server(self.d, "8.8.8.8")

    def test_unconfigure_system_dns_server_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            unconfigure_system_dns_server(self.d, "8.8.8.8")

    def test_configure_system_logging_format_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            configure_system_logging_format(self.d, "SYSLOG_RFC_5424")

    def test_unconfigure_system_logging_format_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            unconfigure_system_logging_format(self.d)

    def test_configure_system_login_banner_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            configure_system_login_banner(self.d, "Welcome")

    def test_unconfigure_system_login_banner_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            unconfigure_system_login_banner(self.d)

    def test_configure_cli_alias_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            configure_cli_alias(self.d, "rr", "show ip route")

    def test_unconfigure_cli_alias_failure(self):
        from unicon.core.errors import SubCommandFailure
        with self.assertRaises(SubCommandFailure):
            unconfigure_cli_alias(self.d, "rr")


class TestLoadConfigFile(unittest.TestCase):
    """load_config_file: not a configure_*/unconfigure_* function (drives
    device.load() + an SFTP transfer instead of device.configure()), but
    covered here for full module coverage."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_local_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_config_file(self.d, "/nonexistent/path/router.cfg")

    @patch.object(system_configure, "_sftp_put")
    def test_success(self, mock_sftp_put):
        with tempfile.NamedTemporaryFile(suffix=".cfg") as tmp:
            tmp.write(b"system hostname LeafX\n")
            tmp.flush()

            load_config_file(self.d, tmp.name, remote_dir="/tmp", timeout=60)

            mock_sftp_put.assert_called_once()
            args = mock_sftp_put.call_args[0]
            self.assertEqual(args[0], self.d)
            self.assertEqual(args[1], Path(tmp.name).expanduser().resolve())
            self.assertEqual(args[2], f"/tmp/{Path(tmp.name).name}")

            self.d.load.assert_called_once_with(
                f"/tmp/{Path(tmp.name).name}", timeout=60
            )

    @patch.object(system_configure, "_sftp_put")
    def test_device_load_subcommandfailure_reraised(self, mock_sftp_put):
        from unicon.core.errors import SubCommandFailure

        self.d.load = Mock(side_effect=SubCommandFailure("load failed"))
        with tempfile.NamedTemporaryFile(suffix=".cfg") as tmp:
            with self.assertRaises(SubCommandFailure):
                load_config_file(self.d, tmp.name)

    @patch.object(system_configure, "_sftp_put")
    def test_device_load_generic_exception_wrapped(self, mock_sftp_put):
        from unicon.core.errors import SubCommandFailure

        self.d.load = Mock(side_effect=RuntimeError("boom"))
        with tempfile.NamedTemporaryFile(suffix=".cfg") as tmp:
            with self.assertRaises(SubCommandFailure):
                load_config_file(self.d, tmp.name)


class TestRollbackConfiguration(unittest.TestCase):
    """rollback_configuration: not a configure_*/unconfigure_* function
    (drives device.rollback() instead of device.configure()), but covered
    here for full module coverage."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_success_default_sno(self):
        rollback_configuration(self.d)
        self.d.rollback.assert_called_once_with(sno=0, timeout=120)

    def test_success_explicit_sno_and_timeout(self):
        rollback_configuration(self.d, sno=3, timeout=180)
        self.d.rollback.assert_called_once_with(sno=3, timeout=180)

    def test_subcommandfailure_reraised(self):
        from unicon.core.errors import SubCommandFailure

        self.d.rollback = Mock(side_effect=SubCommandFailure("rollback failed"))
        with self.assertRaises(SubCommandFailure):
            rollback_configuration(self.d)

    def test_generic_exception_wrapped(self):
        from unicon.core.errors import SubCommandFailure

        self.d.rollback = Mock(side_effect=RuntimeError("boom"))
        with self.assertRaises(SubCommandFailure):
            rollback_configuration(self.d)


class TestSystemConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in system/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(system_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == system_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered system configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nSystem configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
