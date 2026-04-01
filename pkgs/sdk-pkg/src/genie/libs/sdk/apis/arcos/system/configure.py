"""ArcOS system-level configure APIs.

High-level helpers for operations that span connection management and
device-level configuration.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def load_config_file(
    device,
    local_path: str,
    remote_dir: str = "/tmp",
    timeout: int = 120,
) -> None:
    """Copy a local config file to the device and load-override + commit it.

    This function performs three steps:

    1. **File transfer** — Copies ``local_path`` to ``remote_dir/<filename>``
       on the device using SFTP (paramiko), opening a dedicated SSH connection
       independent of the existing Unicon session.

    2. **Load override** — Calls ``device.load(remote_path, timeout=timeout)``
       which sends ``load override <remote_path>`` in config mode and waits
       through the spinner for the completion message.

    3. **Commit** — The ``device.load()`` service automatically commits and
       returns the device to exec mode.

    Args:
        device: pyATS device object (must be connected).
        local_path (str): Absolute or relative path to the config file on the
            local machine.
        remote_dir (str): Directory on the device where the file is staged.
            Defaults to ``'/tmp'``.
        timeout (int): Maximum seconds to wait for each of the load and commit
            stages.  Defaults to 120.

    Returns:
        None

    Raises:
        FileNotFoundError: If ``local_path`` does not exist on the local machine.
        SubCommandFailure: If the SFTP transfer fails, or if ``load override``
            or ``commit`` fail on the device.

    Example:
        >>> load_config_file(device, '/home/user/router.cfg')
        >>> load_config_file(device, '/home/user/router.cfg', timeout=150)
    """
    local = Path(local_path).expanduser().resolve()
    if not local.exists():
        raise FileNotFoundError(f"Config file not found: {local_path}")

    filename = local.name
    remote_path = f"{remote_dir}/{filename}"

    # ── Step 1: Transfer file to device via SFTP ──────────────────────────
    _sftp_put(device, local, remote_path)

    # ── Step 2 & 3: load override + commit (handled by device.load) ───────
    log.info(
        "load_config_file: calling device.load('%s', timeout=%d) on %s",
        remote_path,
        timeout,
        device.name,
    )
    try:
        device.load(remote_path, timeout=timeout)
    except SubCommandFailure:
        raise
    except Exception as exc:
        raise SubCommandFailure(
            f"device.load failed on {device.name}: {exc}"
        ) from exc

    log.info("load_config_file: completed successfully on %s", device.name)


def rollback_configuration(
    device,
    sno: int = 0,
    timeout: int = 120,
) -> None:
    """Rollback device configuration to a previous commit point.

    Uses the confd ``rollback configuration <sno>`` command followed by
    ``commit``.  The underlying Unicon Rollback service handles spinner
    characters and Proceed? prompts.

    Args:
        device: pyATS device object (must be connected).
        sno (int): Rollback sequence number.  ``0`` means the most recent
            commit (i.e. undo the last change).  Defaults to 0.
        timeout (int): Maximum seconds to wait for commit.  Defaults to 120.

    Returns:
        None

    Raises:
        SubCommandFailure: If rollback or commit fails on the device.

    Example:
        >>> rollback_configuration(device)            # rollback most recent commit
        >>> rollback_configuration(device, sno=3)     # rollback to commit #3
        >>> rollback_configuration(device, timeout=180)
    """
    log.info(
        "rollback_configuration: calling device.rollback(sno=%d, timeout=%d) on %s",
        sno,
        timeout,
        device.name,
    )
    try:
        device.rollback(sno=sno, timeout=timeout)
    except SubCommandFailure:
        raise
    except Exception as exc:
        raise SubCommandFailure(
            f"device.rollback failed on {device.name}: {exc}"
        ) from exc

    log.info("rollback_configuration: completed successfully on %s", device.name)


# ── System Settings APIs ─────────────────────────────────────────────────


def configure_system_hostname(device, hostname):
    """Set system hostname.

    Args:
        device (obj): Device object.
        hostname (str): Hostname.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_system_hostname(device, 'LeafX')
    """
    log.info(f"Setting hostname to {hostname} on {device.name}")
    try:
        device.configure([f'system hostname {hostname}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not set hostname on {device.name}. Error:\n{e}"
        )


def unconfigure_system_hostname(device):
    """Remove system hostname.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Removing hostname from {device.name}")
    try:
        device.configure(['no system hostname', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove hostname from {device.name}. Error:\n{e}"
        )


def configure_system_ntp_server(device, address, iburst=None, prefer=None):
    """Configure an NTP server.

    Args:
        device (obj): Device object.
        address (str): NTP server address.
        iburst (bool, optional): Enable iburst.
        prefer (bool, optional): Prefer this server.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_system_ntp_server(device, '10.1.1.1', iburst=True, prefer=True)
    """
    log.info(f"Configuring NTP server {address} on {device.name}")
    config = [f'system ntp server {address}']
    if iburst is not None:
        config.append(f'iburst {"true" if iburst else "false"}')
    if prefer is not None:
        config.append(f'prefer {"true" if prefer else "false"}')
    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure NTP server {address} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_system_ntp_server(device, address):
    """Remove an NTP server.

    Args:
        device (obj): Device object.
        address (str): NTP server address.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Removing NTP server {address} from {device.name}")
    try:
        device.configure([f'no system ntp server {address}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove NTP server {address} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_system_dns_server(device, address):
    """Configure a DNS server.

    Args:
        device (obj): Device object.
        address (str): DNS server address.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.

    Example:
        >>> configure_system_dns_server(device, '8.8.8.8')
    """
    log.info(f"Configuring DNS server {address} on {device.name}")
    try:
        device.configure([f'system dns server {address}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure DNS server {address} on "
            f"{device.name}. Error:\n{e}"
        )


def unconfigure_system_dns_server(device, address):
    """Remove a DNS server.

    Args:
        device (obj): Device object.
        address (str): DNS server address.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Removing DNS server {address} from {device.name}")
    try:
        device.configure([f'no system dns server {address}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove DNS server {address} from "
            f"{device.name}. Error:\n{e}"
        )


def configure_system_logging_format(device, fmt):
    """Set system logging format.

    Args:
        device (obj): Device object.
        fmt (str): Logging format (e.g., 'SYSLOG_RFC_5424').

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Setting logging format to {fmt} on {device.name}")
    try:
        device.configure([f'system logging logging-format {fmt}', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not set logging format on {device.name}. Error:\n{e}"
        )


def unconfigure_system_logging_format(device):
    """Remove system logging format.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Removing logging format from {device.name}")
    try:
        device.configure(['no system logging logging-format', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove logging format from {device.name}. "
            f"Error:\n{e}"
        )


def configure_system_login_banner(device, banner):
    """Set login banner.

    Args:
        device (obj): Device object.
        banner (str): Banner text.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Setting login banner on {device.name}")
    try:
        device.configure([f'system login-banner "{banner}"', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not set login banner on {device.name}. Error:\n{e}"
        )


def unconfigure_system_login_banner(device):
    """Remove login banner.

    Args:
        device (obj): Device object.

    Returns:
        None

    Raises:
        SubCommandFailure: If configuration fails.
    """
    log.info(f"Removing login banner from {device.name}")
    try:
        device.configure(['no system login-banner', '!'])
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove login banner from {device.name}. "
            f"Error:\n{e}"
        )


# ── Private helpers ────────────────────────────────────────────────────────────


def _sftp_put(device, local_path: Path, remote_path: str) -> None:
    """Transfer ``local_path`` to ``remote_path`` on the device via SFTP.

    Opens a dedicated paramiko SSH connection using the device's testbed
    credentials (``device.credentials.default``).  This is independent of the
    existing Unicon CLI session so it does not disturb device state.

    Args:
        device: pyATS device object.
        local_path (Path): Resolved local file path.
        remote_path (str): Destination path on the device (e.g. ``'/tmp/r.cfg'``).

    Raises:
        SubCommandFailure: On any SSH or SFTP error.
    """
    import paramiko  # pyATS dependency — always available in the venv

    conn_info = device.connections.cli
    host = str(conn_info.ip)
    port = int(getattr(conn_info, "port", 22))
    username = str(device.credentials.default.username)
    # SecretString.plaintext gives the actual value; str() returns masked ****
    _pw = device.credentials.default.password
    password = _pw.plaintext if hasattr(_pw, "plaintext") else str(_pw)

    log.info(
        "load_config_file: SFTP %s → %s:%s%s",
        local_path.name,
        device.name,
        host,
        remote_path,
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
        # Try SFTP first; fall back to SSH exec + cat if subsystem unavailable
        try:
            with client.open_sftp() as sftp:
                sftp.put(str(local_path), remote_path)
            log.info("load_config_file: SFTP transfer complete → %s", remote_path)
        except Exception as sftp_exc:
            log.debug(
                "load_config_file: SFTP unavailable (%s), falling back to SSH exec",
                sftp_exc,
            )
            _ssh_exec_put(client, local_path, remote_path)
            log.info("load_config_file: SSH exec transfer complete → %s", remote_path)
    except SubCommandFailure:
        raise
    except Exception as exc:
        raise SubCommandFailure(
            f"SFTP transfer of {local_path.name} to {device.name}:{remote_path} failed: {exc}"
        ) from exc
    finally:
        client.close()


def _ssh_exec_put(client, local_path: Path, remote_path: str) -> None:
    """Transfer a file over an open paramiko SSH connection using exec_command.

    Uses ``cat > remote_path`` via SSH exec channel — works when the SFTP
    subsystem is not available on the device.

    Args:
        client: Open paramiko.SSHClient.
        local_path (Path): Local file to transfer.
        remote_path (str): Destination path on the device.

    Raises:
        SubCommandFailure: If the transfer fails.
    """
    content = local_path.read_bytes()
    stdin, stdout, stderr = client.exec_command(f"cat > {remote_path}")
    stdin.write(content)
    stdin.channel.shutdown_write()

    exit_code = stdout.channel.recv_exit_status()
    err_output = stderr.read().decode(errors="replace").strip()

    if exit_code != 0:
        raise SubCommandFailure(
            f"SSH exec transfer to {remote_path} failed (exit {exit_code}): {err_output}"
        )
