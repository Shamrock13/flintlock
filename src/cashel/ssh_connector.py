"""Live SSH connector — pull running configs from network devices."""

from __future__ import annotations

import os
import time
import uuid
import tempfile

try:
    import paramiko  # type: ignore[import-untyped]

    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

RECV_TIMEOUT = 30  # seconds to wait for device output
RECV_CHUNK = 65536


def _require_paramiko():
    if not PARAMIKO_AVAILABLE:
        raise RuntimeError(
            "Live SSH connection requires the 'paramiko' library. "
            "Install it with: pip install paramiko"
        )


def _read_until_idle(channel, timeout=RECV_TIMEOUT, idle_secs=1.5):
    """Read from channel until no data arrives for idle_secs, or timeout expires."""
    output = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(RECV_CHUNK)
            if not chunk:
                break
            output += chunk
        else:
            time.sleep(0.3)
            # If no data for idle_secs consecutively, assume done
            if not channel.recv_ready():
                time.sleep(idle_secs)
                if not channel.recv_ready():
                    break
    return output.decode("utf-8", errors="ignore")


def _make_client(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy: str = "warn",
    pem_key_path: str | None = None,
    pem_passphrase: str | None = None,
):
    """Create and connect a Paramiko SSH client.

    *host_key_policy* controls how unknown host keys are handled:
      ``"strict"``   — RejectPolicy: refuse connections to hosts not in
                       known_hosts.  Most secure; requires pre-population of
                       ~/.ssh/known_hosts or the system known_hosts file.
      ``"warn"``     — WarningPolicy: log a warning and continue.  Balances
                       usability with visibility (default, replaces old insecure
                       AutoAddPolicy).
      ``"auto_add"`` — AutoAddPolicy: silently accept any host key.  Insecure
                       (MITM-vulnerable); available only for isolated lab use.

    *pem_key_path* — path to a PEM private key file (RSA, ECDSA, or Ed25519).
      When provided, key-based authentication is used instead of a password.
    *pem_passphrase* — optional passphrase for an encrypted PEM key.
    """
    client = paramiko.SSHClient()
    # Load system + user known_hosts so strict/warn modes work with pre-approved keys.
    client.load_system_host_keys()
    try:
        client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
    except FileNotFoundError:
        pass
    _policy_map = {
        "strict": paramiko.RejectPolicy,
        "warn": paramiko.WarningPolicy,
        "auto_add": paramiko.AutoAddPolicy,
    }
    policy_cls = _policy_map.get(host_key_policy, paramiko.WarningPolicy)
    client.set_missing_host_key_policy(policy_cls())

    connect_kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }

    if pem_key_path:
        pp = pem_passphrase.encode() if pem_passphrase else None
        pkey = None
        for key_cls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
            try:
                pkey = key_cls.from_private_key_file(pem_key_path, password=pp)
                break
            except (paramiko.SSHException, ValueError):
                continue
        if pkey is None:
            raise ValueError(
                "Could not load PEM key. Ensure the file is a valid RSA, ECDSA, "
                "or Ed25519 private key and that the passphrase is correct."
            )
        connect_kwargs["pkey"] = pkey
    else:
        connect_kwargs["password"] = password

    client.connect(**connect_kwargs)
    return client


# ── Cisco ASA ─────────────────────────────────────────────────────────────────


def _pull_asa(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    _require_paramiko()
    client = _make_client(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )
    try:
        ch = client.invoke_shell()
        time.sleep(1)
        ch.recv(RECV_CHUNK)  # flush banner
        ch.send("terminal pager 0\n")
        time.sleep(0.5)
        ch.recv(RECV_CHUNK)
        ch.send("show running-config\n")
        return _read_until_idle(ch)
    finally:
        client.close()


# ── Fortinet ──────────────────────────────────────────────────────────────────


def _pull_fortinet(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    _require_paramiko()
    client = _make_client(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )
    try:
        ch = client.invoke_shell()
        time.sleep(1)
        ch.recv(RECV_CHUNK)
        ch.send("config global\n")
        time.sleep(0.5)
        ch.recv(RECV_CHUNK)
        ch.send("show full-configuration firewall policy\n")
        return _read_until_idle(ch, timeout=45)
    finally:
        client.close()


# ── Palo Alto Networks ────────────────────────────────────────────────────────


def _pull_paloalto(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    """Pull running config via PA CLI SSH command."""
    _require_paramiko()
    client = _make_client(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )
    try:
        stdin, stdout, stderr = client.exec_command(
            "show config running", timeout=timeout
        )
        # PA can take several seconds to dump the XML
        time.sleep(5)
        out = stdout.read()
        return out.decode("utf-8", errors="ignore")
    finally:
        client.close()


# ── Cisco FTD ─────────────────────────────────────────────────────────────────
# FTD LINA CLI accepts the same commands as ASA for pulling the running config.


def _pull_ftd(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    """Pull FTD running config via LINA CLI (same as ASA)."""
    return _pull_asa(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )


# ── Juniper SRX ───────────────────────────────────────────────────────────────


def _pull_juniper(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    """Pull Juniper SRX config in set-format via Junos CLI SSH shell.

    Disables the screen-length pager first so the full config is returned
    without interactive ``---more---`` prompts.
    """
    _require_paramiko()
    client = _make_client(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )
    try:
        ch = client.invoke_shell()
        time.sleep(2)
        ch.recv(RECV_CHUNK)  # flush banner / login output
        ch.send("set cli screen-length 0\n")
        time.sleep(0.5)
        ch.recv(RECV_CHUNK)
        ch.send("show configuration | display set\n")
        return _read_until_idle(ch, timeout=max(timeout, 90))
    finally:
        client.close()


# ── pfSense ───────────────────────────────────────────────────────────────────


def _pull_pfsense(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    """Pull pfSense config.xml via SSH exec_command.

    Requires the SSH user to have shell access (not just the menu).
    The config file is at /conf/config.xml on all modern pfSense releases.
    """
    _require_paramiko()
    client = _make_client(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )
    try:
        stdin, stdout, stderr = client.exec_command(
            "cat /conf/config.xml", timeout=timeout
        )
        out = stdout.read()
        return out.decode("utf-8", errors="ignore")
    finally:
        client.close()


# ── iptables (Linux) ──────────────────────────────────────────────────────────


def _pull_iptables(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    """Pull iptables rules via SSH using iptables-save.

    Tries the direct command first; falls back to sudo if the account is not root.
    The connecting user must have password-less sudo or run as root.
    """
    _require_paramiko()
    client = _make_client(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )
    try:
        stdin, stdout, stderr = client.exec_command(
            "iptables-save 2>/dev/null || sudo iptables-save 2>/dev/null",
            timeout=timeout,
        )
        out = stdout.read().decode("utf-8", errors="ignore")
        if not out.strip():
            raise RuntimeError(
                "iptables-save returned empty output — check permissions or "
                "verify iptables is installed on the target host"
            )
        return out
    finally:
        client.close()


# ── nftables (Linux) ──────────────────────────────────────────────────────────


def _pull_nftables(
    host,
    port,
    username,
    password,
    timeout,
    host_key_policy="warn",
    pem_key_path=None,
    pem_passphrase=None,
):
    """Pull nftables ruleset via SSH using nft list ruleset.

    Tries the direct command first; falls back to sudo if needed.
    """
    _require_paramiko()
    client = _make_client(
        host,
        port,
        username,
        password,
        timeout,
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )
    try:
        stdin, stdout, stderr = client.exec_command(
            "nft list ruleset 2>/dev/null || sudo nft list ruleset 2>/dev/null",
            timeout=timeout,
        )
        out = stdout.read().decode("utf-8", errors="ignore")
        if not out.strip():
            raise RuntimeError(
                "nft list ruleset returned empty output — check permissions or "
                "verify nftables is installed on the target host"
            )
        return out
    finally:
        client.close()


# ── Main entrypoint ───────────────────────────────────────────────────────────

_SUFFIXES = {
    "asa": ".txt",
    "ftd": ".txt",
    "fortinet": ".txt",
    "iptables": ".txt",
    "juniper": ".txt",
    "nftables": ".txt",
    "paloalto": ".xml",
    "pfsense": ".xml",
}
_PULLERS = {
    "asa": _pull_asa,
    "ftd": _pull_ftd,
    "fortinet": _pull_fortinet,
    "iptables": _pull_iptables,
    "juniper": _pull_juniper,
    "nftables": _pull_nftables,
    "paloalto": _pull_paloalto,
    "pfsense": _pull_pfsense,
}


def connect_and_pull(
    vendor,
    host,
    port,
    username,
    password,
    timeout=30,
    upload_folder=None,
    host_key_policy: str = "warn",
    pem_key_path: str | None = None,
    pem_passphrase: str | None = None,
):
    """
    Connect to a live device, pull its running config, and save to a temp file.

    Returns (temp_file_path, raw_content_str).
    Raises RuntimeError / paramiko exceptions on failure.

    *pem_key_path* — path to a PEM private key file for key-based auth.
    *pem_passphrase* — optional passphrase for the PEM key.
    """
    puller = _PULLERS.get(vendor)
    if puller is None:
        raise ValueError(f"Live SSH not supported for vendor: {vendor}")

    content = puller(
        host,
        int(port),
        username,
        password,
        int(timeout),
        host_key_policy,
        pem_key_path,
        pem_passphrase,
    )

    if not content or len(content.strip()) < 50:
        raise RuntimeError(
            "Device returned an empty or very short response. "
            "Check credentials and that the account has sufficient privileges."
        )

    suffix = _SUFFIXES[vendor]
    folder = upload_folder or tempfile.gettempdir()
    tmp_path = os.path.join(folder, f"cashel_live_{uuid.uuid4().hex}{suffix}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)

    return tmp_path, content
