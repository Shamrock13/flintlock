"""Subprocess smoke tests for the Typer CLI entrypoint."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    src = str(ROOT / "src")
    env["PYTHONPATH"] = (
        f"{src}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src
    )
    env.setdefault("NO_COLOR", "1")
    env.setdefault("TERM", "dumb")
    return env


def _installed_cli() -> list[str]:
    executable = shutil.which("cashel")
    if executable:
        return [executable]
    return [sys.executable, "-m", "cashel.main"]


def _module_cli() -> list[str]:
    return [sys.executable, "-m", "cashel.main"]


def _run(
    args: list[str], *, installed: bool = False
) -> subprocess.CompletedProcess[str]:
    cmd = (_installed_cli() if installed else _module_cli()) + args
    return subprocess.run(
        cmd,
        cwd=ROOT,
        env=_env(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def _assert_successful_audit(
    result: subprocess.CompletedProcess[str], *needles: str
) -> None:
    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "Cashel v2.0.0" in output
    assert "--- Audit Summary ---" in output
    assert "Total Issues:" in output
    for needle in needles:
        assert needle in output


def test_installed_cashel_help_smoke():
    result = _run(["--help"], installed=True)
    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "Usage:" in output
    assert "--file" in output
    assert "--vendor" in output


def test_cli_audits_example_cisco_asa_config():
    result = _run(["--file", str(EXAMPLES / "cisco_asa.txt"), "--vendor", "asa"])

    _assert_successful_audit(result, "Overly permissive rule found")


def test_cli_audits_example_fortinet_config():
    result = _run(
        ["--file", str(EXAMPLES / "fortinet_fortigate.txt"), "--vendor", "fortinet"]
    )

    _assert_successful_audit(result, "Overly permissive rule")


def test_cli_audits_example_aws_security_group_config():
    result = _run(
        ["--file", str(EXAMPLES / "aws_security_groups.json"), "--vendor", "aws"]
    )

    _assert_successful_audit(result, "Security Group")


def test_cli_audits_example_iptables_config():
    result = _run(["--file", str(EXAMPLES / "iptables.txt"), "--vendor", "iptables"])

    _assert_successful_audit(result, "iptables filter chain")


def test_cli_invalid_vendor_returns_clean_nonzero_error():
    result = _run(["--file", str(EXAMPLES / "cisco_asa.txt"), "--vendor", "bogus"])
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "Unknown vendor: bogus" in output
    assert "Traceback" not in output


def test_cli_missing_file_returns_clean_nonzero_error(tmp_path):
    missing = tmp_path / "missing.cfg"
    result = _run(["--file", str(missing), "--vendor", "asa"])
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert f"File not found: {missing}" in output
    assert "Traceback" not in output
