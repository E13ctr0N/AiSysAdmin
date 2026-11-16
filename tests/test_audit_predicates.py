import os
from pathlib import Path
import shlex
import shutil
import subprocess
from unittest.mock import MagicMock

import pytest

from agensysadmin.ssh_manager import CommandResult
from agensysadmin.tools import security


def test_healthy_negative_categories_remain_complete(monkeypatch):
    ssh = MagicMock()

    def execute(server, command, timeout=None):
        if command == "hostname":
            return CommandResult("host\n", "", 0, 0)
        if command == "hostname -I":
            return CommandResult("192.0.2.1\n", "", 0, 0)
        command = shlex.split(command)[-1]
        if command.startswith("which xinetd"):
            return CommandResult("", "", 1, 0)  # desired absence
        if command.startswith("systemctl list-units"):
            return CommandResult("ssh.service\n", "", 0, 0)
        if command == "cat /etc/hosts 2>/dev/null":
            return CommandResult("127.0.0.1 localhost\n", "", 0, 0)
        return CommandResult("", "", 0, 0)  # find succeeds with no matches

    ssh.execute.side_effect = execute
    for name in ("ssh", "firewall", "users", "network", "filesystem", "updates", "logs", "kernel"):
        monkeypatch.setattr(security, "_audit_" + name,
                            lambda ssh, server: [security._make_finding("pass", "Checked", "PASS", "ok", "")])
    result = security.full_security_audit_impl(ssh, "test")
    assert result["complete"] is True
    assert result["categories"]["services"]["complete"] is True
    assert result["categories"]["malware"]["complete"] is True


@pytest.mark.parametrize("status,output", [(3, "inactive"), (4, "unknown")])
def test_inactive_systemd_service_is_known_not_probe_failure(status, output):
    ssh = MagicMock()
    ssh.execute.return_value = CommandResult(output, "", status, 0)
    probe = security._AuditProbe(ssh)
    probe.execute("test", "systemctl is-active auditd 2>/dev/null")
    assert probe.failed is False


def test_execution_error_is_not_expected_absence():
    ssh = MagicMock()
    ssh.execute.return_value = CommandResult("", "systemctl unavailable", 127, 0)
    probe = security._AuditProbe(ssh)
    probe.execute("test", "systemctl is-active auditd 2>/dev/null")
    assert probe.failed is True


def test_empty_grep_normalization_preserves_upstream_failures():
    bash = shutil.which("bash")
    if os.name == "nt":
        bash = r"C:\Program Files\Git\bin\bash.exe"
    if not bash or not Path(bash).is_file():
        pytest.skip("Bash unavailable")
    grep = security._grep_or_empty("grep nonexistent")
    no_matches = subprocess.run([bash, "-o", "pipefail", "-c", "printf '%s' normal | " + grep], capture_output=True, timeout=5)
    denied = subprocess.run([bash, "-o", "pipefail", "-c", "sh -c 'exit 7' | " + grep], capture_output=True, timeout=5)
    assert no_matches.returncode == 0
    assert denied.returncode == 7
