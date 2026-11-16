from unittest.mock import MagicMock

import pytest

from agensysadmin.ssh_manager import CommandResult
from agensysadmin.tools.security import _AuditProbe, _effective_ssh_settings
from agensysadmin.tools.security_extended import audit_password_policy, audit_network_details, audit_custom_units, audit_update_details, audit_monitoring


def result(value="", code=0):
    return CommandResult(value, "denied" if code else "", code, 0)


@pytest.mark.parametrize("audit", [audit_password_policy, audit_network_details, audit_custom_units, audit_update_details, audit_monitoring])
def test_extended_probe_failures_are_unknown_not_pass(audit):
    ssh = MagicMock()
    ssh.execute.return_value = result(code=1)
    ssh.execute_privileged.return_value = result(code=1)
    findings = audit(ssh, "test")
    assert any(f["status"] == "UNKNOWN" for f in findings)
    assert not any(f["status"] == "PASS" for f in findings)


def test_sshd_context_is_captured_before_escalation():
    ssh = MagicMock()
    ssh.execute.return_value = result("deploy\n192.0.2.10 41000 2001:db8::20 2222\n")
    ssh.execute_privileged.return_value = result("permitrootlogin no\npasswordauthentication no\n")
    settings = _effective_ssh_settings(ssh, "test")
    assert settings["passwordauthentication"] == "no"
    command = ssh.execute_privileged.call_args.args[1]
    assert "user=deploy" in command
    assert "addr=192.0.2.10" in command
    assert "laddr=2001:db8::20" in command
    assert "sudo" not in command


@pytest.mark.parametrize("context", ["root\nbad-host 400 192.0.2.1 22\n", "bad;user\n192.0.2.1 400 192.0.2.2 22\n", "root\n192.0.2.1 400 192.0.2.2 -1\n"])
def test_invalid_context_never_reaches_privileged_shell(context):
    ssh = MagicMock()
    ssh.execute.return_value = result(context)
    assert _effective_ssh_settings(ssh, "test") == {}
    ssh.execute_privileged.assert_not_called()


def test_profile_probes_share_readonly_facts_without_repeating_commands():
    ssh = MagicMock()
    ssh.execute.return_value = result("inventory")
    cache = {}
    first, second = _AuditProbe(ssh, cache), _AuditProbe(ssh, cache)
    assert first.execute("test", "ss -H -lntu").stdout == "inventory"
    assert second.execute("test", "ss -H -lntu").stdout == "inventory"
    ssh.execute.assert_called_once()


def test_probe_timeout_is_unknown_and_failure_is_cached():
    ssh = MagicMock()
    ssh.execute.side_effect = TimeoutError("potentially sensitive output")
    probe = _AuditProbe(ssh)
    first = probe.execute("test", "inventory")
    second = probe.execute("test", "inventory")
    assert first.exit_code == 255
    assert "sensitive" not in first.stderr
    assert second is first
    assert probe.failed is True
    ssh.execute.assert_called_once()


def test_fail2ban_remote_jail_name_is_validated_before_interpolation():
    ssh = MagicMock()
    ssh.execute.side_effect = [result(""), result("/usr/bin/fail2ban-client")]
    ssh.execute_privileged.return_value = result("Jail list: ssh;do-not-execute\n")
    findings = audit_network_details(ssh, "test")
    assert next(f for f in findings if f["check"] == "Fail2ban jails")["status"] == "UNKNOWN"
    ssh.execute_privileged.assert_called_once_with("test", "fail2ban-client status", timeout=None)
