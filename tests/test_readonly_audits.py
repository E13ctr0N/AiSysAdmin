from unittest.mock import MagicMock

from agensysadmin.ssh_manager import CommandResult
from agensysadmin.tools.security import check_updates_impl, _audit_updates, full_security_audit_impl, _audit_ssh, security_audit_impl


def test_update_check_reads_cache_without_sudo_or_refresh():
    ssh = MagicMock()
    ssh.execute.return_value = CommandResult("Listing...\n", "", 0, 0)
    result = check_updates_impl(ssh, "test")
    ssh.execute.assert_called_once_with("test", "apt list --upgradable 2>/dev/null")
    assert result["metadata_source"] == "existing_apt_cache"
    assert result["freshness_verified"] is False


def test_update_audit_failure_is_unknown_not_pass():
    ssh = MagicMock()
    ssh.execute.return_value = CommandResult("", "apt unavailable", 127, 0)
    findings = _audit_updates(ssh, "test")
    for finding in findings:
        if finding["check"] in {"Pending updates", "Security updates"}:
            assert finding["status"] == "UNKNOWN"
    assert all("apt-get update" not in call.args[1] for call in ssh.execute.call_args_list)


def test_full_audit_never_refreshes_package_metadata():
    ssh = MagicMock()
    ssh.execute.return_value = CommandResult("", "", 1, 0)
    full_security_audit_impl(ssh, "test")
    commands = [call.args[1] for call in ssh.execute.call_args_list]
    assert not any("apt-get update" in cmd for cmd in commands)


def test_ssh_audit_uses_effective_connection_settings_including_snippets():
    ssh = MagicMock()
    # The daemon output reflects its Include/Match processing; do not reconstruct
    # defaults by grepping only the top-level configuration file.
    ssh.execute.return_value = CommandResult(
        "permitrootlogin prohibit-password\npasswordauthentication no\n"
        "pubkeyauthentication yes\nport 2222\nmaxauthtries 3\nallowusers operator\n", "", 0, 0)
    findings = _audit_ssh(ssh, "test")
    command = ssh.execute.call_args.args[1]
    assert "sshd -T -C" in command
    assert "SSH_CONNECTION" in command
    assert "user=$(id -un)" in command
    assert "grep" not in command
    assert next(f for f in findings if f["check"] == "Root login")["status"] == "PASS"
    assert next(f for f in findings if f["check"] == "Password authentication")["status"] == "PASS"


def test_failed_or_missing_effective_settings_never_pass():
    for result in (CommandResult("", "sudo denied", 1, 0), CommandResult("", "", 0, 0)):
        ssh = MagicMock()
        ssh.execute.return_value = result
        findings = _audit_ssh(ssh, "test")
        assert not any(f["status"] == "PASS" for f in findings)
        assert any(f["status"] == "UNKNOWN" for f in findings)
        result = security_audit_impl(ssh, "test")
        assert result["success"] is False
        assert result["checks"]["ssh"]["root_login"] == "unknown"


def test_denied_sudo_does_not_become_zero_or_empty_safe_results():
    ssh = MagicMock()
    ssh.execute.side_effect = [
        CommandResult("permitrootlogin no\npasswordauthentication no\n", "", 0, 0),
        CommandResult("present", "", 0, 0),
        CommandResult("", "sudo denied", 1, 0),
        CommandResult("root\n", "", 0, 0),
        CommandResult("", "sudo denied", 1, 0),
    ]
    result = security_audit_impl(ssh, "test")
    assert result["success"] is False
    assert result["checks"]["failed_logins"] == {"count": None, "status": "UNKNOWN"}
    assert result["checks"]["world_writable"] == {"files": None, "status": "UNKNOWN"}
    assert all("|| echo 0" not in call.args[1] for call in ssh.execute.call_args_list)


def test_full_audit_marks_failed_categories_incomplete():
    ssh = MagicMock()
    ssh.execute.return_value = CommandResult("", "permission denied", 1, 0)
    result = full_security_audit_impl(ssh, "test")
    assert result["success"] is False
    assert result["complete"] is False
    for category in result["categories"].values():
        assert category["complete"] is False
        assert category["score"] == 0
        assert all(f["status"] == "UNKNOWN" for f in category["findings"])
    assert any("bash -o pipefail" in call.args[1] for call in ssh.execute.call_args_list)
