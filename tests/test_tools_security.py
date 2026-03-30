import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.security import check_updates_impl, firewall_status_impl, security_audit_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestCheckUpdates:
    def test_updates_available(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(
                stdout=(
                    "Listing...\n"
                    "libssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]\n"
                    "openssl/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]\n"
                    "curl/jammy-security 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]\n"
                ),
                stderr="", exit_code=0, duration_ms=2000,
            ),
        ]
        result = check_updates_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert result["update_count"] == 3
        assert len(result["packages"]) == 3
        assert result["packages"][0]["name"] == "libssl3"
        assert "jammy-security" in result["packages"][0]["source"]

    def test_no_updates(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="Listing...\n", stderr="", exit_code=0, duration_ms=1000),
        ]
        result = check_updates_impl(mock_ssh, "prod")
        assert result["update_count"] == 0
        assert result["packages"] == []

    def test_security_updates_only(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(
                stdout=(
                    "Listing...\n"
                    "libssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]\n"
                    "vim/jammy-updates 8.2.3995-1ubuntu2.17 amd64 [upgradable from: 8.2.3995-1ubuntu2.16]\n"
                ),
                stderr="", exit_code=0, duration_ms=2000,
            ),
        ]
        result = check_updates_impl(mock_ssh, "prod", security_only=True)
        assert result["update_count"] == 1
        assert result["packages"][0]["name"] == "libssl3"


class TestFirewallStatus:
    def test_ufw_active(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "Status: active\n"
                "Logging: on (low)\n"
                "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
                "New profiles: skip\n"
                "\n"
                "To                         Action      From\n"
                "--                         ------      ----\n"
                "22/tcp                     ALLOW IN    Anywhere\n"
                "80/tcp                     ALLOW IN    Anywhere\n"
                "443/tcp                    ALLOW IN    Anywhere\n"
            ),
            stderr="", exit_code=0, duration_ms=100,
        )
        result = firewall_status_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert result["active"] is True
        assert result["default_incoming"] == "deny"
        assert result["default_outgoing"] == "allow"
        assert len(result["rules"]) == 3
        assert result["rules"][0]["port"] == "22/tcp"
        assert result["rules"][0]["action"] == "ALLOW IN"

    def test_ufw_inactive(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Status: inactive\n",
            stderr="", exit_code=0, duration_ms=50,
        )
        result = firewall_status_impl(mock_ssh, "prod")
        assert result["active"] is False
        assert result["rules"] == []

    def test_ufw_not_installed(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="ufw: command not found\n",
            exit_code=127, duration_ms=20,
        )
        result = firewall_status_impl(mock_ssh, "prod")
        assert result["success"] is False


class TestSecurityAudit:
    def test_security_audit_runs_all_checks(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="PermitRootLogin no\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="PasswordAuthentication no\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="/etc/apt/apt.conf.d/20auto-upgrades\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="42\n", stderr="", exit_code=0, duration_ms=30),
            CommandResult(stdout="root\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=100),
        ]
        result = security_audit_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert result["checks"]["ssh"]["root_login"] == "no"
        assert result["checks"]["ssh"]["password_auth"] == "no"
        assert result["checks"]["auto_updates"]["enabled"] is True
        assert result["checks"]["failed_logins"]["count"] == 42
        assert result["checks"]["root_users"]["users"] == ["root"]
        assert result["checks"]["world_writable"]["files"] == []

    def test_security_audit_finds_issues(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="PermitRootLogin yes\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="PasswordAuthentication yes\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=20),
            CommandResult(stdout="1523\n", stderr="", exit_code=0, duration_ms=30),
            CommandResult(stdout="root\nbackdoor\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="/etc/shadow\n/etc/passwd\n", stderr="", exit_code=0, duration_ms=100),
        ]
        result = security_audit_impl(mock_ssh, "prod")
        assert result["checks"]["ssh"]["root_login"] == "yes"
        assert result["checks"]["ssh"]["password_auth"] == "yes"
        assert result["checks"]["auto_updates"]["enabled"] is False
        assert result["checks"]["failed_logins"]["count"] == 1523
        assert "backdoor" in result["checks"]["root_users"]["users"]
        assert len(result["checks"]["world_writable"]["files"]) == 2
