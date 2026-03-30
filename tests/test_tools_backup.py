import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.backup import create_backup_impl, list_backups_impl, check_cron_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestCreateBackup:
    def test_backup_directory(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=5000),
            CommandResult(stdout="-rw-r--r-- 1 root root 15M Mar 31 12:00 /backups/etc-20260331-120000.tar.gz\n", stderr="", exit_code=0, duration_ms=20),
        ]
        result = create_backup_impl(mock_ssh, "prod", source="/etc", dest_dir="/backups")
        assert result["success"] is True
        tar_cmd = mock_ssh.execute.call_args_list[1].args[1]
        assert "tar" in tar_cmd
        assert "/etc" in tar_cmd
        assert "/backups" in tar_cmd

    def test_backup_failure(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="tar: /nonexistent: Cannot stat\n", exit_code=2, duration_ms=100),
        ]
        result = create_backup_impl(mock_ssh, "prod", source="/nonexistent", dest_dir="/backups")
        assert result["success"] is False

    def test_backup_custom_name(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="-rw-r--r-- 1 root root 5M Mar 31 12:00 /backups/mybackup.tar.gz\n", stderr="", exit_code=0, duration_ms=20),
        ]
        result = create_backup_impl(mock_ssh, "prod", source="/var/www", dest_dir="/backups", name="mybackup")
        tar_cmd = mock_ssh.execute.call_args_list[1].args[1]
        assert "mybackup.tar.gz" in tar_cmd


class TestListBackups:
    def test_list_backups(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "-rw-r--r-- 1 root root  15M Mar 30 10:00 /backups/etc-20260330-100000.tar.gz\n"
                "-rw-r--r-- 1 root root 120M Mar 31 02:00 /backups/www-20260331-020000.tar.gz\n"
                "-rw-r--r-- 1 root root 500M Mar 31 12:00 /backups/db-20260331-120000.tar.gz\n"
            ),
            stderr="", exit_code=0, duration_ms=50,
        )
        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result["success"] is True
        assert len(result["backups"]) == 3
        assert result["backups"][0]["name"] == "etc-20260330-100000.tar.gz"
        assert result["backups"][0]["size"] == "15M"

    def test_list_backups_empty(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=30,
        )
        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result["backups"] == []

    def test_list_backups_dir_not_found(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="ls: cannot access '/backups': No such file or directory\n",
            exit_code=2, duration_ms=20,
        )
        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result["success"] is False


class TestCheckCron:
    def test_check_cron_with_jobs(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(
                stdout="0 2 * * * /usr/local/bin/backup.sh\n30 3 * * 0 /usr/local/bin/weekly-cleanup.sh\n",
                stderr="", exit_code=0, duration_ms=20,
            ),
            CommandResult(
                stdout="/etc/cron.d/certbot:\n0 */12 * * * root test -x /usr/bin/certbot && certbot -q renew\n",
                stderr="", exit_code=0, duration_ms=30,
            ),
        ]
        result = check_cron_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert len(result["user_cron"]) == 2
        assert result["user_cron"][0]["schedule"] == "0 2 * * *"
        assert result["user_cron"][0]["command"] == "/usr/local/bin/backup.sh"
        assert "certbot" in result["system_cron"]

    def test_check_cron_empty(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="no crontab for root\n", exit_code=1, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
        ]
        result = check_cron_impl(mock_ssh, "prod")
        assert result["user_cron"] == []

    def test_check_cron_specific_user(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="*/5 * * * * /app/healthcheck.sh\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
        ]
        result = check_cron_impl(mock_ssh, "prod", user="www-data")
        cmd = mock_ssh.execute.call_args_list[0].args[1]
        assert "www-data" in cmd
