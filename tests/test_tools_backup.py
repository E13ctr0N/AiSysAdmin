import pytest
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.backup import (
    _CREATE_ARCHIVE_SCRIPT,
    _VALIDATE_BACKUP_DESTINATION_SCRIPT,
    check_cron_impl,
    create_backup_impl,
    list_backups_impl,
)


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestCreateBackup:
    def test_backup_directory(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=5000),
            CommandResult(stdout="-rw-r--r-- 1 root root 15M Mar 31 12:00 /backups/etc-20260331-120000.tar.gz\n", stderr="", exit_code=0, duration_ms=20),
        ]
        result = create_backup_impl(mock_ssh, "prod", source="/etc", dest_dir="/backups")
        assert result["success"] is True
        tar_cmd = mock_ssh.execute_privileged.call_args_list[2].args[1]
        assert "tar" in tar_cmd
        assert "/etc" in tar_cmd
        assert "/backups" in tar_cmd
        assert "sudo" not in tar_cmd
        assert "umask 077" in tar_cmd
        assert "ln -- \"$tmp\" \"$dest\"" in tar_cmd

    def test_backup_failure(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="tar: /nonexistent: Cannot stat\n", exit_code=2, duration_ms=100),
        ]
        result = create_backup_impl(mock_ssh, "prod", source="/nonexistent", dest_dir="/backups")
        assert result["success"] is False

    def test_backup_custom_name(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="-rw-r--r-- 1 root root 5M Mar 31 12:00 /backups/mybackup.tar.gz\n", stderr="", exit_code=0, duration_ms=20),
        ]
        result = create_backup_impl(mock_ssh, "prod", source="/var/www", dest_dir="/backups", name="mybackup")
        tar_cmd = mock_ssh.execute_privileged.call_args_list[2].args[1]
        assert "mybackup.tar.gz" in tar_cmd


class TestListBackups:
    def test_list_backups(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "15728640\t2026-03-30 10:00\t/backups/etc-20260330-100000.tar.gz\n"
                "125829120\t2026-03-31 02:00\t/backups/www-20260331-020000.tar.gz\n"
                "524288000\t2026-03-31 12:00\t/backups/db-20260331-120000.tar.gz\n"
            ),
            stderr="", exit_code=0, duration_ms=50,
        )
        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result["success"] is True
        assert len(result["backups"]) == 3
        assert result["backups"][0]["name"] == "etc-20260330-100000.tar.gz"
        assert result["backups"][0]["size"] == "15728640"

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

    def test_list_backups_silent_command_failure_is_not_success(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(stdout="", stderr="", exit_code=1, duration_ms=20)
        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result == {"success": False, "exit_code": 1, "stderr": "", "backups": []}


class TestCheckCron:
    def test_check_cron_with_jobs(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
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
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="no crontab for root\n", exit_code=1, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
        ]
        result = check_cron_impl(mock_ssh, "prod")
        assert result["user_cron"] == []

    def test_check_cron_specific_user(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="*/5 * * * * /app/healthcheck.sh\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
        ]
        result = check_cron_impl(mock_ssh, "prod", user="www-data")
        cmd = mock_ssh.execute_privileged.call_args_list[0].args[1]
        assert "www-data" in cmd

    @pytest.mark.parametrize("value", ["relative", "/backups\nnext"])
    def test_backup_paths_must_be_safe_absolute_paths(self, mock_ssh, value):
        with pytest.raises(ValueError):
            create_backup_impl(mock_ssh, "prod", source="/etc", dest_dir=value)
        mock_ssh.execute_privileged.assert_not_called()

    def test_backup_quotes_shell_metacharacters_in_path(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1),
            CommandResult(stdout="", stderr="tar failed", exit_code=1, duration_ms=1),
        ]
        create_backup_impl(mock_ssh, "prod", source="/etc;id", dest_dir="/backups")
        assert "'/etc;id'" in mock_ssh.execute_privileged.call_args_list[2].args[1]

    @pytest.mark.parametrize("name", ["../../etc/passwd", "backup;id", "$(id)"])
    def test_backup_name_must_be_single_safe_component(self, mock_ssh, name):
        with pytest.raises(ValueError, match="backup name"):
            create_backup_impl(mock_ssh, "prod", source="/etc", dest_dir="/backups", name=name)

    def test_mkdir_failure_does_not_run_tar(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1),
            CommandResult(stdout="", stderr="permission denied", exit_code=1, duration_ms=1),
        ]
        result = create_backup_impl(mock_ssh, "prod", source="/etc", dest_dir="/backups")
        assert result["success"] is False
        assert mock_ssh.execute_privileged.call_count == 2

    def test_cron_rejects_user_injection(self, mock_ssh):
        with pytest.raises(ValueError, match="user name"):
            check_cron_impl(mock_ssh, "prod", user="root;id")
        mock_ssh.execute_privileged.assert_not_called()

    def test_nested_destination_is_rejected_before_mkdir(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="nested", exit_code=64, duration_ms=1
        )
        result = create_backup_impl(mock_ssh, "prod", "/srv/app", "/srv/app/backups")
        assert result["success"] is False
        assert mock_ssh.execute_privileged.call_count == 1
        assert "readlink -f" in mock_ssh.execute_privileged.call_args.args[1]

    def test_cron_permission_failure_is_incomplete(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="sudo denied", exit_code=1, duration_ms=1),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1),
        ]
        result = check_cron_impl(mock_ssh, "prod")
        assert result["success"] is False
        assert result["complete"] is False
        assert result["user_cron_status"] == "unknown"


@pytest.fixture
def bash():
    executable = shutil.which("bash")
    if os.name == "nt":
        executable = r"C:\Program Files\Git\bin\bash.exe"
        if not Path(executable).is_file():
            pytest.skip("Git Bash unavailable")
    if not executable:
        pytest.skip("POSIX shell unavailable")
    return executable


def _shell(bash, script, *args, env=None):
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-c", script, "sh", *(Path(arg).as_posix() for arg in args)],
        capture_output=True, timeout=10, env=env,
    )


def test_archive_script_cleans_failed_temp_and_preserves_existing_final(bash, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("data", encoding="utf-8")
    final = tmp_path / "backup.tar.gz"
    final.write_bytes(b"existing")
    result = _shell(bash, _CREATE_ARCHIVE_SCRIPT, source, final)
    assert result.returncode != 0
    assert final.read_bytes() == b"existing"
    assert not list(tmp_path.glob(".backup.tar.gz.agensysadmin.*"))


def test_archive_script_cleans_temp_when_tar_fails(bash, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    final = tmp_path / "backup.tar.gz"
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    (shim_dir / "tar").write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    (shim_dir / "tar").chmod(0o700)
    env = os.environ.copy()
    if os.name == "nt":
        shim_path = subprocess.check_output([bash, "-c", "cygpath -u \"$1\"", "sh", str(shim_dir)], text=True).strip()
    else:
        shim_path = str(shim_dir)
    bash_env = tmp_path / "bash_env"
    bash_env.write_text(f"PATH={shlex.quote(shim_path)}:$PATH\nexport PATH\n", encoding="utf-8")
    env["BASH_ENV"] = str(bash_env)
    result = _shell(bash, _CREATE_ARCHIVE_SCRIPT, source, final, env=env)
    assert result.returncode != 0
    assert not final.exists()
    assert not list(tmp_path.glob(".backup.tar.gz.agensysadmin.*"))


def test_destination_script_rejects_nested_and_symlink_destination(bash, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    nested = source / "backups"
    nested.mkdir()
    assert _shell(bash, _VALIDATE_BACKUP_DESTINATION_SCRIPT, source, nested).returncode == 64
    if os.name == "nt":
        pytest.skip("Git Bash does not resolve Windows test symlinks like remote Linux readlink")
    link = tmp_path / "link"
    link.symlink_to(nested)
    assert _shell(bash, _VALIDATE_BACKUP_DESTINATION_SCRIPT, source, link).returncode == 64
