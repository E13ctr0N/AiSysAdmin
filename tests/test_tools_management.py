import pytest
from unittest.mock import MagicMock, call
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.management import install_package_impl, manage_service_impl, edit_config_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestInstallPackage:
    def test_install_single_package(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="Setting up htop (3.2.1-1) ...\n", stderr="", exit_code=0, duration_ms=5000),
        ]

        result = install_package_impl(mock_ssh, "prod", packages=["htop"])
        assert result["success"] is True
        assert result["exit_code"] == 0
        calls = mock_ssh.execute_privileged.call_args_list
        assert "apt-get update" in calls[0].args[1]
        assert "apt-get install -y -- htop" in calls[1].args[1]

    def test_install_multiple_packages(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=5000),
        ]

        result = install_package_impl(mock_ssh, "prod", packages=["nginx", "curl", "htop"])
        calls = mock_ssh.execute_privileged.call_args_list
        assert "apt-get install -y -- nginx curl htop" in calls[1].args[1]

    def test_install_failure(self, mock_ssh):
        mock_ssh.execute_privileged.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="", stderr="E: Unable to locate package fakepkg\n", exit_code=100, duration_ms=2000),
        ]

        result = install_package_impl(mock_ssh, "prod", packages=["fakepkg"])
        assert result["success"] is False
        assert result["exit_code"] == 100
        assert "Unable to locate" in result["stderr"]

    def test_install_without_update(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="Setting up htop\n", stderr="", exit_code=0, duration_ms=5000
        )

        result = install_package_impl(mock_ssh, "prod", packages=["htop"], update=False)
        assert mock_ssh.execute_privileged.call_count == 1
        assert "install" in mock_ssh.execute_privileged.call_args.args[1]

    @pytest.mark.parametrize("package", ["-oDebug::pkgProblemResolver=yes", "curl;id", "$(id)"])
    def test_rejects_package_injection(self, mock_ssh, package):
        with pytest.raises(ValueError, match="package name"):
            install_package_impl(mock_ssh, "prod", packages=[package])
        mock_ssh.execute_privileged.assert_not_called()

    def test_update_failure_does_not_install(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(stdout="", stderr="network down", exit_code=100, duration_ms=10)
        result = install_package_impl(mock_ssh, "prod", packages=["htop"])
        assert result["success"] is False
        assert mock_ssh.execute_privileged.call_count == 1


class TestManageService:
    def test_start_service(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=500
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="start")
        assert result["success"] is True
        assert "systemctl --no-pager start -- nginx" in mock_ssh.execute_privileged.call_args.args[1]

    def test_stop_service(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=500
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="stop")
        assert "systemctl --no-pager stop -- nginx" in mock_ssh.execute_privileged.call_args.args[1]

    def test_restart_service(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=800
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="restart")
        assert result["success"] is True
        assert "systemctl --no-pager restart -- nginx" in mock_ssh.execute_privileged.call_args.args[1]

    def test_enable_service(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="Created symlink\n", stderr="", exit_code=0, duration_ms=300
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="enable")
        assert "systemctl --no-pager enable -- nginx" in mock_ssh.execute_privileged.call_args.args[1]

    def test_disable_service(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="Removed symlink\n", stderr="", exit_code=0, duration_ms=300
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="disable")
        assert "systemctl --no-pager disable -- nginx" in mock_ssh.execute_privileged.call_args.args[1]

    def test_invalid_action(self, mock_ssh):
        with pytest.raises(ValueError, match="Invalid action"):
            manage_service_impl(mock_ssh, "prod", service="nginx", action="destroy")

    def test_service_action_failure(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="Failed to start nginx.service: Unit not found.\n",
            exit_code=5, duration_ms=200
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="start")
        assert result["success"] is False
        assert result["exit_code"] == 5

    def test_rejects_service_injection(self, mock_ssh):
        with pytest.raises(ValueError, match="service name"):
            manage_service_impl(mock_ssh, "prod", service="nginx;id", action="restart")
        mock_ssh.execute_privileged.assert_not_called()


class TestEditConfig:
    def test_read_config(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="server {\n    listen 80;\n    server_name example.com;\n}\n",
            stderr="", exit_code=0, duration_ms=20
        )
        result = edit_config_impl(mock_ssh, "prod", path="/etc/nginx/nginx.conf")
        assert result["content"] == "server {\n    listen 80;\n    server_name example.com;\n}\n"
        assert "cat" in mock_ssh.execute_privileged.call_args.args[1]

    def test_write_config(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(stdout="", stderr="", exit_code=0, duration_ms=30)
        new_content = "server {\n    listen 443;\n}\n"
        result = edit_config_impl(mock_ssh, "prod", path="/etc/nginx/nginx.conf", content=new_content)
        assert result["success"] is True
        command = mock_ssh.execute_privileged.call_args.args[1]
        assert "agensysadmin-backup.XXXXXX" in command
        assert "cat -- \"$target\" > \"$backup\"" in command
        assert " 1" in command

    def test_write_creates_backup(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(stdout="", stderr="", exit_code=0, duration_ms=30)
        edit_config_impl(mock_ssh, "prod", path="/etc/nginx/nginx.conf", content="new content")
        backup_call = mock_ssh.execute_privileged.call_args.args[1]
        assert "mktemp" in backup_call
        assert "config target does not exist; disable backup to create it" in backup_call

    def test_write_no_backup(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=30
        )
        edit_config_impl(mock_ssh, "prod", path="/etc/nginx/nginx.conf", content="new content", backup=False)
        assert mock_ssh.execute_privileged.call_count == 1

    def test_read_nonexistent_file(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="cat: /etc/missing.conf: No such file or directory\n",
            exit_code=1, duration_ms=10
        )
        result = edit_config_impl(mock_ssh, "prod", path="/etc/missing.conf")
        assert result["success"] is False
        assert result["exit_code"] == 1

    def test_read_refuses_symlink_target(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout="", stderr="refusing to read symbolic-link config target\n", exit_code=64, duration_ms=1
        )
        result = edit_config_impl(mock_ssh, "prod", path="/etc/app.conf")
        assert result["success"] is False
        command = mock_ssh.execute_privileged.call_args.args[1]
        assert "refusing to read symbolic-link config target" in command
        assert "cat -- \"$target\"" in command

    def test_write_quotes_path_and_preserves_exact_multiline_content(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1)
        content = "first line\nquote: ' and $HOME\n"
        edit_config_impl(mock_ssh, "prod", path="/etc/my config.conf", content=content)
        call = mock_ssh.execute_privileged.call_args
        command = call.args[1]
        assert content not in command
        assert "$HOME" not in command
        assert "'/etc/my config.conf'" in command
        assert "sudo" not in command
        assert "mktemp" in command
        assert "trap" in command
        assert "mv -T" in command
        assert "refusing to replace symbolic-link config target" in command
        assert "--preserve=all" in command
        assert call.kwargs["input_data"] == content.encode("utf-8")

    def test_reports_unique_backup_path_even_when_write_fails_after_backup(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(
            stdout=(
                "backup_path=/etc/.app.conf.agensysadmin-backup.abcdef\n"
                "backup_metadata_path=/etc/.app.conf.agensysadmin-backup-meta.abcdef\n"
            ),
            stderr="write failed", exit_code=1, duration_ms=1,
        )
        result = edit_config_impl(mock_ssh, "prod", path="/etc/app.conf", content="new")
        assert result["success"] is False
        assert result["backup_created"] is True
        assert result["backup_path"] == "/etc/.app.conf.agensysadmin-backup.abcdef"
        assert result["backup_metadata_path"] == "/etc/.app.conf.agensysadmin-backup-meta.abcdef"

    def test_write_allows_missing_target_when_backup_is_disabled(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1)
        result = edit_config_impl(mock_ssh, "prod", path="/etc/new.conf", content="new", backup=False)
        assert result["success"] is True
        call = mock_ssh.execute_privileged.call_args
        assert call.kwargs["input_data"] == b"new"
        assert "cp --attributes-only" in call.args[1]

    def test_atomic_script_refuses_symlink_target(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(stdout="", stderr="refusing to replace symbolic-link config target\n", exit_code=64, duration_ms=1)
        result = edit_config_impl(mock_ssh, "prod", path="/etc/app.conf", content="new", backup=False)
        assert result["success"] is False
        assert result["backup_created"] is False
        assert result["backup_path"] is None

    @pytest.mark.parametrize("path", ["relative/file", "/etc/evil\nfile", "/etc/evil\x00file"])
    def test_rejects_unsafe_config_path(self, mock_ssh, path):
        with pytest.raises(ValueError):
            edit_config_impl(mock_ssh, "prod", path=path)
        mock_ssh.execute_privileged.assert_not_called()

    def test_backup_failure_does_not_write_config(self, mock_ssh):
        mock_ssh.execute_privileged.return_value = CommandResult(stdout="", stderr="copy failed", exit_code=1, duration_ms=2)
        result = edit_config_impl(mock_ssh, "prod", path="/etc/app.conf", content="new")
        assert result["success"] is False
        assert result["backup_created"] is False
        assert mock_ssh.execute_privileged.call_count == 1

    @pytest.mark.parametrize("content", ["bad\x00content", "x" * (256 * 1024 + 1)], ids=["nul", "oversized"])
    def test_invalid_content_does_not_create_backup(self, mock_ssh, content):
        with pytest.raises(ValueError):
            edit_config_impl(mock_ssh, "prod", path="/etc/app.conf", content=content)
        mock_ssh.execute_privileged.assert_not_called()
