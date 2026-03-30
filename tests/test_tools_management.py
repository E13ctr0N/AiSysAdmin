import pytest
from unittest.mock import MagicMock, call
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.management import install_package_impl, manage_service_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestInstallPackage:
    def test_install_single_package(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="Setting up htop (3.2.1-1) ...\n", stderr="", exit_code=0, duration_ms=5000),
        ]

        result = install_package_impl(mock_ssh, "prod", packages=["htop"])
        assert result["success"] is True
        assert result["exit_code"] == 0
        calls = mock_ssh.execute.call_args_list
        assert "apt-get update" in calls[0].args[1]
        assert "apt-get install -y htop" in calls[1].args[1]

    def test_install_multiple_packages(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=5000),
        ]

        result = install_package_impl(mock_ssh, "prod", packages=["nginx", "curl", "htop"])
        calls = mock_ssh.execute.call_args_list
        assert "apt-get install -y nginx curl htop" in calls[1].args[1]

    def test_install_failure(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="", stderr="E: Unable to locate package fakepkg\n", exit_code=100, duration_ms=2000),
        ]

        result = install_package_impl(mock_ssh, "prod", packages=["fakepkg"])
        assert result["success"] is False
        assert result["exit_code"] == 100
        assert "Unable to locate" in result["stderr"]

    def test_install_without_update(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Setting up htop\n", stderr="", exit_code=0, duration_ms=5000
        )

        result = install_package_impl(mock_ssh, "prod", packages=["htop"], update=False)
        assert mock_ssh.execute.call_count == 1
        assert "install" in mock_ssh.execute.call_args.args[1]


class TestManageService:
    def test_start_service(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=500
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="start")
        assert result["success"] is True
        assert "systemctl start nginx" in mock_ssh.execute.call_args.args[1]

    def test_stop_service(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=500
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="stop")
        assert "systemctl stop nginx" in mock_ssh.execute.call_args.args[1]

    def test_restart_service(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=800
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="restart")
        assert result["success"] is True
        assert "systemctl restart nginx" in mock_ssh.execute.call_args.args[1]

    def test_enable_service(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Created symlink\n", stderr="", exit_code=0, duration_ms=300
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="enable")
        assert "systemctl enable nginx" in mock_ssh.execute.call_args.args[1]

    def test_disable_service(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Removed symlink\n", stderr="", exit_code=0, duration_ms=300
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="disable")
        assert "systemctl disable nginx" in mock_ssh.execute.call_args.args[1]

    def test_invalid_action(self, mock_ssh):
        with pytest.raises(ValueError, match="Invalid action"):
            manage_service_impl(mock_ssh, "prod", service="nginx", action="destroy")

    def test_service_action_failure(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="Failed to start nginx.service: Unit not found.\n",
            exit_code=5, duration_ms=200
        )
        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="start")
        assert result["success"] is False
        assert result["exit_code"] == 5
