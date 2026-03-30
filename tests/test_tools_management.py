import pytest
from unittest.mock import MagicMock, call
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.management import install_package_impl


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
