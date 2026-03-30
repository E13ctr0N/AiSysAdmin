import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.general import execute_command_impl


@pytest.fixture
def mock_ssh():
    manager = MagicMock(spec=SSHManager)
    manager.execute.return_value = CommandResult(
        stdout="uid=0(root)\n", stderr="", exit_code=0, duration_ms=45
    )
    return manager


def test_execute_command_returns_result(mock_ssh):
    result = execute_command_impl(mock_ssh, "prod", "whoami")
    assert result["stdout"] == "uid=0(root)\n"
    assert result["exit_code"] == 0
    assert result["duration_ms"] == 45
    mock_ssh.execute.assert_called_once_with("prod", "whoami", timeout=None)


def test_execute_command_with_timeout(mock_ssh):
    execute_command_impl(mock_ssh, "prod", "sleep 5", timeout=60)
    mock_ssh.execute.assert_called_once_with("prod", "sleep 5", timeout=60)


def test_execute_command_failed(mock_ssh):
    mock_ssh.execute.return_value = CommandResult(
        stdout="", stderr="command not found", exit_code=127, duration_ms=10
    )
    result = execute_command_impl(mock_ssh, "prod", "badcmd")
    assert result["exit_code"] == 127
    assert result["stderr"] == "command not found"
