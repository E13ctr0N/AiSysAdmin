import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from agensysadmin.config import ServerConfig
from agensysadmin.ssh_manager import SSHManager, CommandResult


@pytest.fixture
def server_config():
    return ServerConfig(
        name="test",
        host="10.0.0.1",
        port=22,
        user="admin",
        key_path="/keys/test_key",
    )


@pytest.fixture
def password_config():
    return ServerConfig(
        name="test-pw",
        host="10.0.0.2",
        port=22,
        user="admin",
        password="secret",
    )


class TestCommandResult:
    def test_command_result_fields(self):
        result = CommandResult(
            stdout="hello", stderr="", exit_code=0, duration_ms=150
        )
        assert result.stdout == "hello"
        assert result.exit_code == 0
        assert result.duration_ms == 150

    def test_command_result_to_dict(self):
        result = CommandResult(
            stdout="out", stderr="err", exit_code=1, duration_ms=200
        )
        d = result.to_dict()
        assert d == {
            "stdout": "out",
            "stderr": "err",
            "exit_code": 1,
            "duration_ms": 200,
        }


class TestSSHManager:
    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_connect_with_key(self, mock_ssh_class, server_config):
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        manager = SSHManager()
        manager.connect(server_config)

        mock_client.set_missing_host_key_policy.assert_called_once()
        mock_client.connect.assert_called_once_with(
            hostname="10.0.0.1",
            port=22,
            username="admin",
            key_filename="/keys/test_key",
            password=None,
            timeout=10,
        )

    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_connect_with_password(self, mock_ssh_class, password_config):
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        manager = SSHManager()
        manager.connect(password_config)

        mock_client.connect.assert_called_once_with(
            hostname="10.0.0.2",
            port=22,
            username="admin",
            key_filename=None,
            password="secret",
            timeout=10,
        )

    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_execute_returns_command_result(self, mock_ssh_class, server_config):
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"hello world\n"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        manager = SSHManager()
        manager.connect(server_config)
        result = manager.execute(server_config.name, "echo hello world")

        assert isinstance(result, CommandResult)
        assert result.stdout == "hello world\n"
        assert result.exit_code == 0
        assert result.duration_ms >= 0

    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_connection_caching(self, mock_ssh_class, server_config):
        mock_client = MagicMock()
        mock_client.get_transport.return_value = MagicMock(is_active=MagicMock(return_value=True))
        mock_ssh_class.return_value = mock_client

        manager = SSHManager()
        manager.connect(server_config)
        manager.connect(server_config)

        # Should only create one connection
        assert mock_client.connect.call_count == 1

    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_reconnect_on_dead_connection(self, mock_ssh_class, server_config):
        mock_client = MagicMock()
        mock_client.get_transport.return_value = MagicMock(is_active=MagicMock(return_value=False))
        mock_ssh_class.return_value = mock_client

        manager = SSHManager()
        manager.connect(server_config)
        manager.connect(server_config)

        # Dead transport → reconnect
        assert mock_client.connect.call_count == 2

    def test_disconnect(self, server_config):
        manager = SSHManager()
        # disconnect on non-existent connection should not raise
        manager.disconnect(server_config.name)

    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_is_connected(self, mock_ssh_class, server_config):
        mock_client = MagicMock()
        mock_client.get_transport.return_value = MagicMock(is_active=MagicMock(return_value=True))
        mock_ssh_class.return_value = mock_client

        manager = SSHManager()
        assert manager.is_connected(server_config.name) is False
        manager.connect(server_config)
        assert manager.is_connected(server_config.name) is True
