import pytest
import paramiko
from collections import deque
from dataclasses import replace
from unittest.mock import MagicMock, patch, AsyncMock
from agensysadmin.config import ServerConfig
from agensysadmin.ssh_manager import SSHManager, CommandResult


@pytest.fixture
def server_config():
    return ServerConfig(
        name="test",
        host="192.0.2.11",
        port=22,
        user="admin",
        key_path="/keys/test_key",
    )


@pytest.fixture
def password_config():
    return ServerConfig(
        name="test-pw",
        host="192.0.2.12",
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
            hostname="192.0.2.11",
            port=22,
            username="admin",
            key_filename="/keys/test_key",
            password=None,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            channel_timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )

    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_connect_with_password(self, mock_ssh_class, password_config):
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        manager = SSHManager()
        manager.connect(password_config)

        mock_client.connect.assert_called_once_with(
            hostname="192.0.2.12",
            port=22,
            username="admin",
            key_filename=None,
            password="secret",
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            channel_timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )

    @patch("agensysadmin.ssh_manager.paramiko.SSHClient")
    def test_execute_returns_command_result(self, mock_ssh_class, server_config):
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"hello world\n"
        mock_stdout.channel = FakeChannel([b"hello world\n"])
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


class FakeChannel:
    """Small deterministic channel that requires output draining before exit status."""
    def __init__(self, stdout=(), stderr=(), finished=True):
        self.output = deque(stdout)
        self.errors = deque(stderr)
        self.finished = finished
        self.closed = False

    def recv_ready(self):
        return bool(self.output)

    def recv(self, _size):
        return self.output.popleft()

    def recv_stderr_ready(self):
        return bool(self.errors)

    def recv_stderr(self, _size):
        return self.errors.popleft()

    def exit_status_ready(self):
        return self.finished

    def recv_exit_status(self):
        assert not self.output and not self.errors, "Exit status requested before draining output"
        return 0

    def close(self):
        self.closed = True


@pytest.fixture
def connected_manager(server_config):
    client = MagicMock()
    manager = SSHManager()
    manager._connections[server_config.name] = client
    return manager, client


def command_streams(client, channel):
    stdin, stdout, stderr = MagicMock(), MagicMock(), MagicMock()
    stdout.channel = channel
    client.exec_command.return_value = stdin, stdout, stderr
    return stdin, stdout, stderr


def test_verifies_host_keys_and_disables_implicit_auth(server_config):
    with patch("agensysadmin.ssh_manager.paramiko.SSHClient") as cls:
        client = cls.return_value
        SSHManager().connect(server_config)
        client.load_system_host_keys.assert_called_once_with()
        policy = client.set_missing_host_key_policy.call_args.args[0]
        assert isinstance(policy, paramiko.RejectPolicy)
        with pytest.raises(paramiko.SSHException):
            policy.missing_host_key(client, "unknown.invalid", paramiko.RSAKey.generate(1024))


def test_custom_trust_file_is_exclusive(server_config):
    with patch("agensysadmin.ssh_manager.paramiko.SSHClient") as cls:
        SSHManager().connect(replace(server_config, known_hosts_path="trusted_hosts"))
        cls.return_value.load_host_keys.assert_called_once_with("trusted_hosts")
        cls.return_value.load_system_host_keys.assert_not_called()


@pytest.mark.parametrize("error", [paramiko.SSHException("unknown host"), paramiko.AuthenticationException("denied")])
def test_failed_connection_is_closed_and_not_cached(server_config, error):
    with patch("agensysadmin.ssh_manager.paramiko.SSHClient") as cls:
        cls.return_value.connect.side_effect = error
        manager = SSHManager()
        with pytest.raises(type(error)):
            manager.connect(server_config)
        cls.return_value.close.assert_called_once()
        assert not manager._connections


def test_changed_configuration_reconnects(server_config):
    with patch("agensysadmin.ssh_manager.paramiko.SSHClient") as cls:
        manager = SSHManager()
        manager.connect(server_config)
        manager.connect(replace(server_config, host="new.invalid"))
        assert cls.return_value.connect.call_count == 2
        cls.return_value.close.assert_called_once()


def test_drains_both_streams_and_replaces_invalid_utf8(connected_manager):
    manager, client = connected_manager
    channel = FakeChannel([b"hello", b"\xff"], [b"warning", b"!"])
    streams = command_streams(client, channel)
    result = manager.execute("test", "diagnostic")
    assert result.stdout == "hello\ufffd"
    assert result.stderr == "warning!"
    assert channel.closed
    for stream in streams:
        stream.close.assert_called_once()


def test_output_limit_closes_channel(connected_manager):
    manager, client = connected_manager
    manager.max_output_bytes = 4
    channel = FakeChannel([b"123"], [b"45"])
    command_streams(client, channel)
    with pytest.raises(ValueError, match="output exceeded"):
        manager.execute("test", "verbose")
    assert channel.closed


def test_stalled_command_has_deadline(connected_manager, monkeypatch):
    manager, client = connected_manager
    channel = FakeChannel(finished=False)
    command_streams(client, channel)
    clock = iter([0, 2])
    monkeypatch.setattr("agensysadmin.ssh_manager.time.monotonic", lambda: next(clock))
    with pytest.raises(TimeoutError, match="completion is unknown"):
        manager.execute("test", "stalled", timeout=1)
    assert channel.closed


@pytest.mark.parametrize("timeout", [0, -1, 301, True, float("nan"), float("inf")])
def test_invalid_timeout_rejected_before_execution(connected_manager, timeout):
    manager, client = connected_manager
    with pytest.raises(ValueError, match="timeout"):
        manager.execute("test", "uname", timeout=timeout)
    client.exec_command.assert_not_called()


def test_secret_input_is_sent_over_stdin_only(connected_manager):
    manager, client = connected_manager
    channel = FakeChannel()
    stdin, _, _ = command_streams(client, channel)
    manager.execute("test", "write-config", input_data=b"API_TOKEN=secret\n")
    assert client.exec_command.call_args.args[0] == "write-config"
    stdin.write.assert_called_once_with(b"API_TOKEN=secret\n")
    stdin.flush.assert_called_once()
    stdin.close.assert_called_once()


def test_failed_stdin_write_closes_channel(connected_manager):
    manager, client = connected_manager
    channel = FakeChannel()
    stdin, _, _ = command_streams(client, channel)
    stdin.write.side_effect = OSError("channel closed")
    with pytest.raises(OSError):
        manager.execute("test", "write-config", input_data=b"test")
    assert channel.closed
    stdin.close.assert_called_once()


@pytest.mark.parametrize("data", ["not-bytes", b"a" * (256 * 1024 + 1)], ids=["non-bytes", "oversized"])
def test_invalid_input_rejected_before_execution(connected_manager, data):
    manager, client = connected_manager
    with pytest.raises(ValueError, match="input_data"):
        manager.execute("test", "write-config", input_data=data)
    client.exec_command.assert_not_called()
