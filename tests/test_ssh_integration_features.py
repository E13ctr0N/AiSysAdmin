import os
from pathlib import Path
import shlex
import shutil
import subprocess
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from agensysadmin.config import ServerConfig
from agensysadmin.journal import OperationJournal
from agensysadmin.ssh_manager import SSHManager, host_key_sha256, _SUDO_INPUT_SCRIPT
from test_ssh_manager import FakeChannel, command_streams


def manager_for(config, journal=None):
    manager = SSHManager(journal=journal)
    client = MagicMock()
    manager._connections[config.name] = client
    manager._configs[config.name] = config
    streams = command_streams(client, FakeChannel())
    return manager, client, streams


def test_fingerprint_pin_checked_before_authentication():
    actual = paramiko.RSAKey.generate(1024)
    other = paramiko.RSAKey.generate(1024)
    config = ServerConfig("test", "example.invalid", "operator", password="EXAMPLE_SECRET",
                          host_key_sha256="SHA256:" + host_key_sha256(other))
    with patch("agensysadmin.ssh_manager.paramiko.SSHClient") as cls:
        client = cls.return_value
        authenticated = []

        def handshake(**kwargs):
            policy = client.set_missing_host_key_policy.call_args.args[0]
            policy.missing_host_key(client, config.host, actual)
            authenticated.append(True)

        client.connect.side_effect = handshake
        with pytest.raises(paramiko.SSHException, match="fingerprint mismatch"):
            SSHManager().connect(config)
        assert not authenticated
        client.load_system_host_keys.assert_not_called()
        client.load_host_keys.assert_not_called()
        client.close.assert_called_once()


def test_matching_pin_keepalive_and_session_metadata():
    key = paramiko.RSAKey.generate(1024)
    config = ServerConfig("test", "example.invalid", "root", profile="vpn_node",
                          host_key_sha256=host_key_sha256(key))
    with patch("agensysadmin.ssh_manager.paramiko.SSHClient") as cls:
        client = cls.return_value
        client.connect.side_effect = lambda **kwargs: client.set_missing_host_key_policy.call_args.args[0].missing_host_key(client, config.host, key)
        manager = SSHManager()
        manager.connect(config)
        assert manager.connection_info("test")["connected_since"] is not None
        assert manager.server_profile("test") == "vpn_node"
        client.get_transport.return_value.set_keepalive.assert_called_once_with(30)


@pytest.mark.parametrize("user", ["root", "operator"])
def test_root_and_passwordless_sudo_preserve_exact_stdin(user):
    config = ServerConfig("test", "example.invalid", user)
    manager, client, streams = manager_for(config)
    payload = b"CONFIG='exact bytes'\n"
    manager.execute_privileged("test", "cat > /example", input_data=payload)
    command = client.exec_command.call_args.args[0]
    assert command.startswith("sudo -n -- sh -c") if user != "root" else command == "cat > /example"
    streams[0].write.assert_called_once_with(payload)


@pytest.mark.parametrize("password_consumed", [False, True])
def test_password_sudo_framing_cannot_contaminate_payload(password_consumed):
    config = ServerConfig("test", "example.invalid", "operator", sudo_password="FAKE_SUDO_PASSWORD")
    manager, client, streams = manager_for(config)
    payload = b"API_KEY='example only'\nno extra newline"
    manager.execute_privileged("test", "cat", input_data=payload)
    command = client.exec_command.call_args.args[0]
    framed = streams[0].write.call_args.args[0]
    assert config.sudo_password not in command
    assert payload.decode() not in command
    marker = framed.split(b"\n", 2)[1].decode()
    child_input = framed.split(b"\n", 1)[1] if password_consumed else framed
    bash = r"C:\Program Files\Git\bin\bash.exe" if os.name == "nt" else shutil.which("bash")
    if not bash or not Path(bash).is_file():
        pytest.skip("POSIX shell unavailable")
    result = subprocess.run([bash, "-c", _SUDO_INPUT_SCRIPT, "sh", marker, "cat"],
                            input=child_input, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout == payload


def test_ssh_journal_contains_no_command_output_or_sudo_password(tmp_path):
    journal = OperationJournal(tmp_path / "ops.jsonl")
    config = ServerConfig("test", "example.invalid", "root", sudo_password="SECRET_UNUSED")
    manager, client, _ = manager_for(config, journal)
    command_streams(client, FakeChannel([b"Bearer SECRET_OUTPUT"]))
    manager.execute_privileged("test", "printf SECRET_COMMAND")
    text = journal.path.read_text()
    assert "SECRET_" not in text
    assert "Bearer" not in text
    entries = journal.read()
    assert entries[-1]["data"]["privileged"] is True
    assert entries[-1]["data"]["stdout_bytes"] == len(b"Bearer SECRET_OUTPUT")
    assert manager.connection_info("test")["command_count"] == 1


def test_journal_failure_after_execution_is_reported_without_ambiguous_retry():
    journal = MagicMock()
    journal.record.side_effect = [None, OSError("full disk")]
    manager, client, _ = manager_for(ServerConfig("test", "example.invalid", "root"), journal)
    result = manager.execute("test", "true")
    assert result.exit_code == 0
    assert result.to_dict()["journal_warning"] is True
    assert client.exec_command.call_count == 1


def test_new_session_resets_its_command_counter():
    config = ServerConfig("test", "example.invalid", "root")
    with patch("agensysadmin.ssh_manager.paramiko.SSHClient") as cls:
        client = cls.return_value
        command_streams(client, FakeChannel())
        manager = SSHManager()
        manager.connect(config)
        manager.execute("test", "true")
        assert manager.connection_info("test")["command_count"] == 1
        manager.disconnect("test")
        manager.connect(config)
        assert manager.connection_info("test")["command_count"] == 0
