"""Exercise MCP entry points: denied operations must never open an SSH connection."""
import asyncio
from unittest.mock import MagicMock

import pytest

from agensysadmin import server
from agensysadmin.config import ServerConfig


@pytest.fixture
def policy_server(monkeypatch, tmp_path):
    ssh = MagicMock()
    application = server.App(tmp_path)
    application.ssh = ssh
    monkeypatch.setattr(server, "app", application)
    config = ServerConfig("test", "example.invalid", "operator", config_read_paths=("/etc/example",))
    application.servers = {"test": config}
    return ssh


@pytest.mark.parametrize("tool,kwargs", [
    ("execute_command", {"command": "uname -a"}),
    ("install_package", {"packages": ["curl"]}),
    ("manage_service", {"service": "nginx", "action": "restart"}),
    ("edit_config", {"path": "/etc/example", "content": ""}),
    ("create_backup", {"source": "/etc", "dest_dir": "/backups"}),
    *[("docker_compose", {"action": action, "path": "/srv/app"})
      for action in ("up", "down", "restart", "stop", "start", "pull", "build")],
])
def test_mutations_denied_before_ssh(policy_server, tool, kwargs):
    with pytest.raises(PermissionError):
        getattr(server, tool)("test", **kwargs)
    policy_server.connect.assert_not_called()
    policy_server.execute.assert_not_called()


@pytest.mark.parametrize("tool,kwargs", [
    ("manage_service", {"service": "nginx", "action": "status"}),
    ("edit_config", {"path": "/etc/example"}),
    ("docker_compose", {"action": "ps", "path": "/srv/app"}),
    ("docker_compose", {"action": "logs", "path": "/srv/app"}),
    ("check_updates", {}),
    ("security_audit", {}),
    ("full_security_audit", {}),
])
def test_read_tools_remain_available(policy_server, monkeypatch, tool, kwargs):
    impl = MagicMock(return_value={"ok": True})
    monkeypatch.setattr(server, tool + "_impl", impl)
    assert getattr(server, tool)("test", **kwargs) == {"ok": True}
    policy_server.connect.assert_called_once()
    impl.assert_called_once()


def test_arbitrary_shell_requires_separate_permission(policy_server, monkeypatch):
    server.app.servers = {"test": ServerConfig(
        "test", "example.invalid", "operator", allow_mutations=True)}
    with pytest.raises(PermissionError):
        server.execute_command("test", "cat /etc/os-release")
    policy_server.connect.assert_not_called()


def test_explicit_operator_opt_in_allows_shell(policy_server, monkeypatch):
    server.app.servers = {"test": ServerConfig(
        "test", "example.invalid", "operator", allow_mutations=True,
        allow_arbitrary_commands=True)}
    impl = MagicMock(return_value={"exit_code": 0})
    monkeypatch.setattr(server, "execute_command_impl", impl)
    server.execute_command("test", "uname -a")
    impl.assert_called_once()


def test_annotations_are_conservative_for_mixed_tools():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    for name in ("execute_command", "manage_service", "edit_config", "docker_compose", "create_backup", "install_package"):
        assert tools[name].annotations.readOnlyHint is False
        assert tools[name].annotations.destructiveHint is True
    for name in ("check_updates", "full_security_audit", "docker_logs", "list_servers"):
        assert tools[name].annotations.readOnlyHint is True


@pytest.mark.parametrize("path", ["/etc/shadow", "/root/.ssh/id_ed25519", "/etc/app/.env"])
def test_default_diagnostics_cannot_read_arbitrary_privileged_files(policy_server, path):
    with pytest.raises(PermissionError, match="allowlist"):
        server.edit_config("test", path)
    policy_server.connect.assert_not_called()


def test_unrestricted_config_writes_cannot_bypass_shell_permission(policy_server):
    server.app.servers["test"] = ServerConfig("test", "example.invalid", "root",
        allow_mutations=True, allow_arbitrary_commands=False,
        config_write_paths=("/etc/cron.d/example", "/etc/systemd/system/example.service"))
    for path in server.app.servers["test"].config_write_paths:
        with pytest.raises(PermissionError):
            server.edit_config("test", path, content="example", backup=False)
    policy_server.connect.assert_not_called()


def test_compose_code_execution_requires_explicit_shell_permission(policy_server):
    server.app.servers["test"] = ServerConfig("test", "example.invalid", "root", allow_mutations=True)
    with pytest.raises(PermissionError):
        server.docker_compose("test", "up", "/srv/example")
    policy_server.connect.assert_not_called()


def test_exact_allowlist_does_not_allow_traversal_or_neighbor_files(policy_server):
    for path in ("/etc/example.bak", "/etc/../etc/example", "/etc/example/child"):
        with pytest.raises(PermissionError):
            server.edit_config("test", path)
    policy_server.connect.assert_not_called()


def test_denied_file_read_is_journalled_without_the_path(policy_server):
    with pytest.raises(PermissionError):
        server.edit_config("test", "/root/.ssh/id_ed25519")
    entries = server.app.journal.read(event_type="policy_denied")
    assert len(entries) == 1
    assert "/root" not in str(entries)
