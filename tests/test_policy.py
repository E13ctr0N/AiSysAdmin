"""Exercise MCP entry points: denied operations must never open an SSH connection."""
import asyncio
from unittest.mock import MagicMock

import pytest

from agensysadmin import server
from agensysadmin.config import ServerConfig


@pytest.fixture
def policy_server(monkeypatch):
    ssh = MagicMock()
    monkeypatch.setattr(server, "_ssh", ssh)
    config = ServerConfig("test", "example.invalid", "operator")
    monkeypatch.setattr(server, "_servers", {"test": config})
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
    monkeypatch.setattr(server, "_servers", {"test": ServerConfig(
        "test", "example.invalid", "operator", allow_mutations=True)})
    with pytest.raises(PermissionError):
        server.execute_command("test", "cat /etc/os-release")
    policy_server.connect.assert_not_called()


def test_explicit_operator_opt_in_allows_shell(policy_server, monkeypatch):
    monkeypatch.setattr(server, "_servers", {"test": ServerConfig(
        "test", "example.invalid", "operator", allow_mutations=True,
        allow_arbitrary_commands=True)})
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
