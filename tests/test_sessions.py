import asyncio
import inspect
from unittest.mock import MagicMock

import pytest

from agensysadmin import server
from agensysadmin.config import ServerConfig


@pytest.fixture
def application(tmp_path, monkeypatch):
    app = server.App(tmp_path)
    app.servers = {"staging": ServerConfig("staging", "example.invalid", "root", role="Test host", profile="docker_host")}
    app.ssh = MagicMock()
    app.ssh.connection_info.return_value = {"connected": True, "connected_since": 123, "command_count": 2}
    monkeypatch.setattr(server, "app", app)
    return app


def test_session_aliases_use_same_implementation(application):
    assert server.connect_server("staging") == server.start_session("staging")
    assert application.ssh.connect.call_count == 2
    server.end_session("staging")
    server.disconnect_server("staging")
    assert application.ssh.disconnect.call_count == 2


def test_mcp_cannot_enroll_or_change_trust(application):
    assert list(inspect.signature(server.connect_server).parameters) == ["server"]
    with pytest.raises(TypeError):
        server.connect_server(host="example.invalid", allow_unknown_host_key=True)
    with pytest.raises(ValueError):
        server.connect_server("not-enrolled")
    application.ssh.connect.assert_not_called()


def test_inventory_preserves_roles_profiles_and_stats(application):
    result = server.list_servers()["staging"]
    assert result["role"] == "Test host"
    assert result["profile"] == "docker_host"
    assert result["command_count"] == 2
    assert result["allow_mutations"] is False


def test_app_constructor_has_no_filesystem_or_configuration_side_effects(tmp_path):
    root = tmp_path / "not-created"
    server.App(root)
    assert not root.exists()


def test_27_tools_remain_available_with_safe_enrollment_replacement():
    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert len(names) == 27
    assert {"start_session", "end_session", "connect_server", "disconnect_server", "operation_journal"} <= names
