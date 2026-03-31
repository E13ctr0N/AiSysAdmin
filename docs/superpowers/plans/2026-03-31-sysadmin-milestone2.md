# AgenSysAdmin Milestone 2 — Installation & Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tools for installing packages, managing systemd services (start/stop/restart/enable/disable), and reading/editing config files on remote servers.

**Architecture:** Three new `*_impl` functions in a new `tools/management.py` module, wired into the existing FastMCP server. Same pattern as Milestone 1 tools.

**Tech Stack:** Python 3.11+, existing agensysadmin infrastructure (SSHManager, FastMCP server)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/agensysadmin/tools/management.py` | Create | install_package_impl, manage_service_impl, edit_config_impl |
| `tests/test_tools_management.py` | Create | Tests for all management tools |
| `src/agensysadmin/server.py` | Modify | Register 3 new MCP tools |
| `tests/test_server_integration.py` | Modify | Add new tools to registration check |

---

### Task 1: install_package Tool

**Files:**
- Create: `src/agensysadmin/tools/management.py`
- Create: `tests/test_tools_management.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_management.py
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
            # apt update
            CommandResult(stdout="Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n", stderr="", exit_code=0, duration_ms=3000),
            # apt install
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_management.py::TestInstallPackage -v`
Expected: FAIL — ModuleNotFoundError

- [ ] **Step 3: Implement install_package_impl**

```python
# src/agensysadmin/tools/management.py
from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager


def install_package_impl(
    ssh: SSHManager,
    server: str,
    packages: list[str],
    update: bool = True,
) -> dict:
    if update:
        ssh.execute(server, "sudo apt-get update -qq", timeout=60)

    pkg_list = " ".join(packages)
    result = ssh.execute(
        server, f"sudo apt-get install -y {pkg_list}", timeout=120
    )

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "packages": packages,
        "duration_ms": result.duration_ms,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_management.py::TestInstallPackage -v`
Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/management.py tests/test_tools_management.py && git commit -m "feat: add install_package tool"
```

---

### Task 2: manage_service Tool

**Files:**
- Modify: `src/agensysadmin/tools/management.py`
- Modify: `tests/test_tools_management.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_tools_management.py`:

```python
from agensysadmin.tools.management import install_package_impl, manage_service_impl


class TestManageService:
    def test_start_service(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=500
        )

        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="start")
        assert result["success"] is True
        mock_ssh.execute.assert_called_once()
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
            stdout="Created symlink /etc/systemd/system/multi-user.target.wants/nginx.service\n",
            stderr="", exit_code=0, duration_ms=300
        )

        result = manage_service_impl(mock_ssh, "prod", service="nginx", action="enable")
        assert "systemctl enable nginx" in mock_ssh.execute.call_args.args[1]

    def test_disable_service(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Removed /etc/systemd/system/multi-user.target.wants/nginx.service.\n",
            stderr="", exit_code=0, duration_ms=300
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_management.py::TestManageService -v`
Expected: FAIL — ImportError

- [ ] **Step 3: Implement manage_service_impl**

Append to `src/agensysadmin/tools/management.py`:

```python
VALID_SERVICE_ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable", "status"}


def manage_service_impl(
    ssh: SSHManager,
    server: str,
    service: str,
    action: str,
) -> dict:
    if action not in VALID_SERVICE_ACTIONS:
        raise ValueError(
            f"Invalid action '{action}'. Must be one of: {sorted(VALID_SERVICE_ACTIONS)}"
        )

    result = ssh.execute(server, f"sudo systemctl {action} {service}")

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "service": service,
        "action": action,
        "duration_ms": result.duration_ms,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_management.py::TestManageService -v`
Expected: all 7 tests PASS

- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/management.py tests/test_tools_management.py && git commit -m "feat: add manage_service tool"
```

---

### Task 3: edit_config Tool

**Files:**
- Modify: `src/agensysadmin/tools/management.py`
- Modify: `tests/test_tools_management.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_tools_management.py`:

```python
from agensysadmin.tools.management import install_package_impl, manage_service_impl, edit_config_impl


class TestEditConfig:
    def test_read_config(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="server {\n    listen 80;\n    server_name example.com;\n}\n",
            stderr="", exit_code=0, duration_ms=20
        )

        result = edit_config_impl(mock_ssh, "prod", path="/etc/nginx/nginx.conf")
        assert result["content"] == "server {\n    listen 80;\n    server_name example.com;\n}\n"
        assert "cat" in mock_ssh.execute.call_args.args[1]

    def test_write_config(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # backup
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            # write
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=30),
        ]

        new_content = "server {\n    listen 443;\n}\n"
        result = edit_config_impl(
            mock_ssh, "prod",
            path="/etc/nginx/nginx.conf",
            content=new_content
        )
        assert result["success"] is True
        calls = mock_ssh.execute.call_args_list
        # First call should be backup
        assert "cp" in calls[0].args[1]
        assert ".bak" in calls[0].args[1]

    def test_write_creates_backup(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=30),
        ]

        edit_config_impl(
            mock_ssh, "prod",
            path="/etc/nginx/nginx.conf",
            content="new content"
        )
        backup_call = mock_ssh.execute.call_args_list[0].args[1]
        assert "cp" in backup_call
        assert "/etc/nginx/nginx.conf" in backup_call

    def test_write_no_backup(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=30
        )

        edit_config_impl(
            mock_ssh, "prod",
            path="/etc/nginx/nginx.conf",
            content="new content",
            backup=False
        )
        # Only one call — no backup
        assert mock_ssh.execute.call_count == 1

    def test_read_nonexistent_file(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="cat: /etc/missing.conf: No such file or directory\n",
            exit_code=1, duration_ms=10
        )

        result = edit_config_impl(mock_ssh, "prod", path="/etc/missing.conf")
        assert result["success"] is False
        assert result["exit_code"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_management.py::TestEditConfig -v`
Expected: FAIL — ImportError

- [ ] **Step 3: Implement edit_config_impl**

Append to `src/agensysadmin/tools/management.py`:

```python
def edit_config_impl(
    ssh: SSHManager,
    server: str,
    path: str,
    content: str | None = None,
    backup: bool = True,
) -> dict:
    if content is None:
        # Read mode
        result = ssh.execute(server, f"sudo cat {path}")
        return {
            "success": result.exit_code == 0,
            "exit_code": result.exit_code,
            "content": result.stdout,
            "stderr": result.stderr,
            "path": path,
        }

    # Write mode
    if backup:
        ssh.execute(server, f"sudo cp {path} {path}.bak")

    escaped_content = content.replace("'", "'\\''")
    result = ssh.execute(
        server, f"echo '{escaped_content}' | sudo tee {path} > /dev/null"
    )

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "path": path,
        "backup_created": backup,
        "duration_ms": result.duration_ms,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_management.py::TestEditConfig -v`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/management.py tests/test_tools_management.py && git commit -m "feat: add edit_config tool"
```

---

### Task 4: Wire New Tools into MCP Server

**Files:**
- Modify: `src/agensysadmin/server.py`
- Modify: `tests/test_server_integration.py`

- [ ] **Step 1: Add imports and tool definitions to server.py**

Add to imports in `src/agensysadmin/server.py`:

```python
from agensysadmin.tools.management import (
    edit_config_impl,
    install_package_impl,
    manage_service_impl,
)
```

Add 3 new tool functions after the existing tools:

```python
@mcp.tool()
def install_package(server: str, packages: list[str], update: bool = True) -> dict:
    """Install packages via apt on a remote server. Set update=False to skip apt update."""
    _ensure_connected(server)
    return install_package_impl(_ssh, server, packages=packages, update=update)


@mcp.tool()
def manage_service(server: str, service: str, action: str) -> dict:
    """Manage a systemd service. action: 'start', 'stop', 'restart', 'reload', 'enable', 'disable', 'status'."""
    _ensure_connected(server)
    return manage_service_impl(_ssh, server, service=service, action=action)


@mcp.tool()
def edit_config(server: str, path: str, content: str | None = None, backup: bool = True) -> dict:
    """Read or write a config file. Omit content to read. Provide content to write (creates .bak backup by default)."""
    _ensure_connected(server)
    return edit_config_impl(_ssh, server, path=path, content=content, backup=backup)
```

- [ ] **Step 2: Update integration test**

In `tests/test_server_integration.py`, update the expected tools set to include the 3 new tools:

```python
    expected = {
        "list_servers",
        "system_info",
        "disk_usage",
        "check_services",
        "check_ports",
        "process_list",
        "execute_command",
        "install_package",
        "manage_service",
        "edit_config",
    }
```

- [ ] **Step 3: Run full test suite**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/ -v`
Expected: all tests PASS (existing 27 + new 16 = ~43 tests)

- [ ] **Step 4: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/server.py tests/test_server_integration.py && git commit -m "feat: wire install_package, manage_service, edit_config into MCP server"
```
