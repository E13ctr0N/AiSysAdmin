# AgenSysAdmin Milestone 3 — Docker Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tools for managing Docker containers, images, and docker-compose on remote servers.

**Architecture:** New `tools/docker.py` module with `*_impl` functions, wired into existing FastMCP server.

**Tech Stack:** Python 3.11+, existing agensysadmin infrastructure

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/agensysadmin/tools/docker.py` | Create | docker_ps_impl, docker_logs_impl, docker_compose_impl, docker_images_impl |
| `tests/test_tools_docker.py` | Create | Tests for all docker tools |
| `src/agensysadmin/server.py` | Modify | Register 4 new MCP tools |
| `tests/test_server_integration.py` | Modify | Update registration check |

---

### Task 1: docker_ps Tool

**Files:**
- Create: `src/agensysadmin/tools/docker.py`
- Create: `tests/test_tools_docker.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_docker.py
import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.docker import docker_ps_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestDockerPs:
    def test_docker_ps_running(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "CONTAINER ID   IMAGE          COMMAND                  CREATED       STATUS       PORTS                 NAMES\n"
                "a1b2c3d4e5f6   nginx:latest   \"/docker-entrypoint.…\"   2 hours ago   Up 2 hours   0.0.0.0:80->80/tcp    web\n"
                "f6e5d4c3b2a1   postgres:15    \"docker-entrypoint.s…\"   3 days ago    Up 3 days    5432/tcp              db\n"
            ),
            stderr="", exit_code=0, duration_ms=100,
        )

        result = docker_ps_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert len(result["containers"]) == 2
        assert result["containers"][0]["names"] == "web"
        assert result["containers"][0]["image"] == "nginx:latest"
        assert result["containers"][1]["names"] == "db"

    def test_docker_ps_all(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "CONTAINER ID   IMAGE          COMMAND   CREATED       STATUS                   PORTS   NAMES\n"
                "a1b2c3d4e5f6   nginx:latest   \"nginx\"   2 hours ago   Up 2 hours               80/tcp  web\n"
                "b2c3d4e5f6a1   redis:7        \"redis\"   1 day ago     Exited (0) 5 hours ago           cache\n"
            ),
            stderr="", exit_code=0, duration_ms=100,
        )

        result = docker_ps_impl(mock_ssh, "prod", all_containers=True)
        assert "docker ps -a" in mock_ssh.execute.call_args.args[1]
        assert len(result["containers"]) == 2

    def test_docker_ps_no_containers(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES\n",
            stderr="", exit_code=0, duration_ms=50,
        )

        result = docker_ps_impl(mock_ssh, "prod")
        assert result["containers"] == []

    def test_docker_not_installed(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="bash: docker: command not found\n",
            exit_code=127, duration_ms=20,
        )

        result = docker_ps_impl(mock_ssh, "prod")
        assert result["success"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_docker.py::TestDockerPs -v`

- [ ] **Step 3: Implement docker_ps_impl**

```python
# src/agensysadmin/tools/docker.py
from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager


def docker_ps_impl(
    ssh: SSHManager,
    server: str,
    all_containers: bool = False,
) -> dict:
    cmd = "docker ps -a" if all_containers else "docker ps"
    cmd += " --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}'"
    result = ssh.execute(server, cmd)

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "containers": [],
        }

    containers = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 5:
            containers.append({
                "id": parts[0],
                "image": parts[1],
                "status": parts[2],
                "ports": parts[3],
                "names": parts[4],
            })

    return {
        "success": True,
        "containers": containers,
    }
```

NOTE: The tests use raw `docker ps` output (table format with headers), but the implementation uses `--format` with tab-separated values. You need to reconcile: either adjust the tests to match `--format` output (no headers, tab-separated: `a1b2c3d4e5f6\tnginx:latest\tUp 2 hours\t0.0.0.0:80->80/tcp\tweb`), or adjust the implementation to parse the table format. The `--format` approach is cleaner and more reliable — **adjust the test mock data to match the `--format` output**.

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/docker.py tests/test_tools_docker.py && git commit -m "feat: add docker_ps tool"
```

---

### Task 2: docker_logs Tool

**Files:**
- Modify: `src/agensysadmin/tools/docker.py`
- Modify: `tests/test_tools_docker.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_tools_docker.py`:

```python
from agensysadmin.tools.docker import docker_ps_impl, docker_logs_impl


class TestDockerLogs:
    def test_docker_logs_default(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="2026-03-31 10:00:00 [info] Starting nginx\n2026-03-31 10:00:01 [info] Ready\n",
            stderr="", exit_code=0, duration_ms=50,
        )

        result = docker_logs_impl(mock_ssh, "prod", container="web")
        assert result["success"] is True
        assert "Starting nginx" in result["logs"]
        assert "docker logs" in mock_ssh.execute.call_args.args[1]
        assert "web" in mock_ssh.execute.call_args.args[1]

    def test_docker_logs_with_tail(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="last line\n", stderr="", exit_code=0, duration_ms=50,
        )

        result = docker_logs_impl(mock_ssh, "prod", container="web", tail=10)
        assert "--tail 10" in mock_ssh.execute.call_args.args[1]

    def test_docker_logs_container_not_found(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="Error: No such container: missing\n",
            exit_code=1, duration_ms=20,
        )

        result = docker_logs_impl(mock_ssh, "prod", container="missing")
        assert result["success"] is False
```

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement docker_logs_impl**

```python
def docker_logs_impl(
    ssh: SSHManager,
    server: str,
    container: str,
    tail: int | None = None,
) -> dict:
    cmd = f"docker logs {container}"
    if tail is not None:
        cmd += f" --tail {tail}"

    result = ssh.execute(server, cmd)

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "logs": result.stdout,
        "stderr": result.stderr,
        "container": container,
        "duration_ms": result.duration_ms,
    }
```

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/docker.py tests/test_tools_docker.py && git commit -m "feat: add docker_logs tool"
```

---

### Task 3: docker_compose Tool

**Files:**
- Modify: `src/agensysadmin/tools/docker.py`
- Modify: `tests/test_tools_docker.py`

- [ ] **Step 1: Write failing tests**

```python
from agensysadmin.tools.docker import docker_ps_impl, docker_logs_impl, docker_compose_impl


class TestDockerCompose:
    def test_compose_up(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Creating network app_default\nCreating app_web_1\nCreating app_db_1\n",
            stderr="", exit_code=0, duration_ms=5000,
        )

        result = docker_compose_impl(mock_ssh, "prod", action="up", path="/opt/app")
        assert result["success"] is True
        cmd = mock_ssh.execute.call_args.args[1]
        assert "docker compose" in cmd
        assert "up -d" in cmd
        assert "-f /opt/app/docker-compose.yml" in cmd or "cd /opt/app" in cmd

    def test_compose_down(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Stopping app_web_1\nRemoving app_web_1\n",
            stderr="", exit_code=0, duration_ms=3000,
        )

        result = docker_compose_impl(mock_ssh, "prod", action="down", path="/opt/app")
        assert result["success"] is True
        assert "down" in mock_ssh.execute.call_args.args[1]

    def test_compose_restart(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Restarting app_web_1\n", stderr="", exit_code=0, duration_ms=2000,
        )

        result = docker_compose_impl(mock_ssh, "prod", action="restart", path="/opt/app")
        assert "restart" in mock_ssh.execute.call_args.args[1]

    def test_compose_ps(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="NAME       IMAGE          SERVICE   CREATED       STATUS       PORTS\napp-web-1  nginx:latest   web       2 hours ago   Up 2 hours   80/tcp\n",
            stderr="", exit_code=0, duration_ms=500,
        )

        result = docker_compose_impl(mock_ssh, "prod", action="ps", path="/opt/app")
        assert result["success"] is True

    def test_compose_invalid_action(self, mock_ssh):
        with pytest.raises(ValueError, match="Invalid action"):
            docker_compose_impl(mock_ssh, "prod", action="destroy", path="/opt/app")

    def test_compose_failure(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="no configuration file provided: not found\n",
            exit_code=1, duration_ms=100,
        )

        result = docker_compose_impl(mock_ssh, "prod", action="up", path="/opt/missing")
        assert result["success"] is False
```

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement docker_compose_impl**

```python
VALID_COMPOSE_ACTIONS = {"up", "down", "restart", "stop", "start", "ps", "logs", "pull", "build"}


def docker_compose_impl(
    ssh: SSHManager,
    server: str,
    action: str,
    path: str,
) -> dict:
    if action not in VALID_COMPOSE_ACTIONS:
        raise ValueError(
            f"Invalid action '{action}'. Must be one of: {sorted(VALID_COMPOSE_ACTIONS)}"
        )

    action_cmd = f"{action} -d" if action == "up" else action
    cmd = f"cd {path} && docker compose {action_cmd}"

    result = ssh.execute(server, cmd, timeout=120)

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "action": action,
        "path": path,
        "duration_ms": result.duration_ms,
    }
```

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/docker.py tests/test_tools_docker.py && git commit -m "feat: add docker_compose tool"
```

---

### Task 4: docker_images + Wire into MCP Server

**Files:**
- Modify: `src/agensysadmin/tools/docker.py`
- Modify: `tests/test_tools_docker.py`
- Modify: `src/agensysadmin/server.py`
- Modify: `tests/test_server_integration.py`

- [ ] **Step 1: Write failing tests for docker_images**

```python
from agensysadmin.tools.docker import docker_ps_impl, docker_logs_impl, docker_compose_impl, docker_images_impl


class TestDockerImages:
    def test_docker_images(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="nginx\tlatest\ta1b2c3d4e5f6\t2 weeks ago\t142MB\npostgres\t15\tf6e5d4c3b2a1\t3 weeks ago\t379MB\n",
            stderr="", exit_code=0, duration_ms=80,
        )

        result = docker_images_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert len(result["images"]) == 2
        assert result["images"][0]["repository"] == "nginx"
        assert result["images"][0]["tag"] == "latest"
        assert result["images"][0]["size"] == "142MB"

    def test_docker_images_empty(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=50,
        )

        result = docker_images_impl(mock_ssh, "prod")
        assert result["images"] == []
```

- [ ] **Step 2: Implement docker_images_impl**

```python
def docker_images_impl(ssh: SSHManager, server: str) -> dict:
    result = ssh.execute(
        server, "docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}'"
    )

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "images": [],
        }

    images = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 5:
            images.append({
                "repository": parts[0],
                "tag": parts[1],
                "id": parts[2],
                "created": parts[3],
                "size": parts[4],
            })

    return {"success": True, "images": images}
```

- [ ] **Step 3: Wire all 4 docker tools into server.py**

Add import:
```python
from agensysadmin.tools.docker import (
    docker_compose_impl,
    docker_images_impl,
    docker_logs_impl,
    docker_ps_impl,
)
```

Add 4 tool functions:
```python
@mcp.tool()
def docker_ps(server: str, all_containers: bool = False) -> dict:
    """List Docker containers. Set all_containers=True to include stopped containers."""
    _ensure_connected(server)
    return docker_ps_impl(_ssh, server, all_containers=all_containers)


@mcp.tool()
def docker_logs(server: str, container: str, tail: int | None = None) -> dict:
    """Get logs from a Docker container. Use tail to limit number of lines."""
    _ensure_connected(server)
    return docker_logs_impl(_ssh, server, container=container, tail=tail)


@mcp.tool()
def docker_compose(server: str, action: str, path: str) -> dict:
    """Run docker compose action in a directory. action: 'up', 'down', 'restart', 'stop', 'start', 'ps', 'logs', 'pull', 'build'."""
    _ensure_connected(server)
    return docker_compose_impl(_ssh, server, action=action, path=path)


@mcp.tool()
def docker_images(server: str) -> dict:
    """List Docker images on a server."""
    _ensure_connected(server)
    return docker_images_impl(_ssh, server)
```

- [ ] **Step 4: Update integration test expected set**

Add to the expected set in `test_all_tools_registered`:
```python
        "docker_ps",
        "docker_logs",
        "docker_compose",
        "docker_images",
```

- [ ] **Step 5: Run full test suite**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/ -v`

- [ ] **Step 6: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/docker.py tests/test_tools_docker.py src/agensysadmin/server.py tests/test_server_integration.py && git commit -m "feat: add Docker tools — docker_ps, docker_logs, docker_compose, docker_images"
```
