# AgenSysAdmin Milestone 1 — Core + Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python MCP server that connects to remote Ubuntu/Debian servers via SSH and exposes monitoring tools (system_info, disk_usage, check_services, check_ports, process_list) plus a general-purpose execute_command tool.

**Architecture:** Monolithic MCP server using FastMCP (mcp SDK) with modular internal structure. SSH connections via paramiko with connection pooling. Config from servers.yaml + .env.

**Tech Stack:** Python 3.11+, mcp SDK (FastMCP), paramiko, pyyaml, python-dotenv, pytest

---

## File Structure

| File | Responsibility |
|------|----------------|
| `pyproject.toml` | Project metadata, dependencies |
| `src/agensysadmin/__init__.py` | Package init |
| `src/agensysadmin/config.py` | Load servers.yaml + .env, provide ServerConfig dataclass |
| `src/agensysadmin/ssh_manager.py` | SSH connection pool, execute commands on remote hosts |
| `src/agensysadmin/server.py` | FastMCP server, registers all tools |
| `src/agensysadmin/tools/__init__.py` | Tools package init |
| `src/agensysadmin/tools/monitoring.py` | system_info, disk_usage, check_services, check_ports, process_list |
| `src/agensysadmin/tools/general.py` | execute_command |
| `servers.yaml.example` | Example server config |
| `tests/conftest.py` | Shared fixtures (mock SSH, temp config) |
| `tests/test_config.py` | Config loading tests |
| `tests/test_ssh_manager.py` | SSH manager tests |
| `tests/test_tools_monitoring.py` | Monitoring tools tests |
| `tests/test_tools_general.py` | General tools tests |

---

### Task 1: Project Setup

**Files:**
- Create: `pyproject.toml`
- Create: `src/agensysadmin/__init__.py`
- Create: `servers.yaml.example`
- Create: `.env.example`
- Create: `.gitignore`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "agensysadmin"
version = "0.1.0"
description = "MCP server for remote Linux server administration via SSH"
requires-python = ">=3.11"
dependencies = [
    "mcp>=1.20",
    "paramiko>=3.4",
    "pyyaml>=6.0",
    "python-dotenv>=1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
]

[tool.hatch.build.targets.wheel]
packages = ["src/agensysadmin"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 2: Create package init**

```python
# src/agensysadmin/__init__.py
```

Empty file — just marks the package.

- [ ] **Step 3: Create servers.yaml.example**

```yaml
servers:
  prod:
    host: 192.168.1.10
    port: 22
    user: admin
    key_env: PROD_SSH_KEY_PATH

  staging:
    host: 192.168.1.20
    port: 2222
    user: deploy
    key_env: STAGING_SSH_KEY_PATH
```

- [ ] **Step 4: Create .env.example**

```
PROD_SSH_KEY_PATH=/home/user/.ssh/prod_key
STAGING_SSH_KEY_PATH=/home/user/.ssh/staging_key
# PROD_SSH_PASSWORD=secret
```

- [ ] **Step 5: Create .gitignore**

```gitignore
__pycache__/
*.pyc
.env
servers.yaml
*.egg-info/
dist/
.venv/
.pytest_cache/
```

- [ ] **Step 6: Create tools package init**

```python
# src/agensysadmin/tools/__init__.py
```

- [ ] **Step 7: Install dependencies**

Run: `cd D:/AI/AgenSysAdmin && python -m venv .venv && .venv/Scripts/activate && pip install -e ".[dev]"`
Expected: successful install, no errors.

- [ ] **Step 8: Commit**

```bash
git init
git add pyproject.toml src/agensysadmin/__init__.py src/agensysadmin/tools/__init__.py servers.yaml.example .env.example .gitignore
git commit -m "chore: initialize project with dependencies"
```

---

### Task 2: Config Module

**Files:**
- Create: `src/agensysadmin/config.py`
- Create: `tests/conftest.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing tests for config**

```python
# tests/test_config.py
import os
import pytest
from pathlib import Path
from agensysadmin.config import ServerConfig, load_config


@pytest.fixture
def config_dir(tmp_path):
    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text("""
servers:
  prod:
    host: 10.0.0.1
    port: 22
    user: admin
    key_env: PROD_SSH_KEY_PATH
  staging:
    host: 10.0.0.2
    port: 2222
    user: deploy
    password_env: STAGING_SSH_PASSWORD
""")
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PROD_SSH_KEY_PATH=/keys/prod_key\nSTAGING_SSH_PASSWORD=secret123\n"
    )
    return tmp_path


def test_load_config_returns_dict_of_server_configs(config_dir):
    servers = load_config(config_dir)
    assert "prod" in servers
    assert "staging" in servers
    assert isinstance(servers["prod"], ServerConfig)


def test_server_config_fields(config_dir):
    servers = load_config(config_dir)
    prod = servers["prod"]
    assert prod.host == "10.0.0.1"
    assert prod.port == 22
    assert prod.user == "admin"
    assert prod.key_path == "/keys/prod_key"
    assert prod.password is None


def test_server_config_password_auth(config_dir):
    servers = load_config(config_dir)
    staging = servers["staging"]
    assert staging.host == "10.0.0.2"
    assert staging.port == 2222
    assert staging.password == "secret123"
    assert staging.key_path is None


def test_load_config_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path)


def test_server_config_default_port(tmp_path):
    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text("""
servers:
  minimal:
    host: 10.0.0.3
    user: root
""")
    (tmp_path / ".env").write_text("")
    servers = load_config(tmp_path)
    assert servers["minimal"].port == 22
```

- [ ] **Step 2: Create conftest.py**

```python
# tests/conftest.py
```

Empty for now — fixtures live in test files or will be added as needed.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agensysadmin.config'`

- [ ] **Step 4: Implement config module**

```python
# src/agensysadmin/config.py
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    user: str
    port: int = 22
    key_path: str | None = None
    password: str | None = None


def load_config(base_path: Path | str) -> dict[str, ServerConfig]:
    base_path = Path(base_path)
    servers_file = base_path / "servers.yaml"
    env_file = base_path / ".env"

    if not servers_file.exists():
        raise FileNotFoundError(f"servers.yaml not found in {base_path}")

    if env_file.exists():
        load_dotenv(env_file, override=True)

    with open(servers_file) as f:
        data = yaml.safe_load(f)

    servers: dict[str, ServerConfig] = {}
    for name, cfg in data.get("servers", {}).items():
        key_path = None
        password = None

        key_env = cfg.get("key_env")
        if key_env:
            key_path = os.environ.get(key_env)

        password_env = cfg.get("password_env")
        if password_env:
            password = os.environ.get(password_env)

        servers[name] = ServerConfig(
            name=name,
            host=cfg["host"],
            port=cfg.get("port", 22),
            user=cfg["user"],
            key_path=key_path,
            password=password,
        )

    return servers
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_config.py -v`
Expected: all 5 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agensysadmin/config.py tests/conftest.py tests/test_config.py
git commit -m "feat: add config module — load servers.yaml + .env"
```

---

### Task 3: SSH Manager

**Files:**
- Create: `src/agensysadmin/ssh_manager.py`
- Create: `tests/test_ssh_manager.py`

- [ ] **Step 1: Write failing tests for SSH manager**

```python
# tests/test_ssh_manager.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_ssh_manager.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agensysadmin.ssh_manager'`

- [ ] **Step 3: Implement SSH manager**

```python
# src/agensysadmin/ssh_manager.py
from __future__ import annotations

import time
from dataclasses import dataclass

import paramiko

from agensysadmin.config import ServerConfig


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int

    def to_dict(self) -> dict:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }


class SSHManager:
    def __init__(self, connect_timeout: int = 10, command_timeout: int = 30):
        self._connections: dict[str, paramiko.SSHClient] = {}
        self._configs: dict[str, ServerConfig] = {}
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout

    def connect(self, config: ServerConfig) -> None:
        if config.name in self._connections:
            client = self._connections[config.name]
            transport = client.get_transport()
            if transport and transport.is_active():
                return
            # Dead connection — clean up and reconnect
            client.close()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=config.host,
            port=config.port,
            username=config.user,
            key_filename=config.key_path,
            password=config.password,
            timeout=self.connect_timeout,
        )
        self._connections[config.name] = client
        self._configs[config.name] = config

    def disconnect(self, server_name: str) -> None:
        client = self._connections.pop(server_name, None)
        if client:
            client.close()
        self._configs.pop(server_name, None)

    def disconnect_all(self) -> None:
        for name in list(self._connections):
            self.disconnect(name)

    def is_connected(self, server_name: str) -> bool:
        client = self._connections.get(server_name)
        if not client:
            return False
        transport = client.get_transport()
        return transport is not None and transport.is_active()

    def execute(
        self, server_name: str, command: str, timeout: int | None = None
    ) -> CommandResult:
        client = self._connections.get(server_name)
        if not client:
            raise ConnectionError(f"Not connected to server '{server_name}'")

        timeout = timeout or self.command_timeout
        start = time.monotonic()
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        elapsed_ms = int((time.monotonic() - start) * 1000)

        return CommandResult(
            stdout=stdout.read().decode(),
            stderr=stderr.read().decode(),
            exit_code=exit_code,
            duration_ms=elapsed_ms,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_ssh_manager.py -v`
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/ssh_manager.py tests/test_ssh_manager.py
git commit -m "feat: add SSH manager with connection pooling"
```

---

### Task 4: General Tool — execute_command

**Files:**
- Create: `src/agensysadmin/tools/general.py`
- Create: `tests/test_tools_general.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_general.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_general.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement general tools**

```python
# src/agensysadmin/tools/general.py
from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager


def execute_command_impl(
    ssh: SSHManager,
    server: str,
    command: str,
    timeout: int | None = None,
) -> dict:
    result = ssh.execute(server, command, timeout=timeout)
    return result.to_dict()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_general.py -v`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/general.py tests/test_tools_general.py
git commit -m "feat: add execute_command tool"
```

---

### Task 5: Monitoring Tools

**Files:**
- Create: `src/agensysadmin/tools/monitoring.py`
- Create: `tests/test_tools_monitoring.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_monitoring.py
import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.monitoring import (
    system_info_impl,
    disk_usage_impl,
    check_services_impl,
    check_ports_impl,
    process_list_impl,
)


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestSystemInfo:
    def test_system_info_parses_output(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # uname -a
            CommandResult(
                stdout="Linux prod 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
            # uptime -p
            CommandResult(
                stdout="up 14 days, 3 hours, 22 minutes\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
            # free -b  (bytes for precision)
            CommandResult(
                stdout=(
                    "              total        used        free      shared  buff/cache   available\n"
                    "Mem:     8368730112  2147483648  4194304000   134217728  2027942464  5905580032\n"
                    "Swap:    2147483648           0  2147483648\n"
                ),
                stderr="", exit_code=0, duration_ms=10,
            ),
            # nproc
            CommandResult(
                stdout="4\n", stderr="", exit_code=0, duration_ms=10,
            ),
            # cat /proc/loadavg
            CommandResult(
                stdout="0.52 0.38 0.29 1/234 12345\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
        ]

        result = system_info_impl(mock_ssh, "prod")
        assert "Linux" in result["uname"]
        assert "up 14 days" in result["uptime"]
        assert result["cpu_cores"] == 4
        assert result["load_average"] == "0.52 0.38 0.29"
        assert "total" in result["memory"]
        assert "total" in result["swap"]


class TestDiskUsage:
    def test_disk_usage_parses_df(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        50G   20G   28G  42% /\n"
                "/dev/sdb1       100G   60G   35G  63% /data\n"
            ),
            stderr="", exit_code=0, duration_ms=15,
        )

        result = disk_usage_impl(mock_ssh, "prod")
        assert len(result["filesystems"]) == 2
        assert result["filesystems"][0]["mounted_on"] == "/"
        assert result["filesystems"][0]["use_percent"] == "42%"


class TestCheckServices:
    def test_check_services_with_list(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "nginx.service - A high performance web server\n"
                "   Loaded: loaded\n"
                "   Active: active (running) since Mon 2026-03-30 10:00:00 UTC\n"
            ),
            stderr="", exit_code=0, duration_ms=20,
        )

        result = check_services_impl(mock_ssh, "prod", services=["nginx"])
        assert "nginx" in result["services"]
        assert result["services"]["nginx"]["active"] is True

    def test_check_services_inactive(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "redis.service - Redis\n"
                "   Loaded: loaded\n"
                "   Active: inactive (dead)\n"
            ),
            stderr="", exit_code=3, duration_ms=20,
        )

        result = check_services_impl(mock_ssh, "prod", services=["redis"])
        assert result["services"]["redis"]["active"] is False

    def test_check_services_all(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "  UNIT                   LOAD   ACTIVE SUB     DESCRIPTION\n"
                "  nginx.service          loaded active running A high performance web server\n"
                "  ssh.service            loaded active running OpenBSD Secure Shell server\n"
            ),
            stderr="", exit_code=0, duration_ms=20,
        )

        result = check_services_impl(mock_ssh, "prod", services=None)
        assert result["raw_output"] is not None


class TestCheckPorts:
    def test_check_ports(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:((\"nginx\",pid=1234,fd=6))\n"
                "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=567,fd=3))\n"
            ),
            stderr="", exit_code=0, duration_ms=25,
        )

        result = check_ports_impl(mock_ssh, "prod")
        assert len(result["ports"]) == 2
        assert result["ports"][0]["port"] == 80
        assert result["ports"][0]["process"] == "nginx"


class TestProcessList:
    def test_process_list_by_cpu(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "  PID USER      %CPU %MEM    RSS COMMAND\n"
                " 1234 www-data  45.2  3.1  256000 nginx\n"
                " 5678 postgres  22.1 12.5 1024000 postgres\n"
            ),
            stderr="", exit_code=0, duration_ms=30,
        )

        result = process_list_impl(mock_ssh, "prod", sort_by="cpu")
        assert len(result["processes"]) == 2
        assert result["processes"][0]["pid"] == 1234
        assert result["processes"][0]["cpu_percent"] == 45.2

    def test_process_list_by_memory(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "  PID USER      %CPU %MEM    RSS COMMAND\n"
                " 5678 postgres  22.1 12.5 1024000 postgres\n"
                " 1234 www-data  45.2  3.1  256000 nginx\n"
            ),
            stderr="", exit_code=0, duration_ms=30,
        )

        result = process_list_impl(mock_ssh, "prod", sort_by="memory")
        assert result["processes"][0]["mem_percent"] == 12.5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_monitoring.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement monitoring tools**

```python
# src/agensysadmin/tools/monitoring.py
from __future__ import annotations

import re

from agensysadmin.ssh_manager import SSHManager


def system_info_impl(ssh: SSHManager, server: str) -> dict:
    uname = ssh.execute(server, "uname -a").stdout.strip()
    uptime = ssh.execute(server, "uptime -p").stdout.strip()
    free_output = ssh.execute(server, "free -b").stdout
    cpu_cores = int(ssh.execute(server, "nproc").stdout.strip())
    loadavg = ssh.execute(server, "cat /proc/loadavg").stdout.strip()

    memory = _parse_free(free_output)

    return {
        "uname": uname,
        "uptime": uptime,
        "cpu_cores": cpu_cores,
        "load_average": " ".join(loadavg.split()[:3]),
        "memory": memory.get("mem", {}),
        "swap": memory.get("swap", {}),
    }


def _parse_free(output: str) -> dict:
    result = {}
    lines = output.strip().split("\n")
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        label = parts[0].lower().rstrip(":")
        if label == "mem":
            result["mem"] = {
                "total": int(parts[1]),
                "used": int(parts[2]),
                "free": int(parts[3]),
                "available": int(parts[6]) if len(parts) > 6 else None,
            }
        elif label == "swap":
            result["swap"] = {
                "total": int(parts[1]),
                "used": int(parts[2]),
                "free": int(parts[3]),
            }
    return result


def disk_usage_impl(ssh: SSHManager, server: str) -> dict:
    output = ssh.execute(server, "df -h --output=source,size,used,avail,pcent,target").stdout
    lines = output.strip().split("\n")
    filesystems = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            filesystems.append({
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "use_percent": parts[4],
                "mounted_on": parts[5],
            })
    return {"filesystems": filesystems}


def check_services_impl(
    ssh: SSHManager, server: str, services: list[str] | None = None
) -> dict:
    if services:
        result_services = {}
        for svc in services:
            output = ssh.execute(server, f"systemctl status {svc}")
            active = "active (running)" in output.stdout
            result_services[svc] = {
                "active": active,
                "raw_output": output.stdout.strip(),
            }
        return {"services": result_services}
    else:
        output = ssh.execute(
            server, "systemctl list-units --type=service --state=running --no-pager"
        )
        return {"raw_output": output.stdout.strip()}


def check_ports_impl(ssh: SSHManager, server: str) -> dict:
    output = ssh.execute(server, "ss -tlnp").stdout
    lines = output.strip().split("\n")
    ports = []
    for line in lines:
        if "LISTEN" not in line:
            continue
        parts = line.split()
        # Parse local address:port
        local_addr = parts[3] if len(parts) > 3 else ""
        port_match = re.search(r":(\d+)$", local_addr)
        port = int(port_match.group(1)) if port_match else 0

        # Parse process name
        process = ""
        process_match = re.search(r'\("([^"]+)"', line)
        if process_match:
            process = process_match.group(1)

        ports.append({"port": port, "address": local_addr, "process": process})
    return {"ports": ports}


def process_list_impl(
    ssh: SSHManager, server: str, sort_by: str = "cpu"
) -> dict:
    sort_flag = "-%cpu" if sort_by == "cpu" else "-%mem"
    output = ssh.execute(
        server,
        f"ps aux --sort={sort_flag} | head -21",
    ).stdout
    lines = output.strip().split("\n")
    processes = []
    for line in lines[1:]:  # skip header
        parts = line.split(None, 10)
        if len(parts) >= 11:
            processes.append({
                "pid": int(parts[1]),
                "user": parts[0],
                "cpu_percent": float(parts[2]),
                "mem_percent": float(parts[3]),
                "rss_kb": int(parts[5]),
                "command": parts[10],
            })
    return {"processes": processes}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_monitoring.py -v`
Expected: all tests PASS

Note: some tests may need minor adjustments based on exact parsing. Fix any parsing mismatches in the implementation — the test fixtures define the expected behavior, the parsing code adapts to match.

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/monitoring.py tests/test_tools_monitoring.py
git commit -m "feat: add monitoring tools — system_info, disk_usage, check_services, check_ports, process_list"
```

---

### Task 6: MCP Server — Wire Everything Together

**Files:**
- Create: `src/agensysadmin/server.py`
- Create: `src/agensysadmin/__main__.py`

- [ ] **Step 1: Implement the MCP server**

```python
# src/agensysadmin/server.py
from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from agensysadmin.config import load_config
from agensysadmin.ssh_manager import SSHManager
from agensysadmin.tools.general import execute_command_impl
from agensysadmin.tools.monitoring import (
    check_ports_impl,
    check_services_impl,
    disk_usage_impl,
    process_list_impl,
    system_info_impl,
)

mcp = FastMCP("agensysadmin")

BASE_PATH = Path(__file__).resolve().parent.parent.parent
_servers: dict = {}
_ssh = SSHManager()


def _get_config():
    global _servers
    if not _servers:
        _servers = load_config(BASE_PATH)
    return _servers


def _ensure_connected(server: str) -> str:
    configs = _get_config()
    if server not in configs:
        raise ValueError(
            f"Unknown server '{server}'. Available: {list(configs.keys())}"
        )
    _ssh.connect(configs[server])
    return server


@mcp.tool()
def list_servers() -> dict:
    """List all configured servers and their connection status."""
    configs = _get_config()
    result = {}
    for name, cfg in configs.items():
        connected = _ssh.is_connected(name)
        result[name] = {
            "host": cfg.host,
            "port": cfg.port,
            "user": cfg.user,
            "connected": connected,
        }
    return result


@mcp.tool()
def system_info(server: str) -> dict:
    """Get OS, uptime, CPU cores, load average, memory and swap usage for a server."""
    _ensure_connected(server)
    return system_info_impl(_ssh, server)


@mcp.tool()
def disk_usage(server: str) -> dict:
    """Get disk and filesystem usage for a server."""
    _ensure_connected(server)
    return disk_usage_impl(_ssh, server)


@mcp.tool()
def check_services(server: str, services: list[str] | None = None) -> dict:
    """Check systemd service status. Pass specific service names or omit for all running services."""
    _ensure_connected(server)
    return check_services_impl(_ssh, server, services=services)


@mcp.tool()
def check_ports(server: str) -> dict:
    """List all listening TCP ports and associated processes on a server."""
    _ensure_connected(server)
    return check_ports_impl(_ssh, server)


@mcp.tool()
def process_list(server: str, sort_by: str = "cpu") -> dict:
    """List top processes sorted by CPU or memory usage. sort_by: 'cpu' or 'memory'."""
    _ensure_connected(server)
    return process_list_impl(_ssh, server, sort_by=sort_by)


@mcp.tool()
def execute_command(server: str, command: str, timeout: int | None = None) -> dict:
    """Execute an arbitrary shell command on a remote server. Returns stdout, stderr, exit_code, duration_ms."""
    _ensure_connected(server)
    return execute_command_impl(_ssh, server, command, timeout=timeout)
```

- [ ] **Step 2: Create __main__.py for `python -m agensysadmin` entry point**

```python
# src/agensysadmin/__main__.py
from agensysadmin.server import mcp

mcp.run()
```

- [ ] **Step 3: Verify server starts without errors**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -c "from agensysadmin.server import mcp; print('Server module loads OK')" `
Expected: `Server module loads OK`

- [ ] **Step 4: Commit**

```bash
git add src/agensysadmin/server.py src/agensysadmin/__main__.py
git commit -m "feat: add MCP server wiring all tools together"
```

---

### Task 7: Integration Smoke Test + README

**Files:**
- Create: `tests/test_server_integration.py`
- Create: `README.md`

- [ ] **Step 1: Write integration test for tool registration**

```python
# tests/test_server_integration.py
def test_server_imports():
    """Verify server module loads without errors."""
    from agensysadmin.server import mcp
    assert mcp is not None


def test_all_tools_registered():
    """Verify all expected tools are registered on the MCP server."""
    from agensysadmin.server import mcp

    tool_names = set()
    for tool in mcp._tool_manager._tools.values():
        tool_names.add(tool.name)

    expected = {
        "list_servers",
        "system_info",
        "disk_usage",
        "check_services",
        "check_ports",
        "process_list",
        "execute_command",
    }
    assert expected.issubset(tool_names), f"Missing tools: {expected - tool_names}"
```

- [ ] **Step 2: Run all tests**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/ -v`
Expected: all tests PASS

- [ ] **Step 3: Write README.md**

```markdown
# AgenSysAdmin

MCP server for remote Linux server administration via SSH. Integrates with Claude Code to manage Ubuntu/Debian servers.

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Linux/Mac
pip install -e ".[dev]"
```

## Configuration

1. Copy `servers.yaml.example` to `servers.yaml` and edit with your server details.
2. Copy `.env.example` to `.env` and set SSH key paths or passwords.

## Claude Code Integration

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "sysadmin": {
      "command": "python",
      "args": ["-m", "agensysadmin"],
      "cwd": "D:/AI/AgenSysAdmin"
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_servers` | List configured servers and connection status |
| `system_info` | OS, uptime, CPU, RAM, load average |
| `disk_usage` | Disk and filesystem usage |
| `check_services` | Systemd service status |
| `check_ports` | Listening TCP ports |
| `process_list` | Top processes by CPU/memory |
| `execute_command` | Run any shell command |

## Tests

```bash
pytest tests/ -v
```
```

- [ ] **Step 4: Run full test suite one final time**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/ -v`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_server_integration.py README.md
git commit -m "feat: add integration tests and README"
```

---

## Self-Review Checklist

- **Spec coverage:** All 7 tools from the spec are implemented (list_servers, system_info, disk_usage, check_services, check_ports, process_list, execute_command). SSH Manager with connection pooling, reconnection, key+password auth. Config from servers.yaml + .env. MCP integration via FastMCP. ✓
- **Placeholder scan:** No TBD/TODO. All code blocks are complete. ✓
- **Type consistency:** `SSHManager`, `CommandResult`, `ServerConfig`, `load_config` — names consistent across all tasks. `*_impl` pattern consistent for all tool implementations. ✓
- **Scope check:** Focused on Milestone 1 only. No Docker/security/backup tools. ✓
