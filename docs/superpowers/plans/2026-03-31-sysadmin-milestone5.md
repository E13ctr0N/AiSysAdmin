# AgenSysAdmin Milestone 5 — Backup Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tools for creating backups (tar.gz), listing existing backups, and inspecting cron jobs on remote servers.

**Architecture:** New `tools/backup.py` module with `*_impl` functions, wired into existing FastMCP server.

**Tech Stack:** Python 3.11+, existing agensysadmin infrastructure

---

### Task 1: create_backup + list_backups Tools

**Files:**
- Create: `src/agensysadmin/tools/backup.py`
- Create: `tests/test_tools_backup.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_backup.py
import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.backup import create_backup_impl, list_backups_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestCreateBackup:
    def test_backup_directory(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # mkdir -p
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            # tar
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=5000),
            # ls -lh to get size
            CommandResult(stdout="-rw-r--r-- 1 root root 15M Mar 31 12:00 /backups/etc-20260331-120000.tar.gz\n", stderr="", exit_code=0, duration_ms=20),
        ]

        result = create_backup_impl(mock_ssh, "prod", source="/etc", dest_dir="/backups")
        assert result["success"] is True
        tar_cmd = mock_ssh.execute.call_args_list[1].args[1]
        assert "tar" in tar_cmd
        assert "/etc" in tar_cmd
        assert "/backups" in tar_cmd

    def test_backup_failure(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="tar: /nonexistent: Cannot stat: No such file or directory\n", exit_code=2, duration_ms=100),
        ]

        result = create_backup_impl(mock_ssh, "prod", source="/nonexistent", dest_dir="/backups")
        assert result["success"] is False

    def test_backup_custom_name(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="-rw-r--r-- 1 root root 5M Mar 31 12:00 /backups/mybackup.tar.gz\n", stderr="", exit_code=0, duration_ms=20),
        ]

        result = create_backup_impl(mock_ssh, "prod", source="/var/www", dest_dir="/backups", name="mybackup")
        tar_cmd = mock_ssh.execute.call_args_list[1].args[1]
        assert "mybackup.tar.gz" in tar_cmd


class TestListBackups:
    def test_list_backups(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "-rw-r--r-- 1 root root  15M Mar 30 10:00 /backups/etc-20260330-100000.tar.gz\n"
                "-rw-r--r-- 1 root root 120M Mar 31 02:00 /backups/www-20260331-020000.tar.gz\n"
                "-rw-r--r-- 1 root root 500M Mar 31 12:00 /backups/db-20260331-120000.tar.gz\n"
            ),
            stderr="", exit_code=0, duration_ms=50,
        )

        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result["success"] is True
        assert len(result["backups"]) == 3
        assert result["backups"][0]["name"] == "etc-20260330-100000.tar.gz"
        assert result["backups"][0]["size"] == "15M"

    def test_list_backups_empty(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=30,
        )

        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result["backups"] == []

    def test_list_backups_dir_not_found(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="ls: cannot access '/backups': No such file or directory\n",
            exit_code=2, duration_ms=20,
        )

        result = list_backups_impl(mock_ssh, "prod", path="/backups")
        assert result["success"] is False
```

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement**

```python
# src/agensysadmin/tools/backup.py
from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager


def create_backup_impl(
    ssh: SSHManager,
    server: str,
    source: str,
    dest_dir: str,
    name: str | None = None,
) -> dict:
    ssh.execute(server, f"sudo mkdir -p {dest_dir}")

    if name:
        filename = f"{name}.tar.gz"
    else:
        basename = source.strip("/").replace("/", "-")
        filename = f"{basename}-$(date +%Y%m%d-%H%M%S).tar.gz"

    dest_path = f"{dest_dir}/{filename}"
    result = ssh.execute(
        server, f"sudo tar czf {dest_path} {source}", timeout=300
    )

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "source": source,
        }

    size_result = ssh.execute(server, f"ls -lh {dest_path}")
    size = ""
    if size_result.stdout.strip():
        parts = size_result.stdout.strip().split()
        if len(parts) >= 5:
            size = parts[4]

    return {
        "success": True,
        "path": dest_path,
        "source": source,
        "size": size,
        "duration_ms": result.duration_ms,
    }


def list_backups_impl(
    ssh: SSHManager,
    server: str,
    path: str,
) -> dict:
    result = ssh.execute(server, f"ls -lh {path}/*.tar.gz 2>/dev/null")

    if result.exit_code != 0 and result.stderr.strip():
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "backups": [],
        }

    backups = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 9:
            full_path = parts[-1]
            name = full_path.split("/")[-1]
            backups.append({
                "name": name,
                "size": parts[4],
                "date": f"{parts[5]} {parts[6]} {parts[7]}",
                "path": full_path,
            })

    return {
        "success": True,
        "backups": backups,
    }
```

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/backup.py tests/test_tools_backup.py && git commit -m "feat: add create_backup and list_backups tools"
```

---

### Task 2: check_cron + Wire into MCP Server

**Files:**
- Modify: `src/agensysadmin/tools/backup.py`
- Modify: `tests/test_tools_backup.py`
- Modify: `src/agensysadmin/server.py`
- Modify: `tests/test_server_integration.py`

- [ ] **Step 1: Write failing tests for check_cron**

```python
from agensysadmin.tools.backup import create_backup_impl, list_backups_impl, check_cron_impl

class TestCheckCron:
    def test_check_cron_with_jobs(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # user crontab
            CommandResult(
                stdout="0 2 * * * /usr/local/bin/backup.sh\n30 3 * * 0 /usr/local/bin/weekly-cleanup.sh\n",
                stderr="", exit_code=0, duration_ms=20,
            ),
            # system cron.d
            CommandResult(
                stdout=(
                    "/etc/cron.d/certbot:\n"
                    "0 */12 * * * root test -x /usr/bin/certbot && perl -e 'sleep int(rand(43200))' && certbot -q renew\n"
                ),
                stderr="", exit_code=0, duration_ms=30,
            ),
        ]

        result = check_cron_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert len(result["user_cron"]) == 2
        assert result["user_cron"][0]["schedule"] == "0 2 * * *"
        assert result["user_cron"][0]["command"] == "/usr/local/bin/backup.sh"
        assert "certbot" in result["system_cron"]

    def test_check_cron_empty(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="no crontab for root\n", exit_code=1, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
        ]

        result = check_cron_impl(mock_ssh, "prod")
        assert result["user_cron"] == []

    def test_check_cron_specific_user(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="*/5 * * * * /app/healthcheck.sh\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=20),
        ]

        result = check_cron_impl(mock_ssh, "prod", user="www-data")
        cmd = mock_ssh.execute.call_args_list[0].args[1]
        assert "www-data" in cmd
```

- [ ] **Step 2: Implement check_cron_impl**

```python
def check_cron_impl(
    ssh: SSHManager,
    server: str,
    user: str | None = None,
) -> dict:
    user_flag = f"-u {user}" if user else ""
    user_cron_result = ssh.execute(server, f"sudo crontab {user_flag} -l 2>/dev/null")

    user_cron = []
    for line in user_cron_result.stdout.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 5)
        if len(parts) >= 6:
            user_cron.append({
                "schedule": " ".join(parts[:5]),
                "command": parts[5],
            })

    system_cron_result = ssh.execute(
        server, "sudo cat /etc/cron.d/* 2>/dev/null"
    )

    return {
        "success": True,
        "user_cron": user_cron,
        "system_cron": system_cron_result.stdout.strip(),
    }
```

- [ ] **Step 3: Wire all 3 backup tools into server.py**

Add import:
```python
from agensysadmin.tools.backup import (
    check_cron_impl,
    create_backup_impl,
    list_backups_impl,
)
```

Add tools:
```python
@mcp.tool()
def create_backup(server: str, source: str, dest_dir: str, name: str | None = None) -> dict:
    """Create a tar.gz backup of a directory. Auto-generates timestamped name if not provided."""
    _ensure_connected(server)
    return create_backup_impl(_ssh, server, source=source, dest_dir=dest_dir, name=name)

@mcp.tool()
def list_backups(server: str, path: str) -> dict:
    """List .tar.gz backup files in a directory with sizes and dates."""
    _ensure_connected(server)
    return list_backups_impl(_ssh, server, path=path)

@mcp.tool()
def check_cron(server: str, user: str | None = None) -> dict:
    """List cron jobs — user crontab and system /etc/cron.d/ entries."""
    _ensure_connected(server)
    return check_cron_impl(_ssh, server, user=user)
```

- [ ] **Step 4: Update integration test** — add `"create_backup"`, `"list_backups"`, `"check_cron"` to expected set.

- [ ] **Step 5: Run full test suite**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/ -v`

- [ ] **Step 6: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/backup.py tests/test_tools_backup.py src/agensysadmin/server.py tests/test_server_integration.py && git commit -m "feat: add backup tools — create_backup, list_backups, check_cron"
```
