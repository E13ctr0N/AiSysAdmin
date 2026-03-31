# AgenSysAdmin Milestone 4 — Security Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tools for security auditing: check for available updates, inspect firewall rules, and run a comprehensive security audit.

**Architecture:** New `tools/security.py` module with `*_impl` functions, wired into existing FastMCP server.

**Tech Stack:** Python 3.11+, existing agensysadmin infrastructure

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/agensysadmin/tools/security.py` | Create | check_updates_impl, firewall_status_impl, security_audit_impl |
| `tests/test_tools_security.py` | Create | Tests for all security tools |
| `src/agensysadmin/server.py` | Modify | Register 3 new MCP tools |
| `tests/test_server_integration.py` | Modify | Update registration check |

---

### Task 1: check_updates Tool

**Files:**
- Create: `src/agensysadmin/tools/security.py`
- Create: `tests/test_tools_security.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_security.py
import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.security import check_updates_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestCheckUpdates:
    def test_updates_available(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # apt update
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            # apt list --upgradable
            CommandResult(
                stdout=(
                    "Listing...\n"
                    "libssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]\n"
                    "openssl/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]\n"
                    "curl/jammy-security 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]\n"
                ),
                stderr="", exit_code=0, duration_ms=2000,
            ),
        ]

        result = check_updates_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert result["update_count"] == 3
        assert len(result["packages"]) == 3
        assert result["packages"][0]["name"] == "libssl3"
        assert "jammy-security" in result["packages"][0]["source"]

    def test_no_updates(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(stdout="Listing...\n", stderr="", exit_code=0, duration_ms=1000),
        ]

        result = check_updates_impl(mock_ssh, "prod")
        assert result["update_count"] == 0
        assert result["packages"] == []

    def test_security_updates_only(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=3000),
            CommandResult(
                stdout=(
                    "Listing...\n"
                    "libssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]\n"
                    "vim/jammy-updates 8.2.3995-1ubuntu2.17 amd64 [upgradable from: 8.2.3995-1ubuntu2.16]\n"
                ),
                stderr="", exit_code=0, duration_ms=2000,
            ),
        ]

        result = check_updates_impl(mock_ssh, "prod", security_only=True)
        assert result["update_count"] == 1
        assert result["packages"][0]["name"] == "libssl3"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/test_tools_security.py::TestCheckUpdates -v`

- [ ] **Step 3: Implement check_updates_impl**

```python
# src/agensysadmin/tools/security.py
from __future__ import annotations

import re

from agensysadmin.ssh_manager import SSHManager


def check_updates_impl(
    ssh: SSHManager,
    server: str,
    security_only: bool = False,
) -> dict:
    ssh.execute(server, "sudo apt-get update -qq", timeout=60)
    result = ssh.execute(server, "apt list --upgradable 2>/dev/null")

    packages = []
    for line in result.stdout.strip().split("\n"):
        if line.startswith("Listing") or not line.strip():
            continue
        # Format: name/source version arch [upgradable from: old_version]
        match = re.match(r"^(\S+)/(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            name, source, version, arch = match.groups()
            if security_only and "security" not in source:
                continue
            packages.append({
                "name": name,
                "source": source,
                "version": version,
                "arch": arch,
            })

    return {
        "success": result.exit_code == 0,
        "update_count": len(packages),
        "packages": packages,
    }
```

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/security.py tests/test_tools_security.py && git commit -m "feat: add check_updates tool"
```

---

### Task 2: firewall_status Tool

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write failing tests**

```python
from agensysadmin.tools.security import check_updates_impl, firewall_status_impl


class TestFirewallStatus:
    def test_ufw_active(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # ufw status verbose
            CommandResult(
                stdout=(
                    "Status: active\n"
                    "Logging: on (low)\n"
                    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
                    "New profiles: skip\n"
                    "\n"
                    "To                         Action      From\n"
                    "--                         ------      ----\n"
                    "22/tcp                     ALLOW IN    Anywhere\n"
                    "80/tcp                     ALLOW IN    Anywhere\n"
                    "443/tcp                    ALLOW IN    Anywhere\n"
                ),
                stderr="", exit_code=0, duration_ms=100,
            ),
        ]

        result = firewall_status_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert result["active"] is True
        assert result["default_incoming"] == "deny"
        assert result["default_outgoing"] == "allow"
        assert len(result["rules"]) == 3
        assert result["rules"][0]["port"] == "22/tcp"
        assert result["rules"][0]["action"] == "ALLOW IN"

    def test_ufw_inactive(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Status: inactive\n",
            stderr="", exit_code=0, duration_ms=50,
        )

        result = firewall_status_impl(mock_ssh, "prod")
        assert result["active"] is False
        assert result["rules"] == []

    def test_ufw_not_installed(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="ufw: command not found\n",
            exit_code=127, duration_ms=20,
        )

        result = firewall_status_impl(mock_ssh, "prod")
        assert result["success"] is False
```

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement firewall_status_impl**

```python
def firewall_status_impl(ssh: SSHManager, server: str) -> dict:
    result = ssh.execute(server, "sudo ufw status verbose")

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "active": False,
            "rules": [],
        }

    lines = result.stdout.strip().split("\n")
    active = any("Status: active" in line for line in lines)

    default_incoming = ""
    default_outgoing = ""
    for line in lines:
        if "Default:" in line:
            match_in = re.search(r"(\w+)\s*\(incoming\)", line)
            match_out = re.search(r"(\w+)\s*\(outgoing\)", line)
            if match_in:
                default_incoming = match_in.group(1)
            if match_out:
                default_outgoing = match_out.group(1)

    rules = []
    in_rules = False
    for line in lines:
        if line.startswith("--"):
            in_rules = True
            continue
        if in_rules and line.strip():
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                # Action may be "ALLOW IN", "DENY IN", etc. (two words)
                action_parts = []
                from_source = "Anywhere"
                for i, p in enumerate(parts[1:], 1):
                    if p in ("Anywhere", "Anywhere") or re.match(r"\d+\.\d+\.\d+\.\d+", p):
                        from_source = " ".join(parts[i:])
                        break
                    action_parts.append(p)
                rules.append({
                    "port": port,
                    "action": " ".join(action_parts),
                    "from": from_source,
                })

    return {
        "success": True,
        "active": active,
        "default_incoming": default_incoming,
        "default_outgoing": default_outgoing,
        "rules": rules,
        "raw_output": result.stdout.strip(),
    }
```

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/security.py tests/test_tools_security.py && git commit -m "feat: add firewall_status tool"
```

---

### Task 3: security_audit Tool + Wire into MCP

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`
- Modify: `src/agensysadmin/server.py`
- Modify: `tests/test_server_integration.py`

- [ ] **Step 1: Write failing tests for security_audit**

```python
from agensysadmin.tools.security import check_updates_impl, firewall_status_impl, security_audit_impl


class TestSecurityAudit:
    def test_security_audit_runs_all_checks(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # SSH config: PermitRootLogin
            CommandResult(stdout="PermitRootLogin no\n", stderr="", exit_code=0, duration_ms=20),
            # SSH config: PasswordAuthentication
            CommandResult(stdout="PasswordAuthentication no\n", stderr="", exit_code=0, duration_ms=20),
            # Unattended upgrades
            CommandResult(stdout="/etc/apt/apt.conf.d/20auto-upgrades\n", stderr="", exit_code=0, duration_ms=20),
            # Failed login attempts
            CommandResult(stdout="42\n", stderr="", exit_code=0, duration_ms=30),
            # Users with UID 0
            CommandResult(stdout="root\n", stderr="", exit_code=0, duration_ms=20),
            # World-writable files in /etc
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=100),
        ]

        result = security_audit_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert "ssh" in result["checks"]
        assert result["checks"]["ssh"]["root_login"] == "no"
        assert result["checks"]["ssh"]["password_auth"] == "no"
        assert result["checks"]["auto_updates"]["enabled"] is True
        assert result["checks"]["failed_logins"]["count"] == 42
        assert result["checks"]["root_users"]["users"] == ["root"]
        assert result["checks"]["world_writable"]["files"] == []

    def test_security_audit_finds_issues(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="PermitRootLogin yes\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="PasswordAuthentication yes\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=20),
            CommandResult(stdout="1523\n", stderr="", exit_code=0, duration_ms=30),
            CommandResult(stdout="root\nbackdoor\n", stderr="", exit_code=0, duration_ms=20),
            CommandResult(stdout="/etc/shadow\n/etc/passwd\n", stderr="", exit_code=0, duration_ms=100),
        ]

        result = security_audit_impl(mock_ssh, "prod")
        assert result["checks"]["ssh"]["root_login"] == "yes"
        assert result["checks"]["ssh"]["password_auth"] == "yes"
        assert result["checks"]["auto_updates"]["enabled"] is False
        assert result["checks"]["failed_logins"]["count"] == 1523
        assert "backdoor" in result["checks"]["root_users"]["users"]
        assert len(result["checks"]["world_writable"]["files"]) == 2
```

- [ ] **Step 2: Implement security_audit_impl**

```python
def security_audit_impl(ssh: SSHManager, server: str) -> dict:
    # SSH config checks
    root_login = ssh.execute(
        server, "sudo grep -i '^PermitRootLogin' /etc/ssh/sshd_config | tail -1"
    ).stdout.strip()
    root_login_val = root_login.split()[-1] if root_login else "unknown"

    password_auth = ssh.execute(
        server, "sudo grep -i '^PasswordAuthentication' /etc/ssh/sshd_config | tail -1"
    ).stdout.strip()
    password_auth_val = password_auth.split()[-1] if password_auth else "unknown"

    # Auto-updates
    auto_updates = ssh.execute(
        server, "ls /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null"
    )
    auto_updates_enabled = auto_updates.exit_code == 0 and auto_updates.stdout.strip() != ""

    # Failed logins
    failed_logins = ssh.execute(
        server, "sudo grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0"
    )
    try:
        failed_count = int(failed_logins.stdout.strip())
    except ValueError:
        failed_count = 0

    # Users with UID 0
    root_users = ssh.execute(server, "awk -F: '$3 == 0 {print $1}' /etc/passwd")
    root_users_list = [u for u in root_users.stdout.strip().split("\n") if u.strip()]

    # World-writable files in /etc
    world_writable = ssh.execute(
        server, "sudo find /etc -type f -perm -o+w 2>/dev/null"
    )
    ww_files = [f for f in world_writable.stdout.strip().split("\n") if f.strip()]

    return {
        "success": True,
        "checks": {
            "ssh": {
                "root_login": root_login_val,
                "password_auth": password_auth_val,
            },
            "auto_updates": {
                "enabled": auto_updates_enabled,
            },
            "failed_logins": {
                "count": failed_count,
            },
            "root_users": {
                "users": root_users_list,
            },
            "world_writable": {
                "files": ww_files,
            },
        },
    }
```

- [ ] **Step 3: Wire all 3 security tools into server.py**

Add import:
```python
from agensysadmin.tools.security import (
    check_updates_impl,
    firewall_status_impl,
    security_audit_impl,
)
```

Add tools:
```python
@mcp.tool()
def check_updates(server: str, security_only: bool = False) -> dict:
    """Check for available apt package updates. Set security_only=True to filter security updates only."""
    _ensure_connected(server)
    return check_updates_impl(_ssh, server, security_only=security_only)

@mcp.tool()
def firewall_status(server: str) -> dict:
    """Get UFW firewall status, default policies, and rules."""
    _ensure_connected(server)
    return firewall_status_impl(_ssh, server)

@mcp.tool()
def security_audit(server: str) -> dict:
    """Run a comprehensive security audit: SSH config, auto-updates, failed logins, root users, world-writable files."""
    _ensure_connected(server)
    return security_audit_impl(_ssh, server)
```

- [ ] **Step 4: Update integration test**

Add to expected set:
```python
        "check_updates",
        "firewall_status",
        "security_audit",
```

- [ ] **Step 5: Run full test suite**

Run: `cd D:/AI/AgenSysAdmin && .venv/Scripts/python -m pytest tests/ -v`

- [ ] **Step 6: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/security.py tests/test_tools_security.py src/agensysadmin/server.py tests/test_server_integration.py && git commit -m "feat: add security tools — check_updates, firewall_status, security_audit"
```
