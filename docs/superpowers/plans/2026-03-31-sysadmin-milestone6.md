# AgenSysAdmin Milestone 6 — Report Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generate_report tool that runs multiple monitoring/security checks and compiles results into a structured markdown report.

**Architecture:** New `tools/reports.py` module, reuses existing `*_impl` functions from monitoring and security modules.

**Tech Stack:** Python 3.11+, existing agensysadmin infrastructure

---

### Task 1: generate_report Tool + Wire into MCP

**Files:**
- Create: `src/agensysadmin/tools/reports.py`
- Create: `tests/test_tools_reports.py`
- Modify: `src/agensysadmin/server.py`
- Modify: `tests/test_server_integration.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_reports.py
import pytest
from unittest.mock import MagicMock, patch
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.reports import generate_report_impl


@pytest.fixture
def mock_ssh():
    manager = MagicMock(spec=SSHManager)
    # Default: all commands succeed with minimal output
    manager.execute.return_value = CommandResult(
        stdout="", stderr="", exit_code=0, duration_ms=10
    )
    return manager


class TestGenerateReport:
    def test_report_returns_markdown(self, mock_ssh):
        # system_info needs 5 calls, then disk_usage, check_ports, check_services each 1
        mock_ssh.execute.side_effect = [
            # uname
            CommandResult(stdout="Linux prod 5.15.0\n", stderr="", exit_code=0, duration_ms=10),
            # uptime
            CommandResult(stdout="up 14 days\n", stderr="", exit_code=0, duration_ms=10),
            # free
            CommandResult(stdout="              total\nMem:     8000000000  4000000000  2000000000  100000000  1900000000  3900000000\nSwap:    2000000000  0  2000000000\n", stderr="", exit_code=0, duration_ms=10),
            # nproc
            CommandResult(stdout="4\n", stderr="", exit_code=0, duration_ms=10),
            # loadavg
            CommandResult(stdout="0.5 0.3 0.2 1/100 1234\n", stderr="", exit_code=0, duration_ms=10),
            # df
            CommandResult(stdout="Filesystem Size Used Avail Use% Mounted\n/dev/sda1 50G 20G 28G 42% /\n", stderr="", exit_code=0, duration_ms=10),
            # ss (ports)
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            # systemctl (services)
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
        ]

        result = generate_report_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert "# Server Report: prod" in result["report"]
        assert "## System Info" in result["report"]
        assert "## Disk Usage" in result["report"]

    def test_report_includes_all_sections(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="Linux prod 5.15.0\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="up 1 day\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="              total\nMem:     8000000000  4000000000  2000000000  100000000  1900000000  3900000000\nSwap:    2000000000  0  2000000000\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="2\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="1.0 0.8 0.5 2/50 999\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Filesystem Size Used Avail Use% Mounted\n/dev/sda1 100G 80G 15G 85% /\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
        ]

        result = generate_report_impl(mock_ssh, "prod")
        report = result["report"]
        assert "## System Info" in report
        assert "## Disk Usage" in report
        assert "## Open Ports" in report
        assert "## Services" in report

    def test_report_format_is_string(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="test\n", stderr="", exit_code=0, duration_ms=10
        )
        result = generate_report_impl(mock_ssh, "prod")
        assert isinstance(result["report"], str)
```

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement generate_report_impl**

```python
# src/agensysadmin/tools/reports.py
from __future__ import annotations

from datetime import datetime, timezone

from agensysadmin.ssh_manager import SSHManager
from agensysadmin.tools.monitoring import (
    check_ports_impl,
    check_services_impl,
    disk_usage_impl,
    system_info_impl,
)


def generate_report_impl(ssh: SSHManager, server: str) -> dict:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sections = [f"# Server Report: {server}", f"\nGenerated: {timestamp}\n"]

    # System Info
    try:
        info = system_info_impl(ssh, server)
        sections.append("## System Info\n")
        sections.append(f"- **OS:** {info.get('uname', 'N/A')}")
        sections.append(f"- **Uptime:** {info.get('uptime', 'N/A')}")
        sections.append(f"- **CPU Cores:** {info.get('cpu_cores', 'N/A')}")
        sections.append(f"- **Load Average:** {info.get('load_average', 'N/A')}")
        mem = info.get("memory", {})
        if mem:
            total_gb = mem.get("total", 0) / (1024**3)
            used_gb = mem.get("used", 0) / (1024**3)
            sections.append(f"- **Memory:** {used_gb:.1f} GB / {total_gb:.1f} GB")
        swap = info.get("swap", {})
        if swap:
            swap_total = swap.get("total", 0) / (1024**3)
            swap_used = swap.get("used", 0) / (1024**3)
            sections.append(f"- **Swap:** {swap_used:.1f} GB / {swap_total:.1f} GB")
    except Exception as e:
        sections.append(f"## System Info\n\nError: {e}")

    # Disk Usage
    try:
        disks = disk_usage_impl(ssh, server)
        sections.append("\n## Disk Usage\n")
        sections.append("| Filesystem | Size | Used | Avail | Use% | Mounted |")
        sections.append("|---|---|---|---|---|---|")
        for fs in disks.get("filesystems", []):
            sections.append(
                f"| {fs['filesystem']} | {fs['size']} | {fs['used']} | {fs['available']} | {fs['use_percent']} | {fs['mounted_on']} |"
            )
    except Exception as e:
        sections.append(f"\n## Disk Usage\n\nError: {e}")

    # Open Ports
    try:
        ports = check_ports_impl(ssh, server)
        sections.append("\n## Open Ports\n")
        if ports.get("ports"):
            sections.append("| Port | Address | Process |")
            sections.append("|---|---|---|")
            for p in ports["ports"]:
                sections.append(f"| {p['port']} | {p['address']} | {p['process']} |")
        else:
            sections.append("No listening ports found.")
    except Exception as e:
        sections.append(f"\n## Open Ports\n\nError: {e}")

    # Services
    try:
        services = check_services_impl(ssh, server)
        sections.append("\n## Services\n")
        sections.append(f"```\n{services.get('raw_output', 'N/A')}\n```")
    except Exception as e:
        sections.append(f"\n## Services\n\nError: {e}")

    report = "\n".join(sections)

    return {
        "success": True,
        "report": report,
        "server": server,
        "timestamp": timestamp,
    }
```

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Wire into server.py**

Add import:
```python
from agensysadmin.tools.reports import generate_report_impl
```

Add tool:
```python
@mcp.tool()
def generate_report(server: str) -> dict:
    """Generate a comprehensive markdown report: system info, disk usage, ports, services."""
    _ensure_connected(server)
    return generate_report_impl(_ssh, server)
```

Update integration test expected set: add `"generate_report"`.

- [ ] **Step 6: Run full test suite**
- [ ] **Step 7: Commit**

```bash
cd D:/AI/AgenSysAdmin && git add src/agensysadmin/tools/reports.py tests/test_tools_reports.py src/agensysadmin/server.py tests/test_server_integration.py && git commit -m "feat: add generate_report tool — markdown server reports"
```
