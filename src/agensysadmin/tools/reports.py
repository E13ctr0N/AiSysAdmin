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

    try:
        services = check_services_impl(ssh, server)
        sections.append("\n## Services\n")
        sections.append(f"```\n{services.get('raw_output', 'N/A')}\n```")
    except Exception as e:
        sections.append(f"\n## Services\n\nError: {e}")

    report = "\n".join(sections)
    return {"success": True, "report": report, "server": server, "timestamp": timestamp}
