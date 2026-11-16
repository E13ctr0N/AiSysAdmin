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
    section_status: dict[str, str] = {}

    try:
        info = system_info_impl(ssh, server)
        sections.append("## System Info\n")
        if info.get("success", True):
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
            section_status["system_info"] = "complete"
        else:
            error_type = info.get("error_type", "CommandFailed")
            section_status["system_info"] = f"failed:{error_type}"
            sections.append(f"Unavailable ({error_type}).")
    except Exception as error:
        section_status["system_info"] = f"failed:{type(error).__name__}"
        sections.append(f"## System Info\n\nUnavailable ({type(error).__name__}).")

    try:
        disks = disk_usage_impl(ssh, server)
        sections.append("\n## Disk Usage\n")
        if disks.get("success", True):
            sections.append("| Filesystem | Size | Used | Avail | Use% | Mounted |")
            sections.append("|---|---|---|---|---|---|")
            for fs in disks.get("filesystems", []):
                sections.append(
                    f"| {fs['filesystem']} | {fs['size']} | {fs['used']} | {fs['available']} | {fs['use_percent']} | {fs['mounted_on']} |"
                )
            section_status["disk_usage"] = "complete"
        else:
            error_type = disks.get("error_type", "CommandFailed")
            section_status["disk_usage"] = f"failed:{error_type}"
            sections.append(f"Unavailable ({error_type}).")
    except Exception as error:
        section_status["disk_usage"] = f"failed:{type(error).__name__}"
        sections.append(f"\n## Disk Usage\n\nUnavailable ({type(error).__name__}).")

    try:
        ports = check_ports_impl(ssh, server)
        sections.append("\n## Open Ports\n")
        if not ports.get("success", True):
            error_type = ports.get("error_type", "CommandFailed")
            section_status["open_ports"] = f"failed:{error_type}"
            sections.append(f"Unavailable ({error_type}).")
        elif ports.get("ports"):
            sections.append("| Port | Address | Process |")
            sections.append("|---|---|---|")
            for p in ports["ports"]:
                sections.append(f"| {p['port']} | {p['address']} | {p['process']} |")
        else:
            sections.append("No listening ports found.")
        if ports.get("success", True):
            section_status["open_ports"] = "complete"
    except Exception as error:
        section_status["open_ports"] = f"failed:{type(error).__name__}"
        sections.append(f"\n## Open Ports\n\nUnavailable ({type(error).__name__}).")

    try:
        services = check_services_impl(ssh, server)
        sections.append("\n## Services\n")
        if services.get("success", True):
            sections.append(f"```\n{services.get('raw_output', 'N/A')}\n```")
            section_status["services"] = "complete"
        else:
            error_type = services.get("error_type", "CommandFailed")
            section_status["services"] = f"failed:{error_type}"
            sections.append(f"Unavailable ({error_type}).")
    except Exception as error:
        section_status["services"] = f"failed:{type(error).__name__}"
        sections.append(f"\n## Services\n\nUnavailable ({type(error).__name__}).")

    report = "\n".join(sections)
    complete = all(status == "complete" for status in section_status.values())
    return {
        "success": complete,
        "complete": complete,
        "section_status": section_status,
        "report": report,
        "server": server,
        "timestamp": timestamp,
    }
