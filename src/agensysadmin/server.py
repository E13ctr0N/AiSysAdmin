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
from agensysadmin.tools.docker import (
    docker_compose_impl,
    docker_images_impl,
    docker_logs_impl,
    docker_ps_impl,
)
from agensysadmin.tools.management import (
    edit_config_impl,
    install_package_impl,
    manage_service_impl,
)
from agensysadmin.tools.security import (
    check_updates_impl,
    firewall_status_impl,
    full_security_audit_impl,
    security_audit_impl,
)
from agensysadmin.tools.backup import (
    check_cron_impl,
    create_backup_impl,
    list_backups_impl,
)
from agensysadmin.tools.reports import generate_report_impl

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


@mcp.tool()
def full_security_audit(server: str) -> dict:
    """Run a comprehensive security audit with scoring: SSH, firewall, users, network, filesystem, services, updates, logs, kernel, malware. Returns score, grade, findings, and markdown report."""
    _ensure_connected(server)
    return full_security_audit_impl(_ssh, server)


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


@mcp.tool()
def generate_report(server: str) -> dict:
    """Generate a comprehensive markdown report: system info, disk usage, ports, services."""
    _ensure_connected(server)
    return generate_report_impl(_ssh, server)
