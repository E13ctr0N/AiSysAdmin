from __future__ import annotations

from pathlib import Path
import logging
import os

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

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

BASE_PATH = Path(os.environ.get("AGENSYSADMIN_CONFIG_DIR", Path(__file__).resolve().parent.parent.parent)).expanduser().resolve()
_servers: dict = {}
_ssh = SSHManager()
_logger = logging.getLogger(__name__)


def _get_config():
    global _servers
    if not _servers:
        _servers = load_config(BASE_PATH)
    return _servers


def _ensure_connected(server: str, *, mutation: bool = False,
                      arbitrary: bool = False, operation: str = "inspect") -> str:
    configs = _get_config()
    if server not in configs:
        raise ValueError(
            f"Unknown server '{server}'. Available: {list(configs.keys())}"
        )
    config = configs[server]
    # Permissions come only from operator-owned local configuration, never from
    # a model-supplied 'confirmed' argument. Reject BEFORE opening any SSH channel.
    if (mutation and config.allow_mutations is not True) or (arbitrary and config.allow_arbitrary_commands is not True):
        _logger.warning("Denied operation=%s on configured server=%s", operation, config.name)
        raise PermissionError("Operation disabled by local server policy. Ask the operator to review servers.yaml and restart the MCP server.")
    if mutation:
        _logger.warning("Authorized mutation operation=%s on configured server=%s", operation, config.name)
    _ssh.connect(config)
    return server


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
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
            "allow_mutations": cfg.allow_mutations,
            "allow_arbitrary_commands": cfg.allow_arbitrary_commands,
        }
    return result


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def system_info(server: str) -> dict:
    """Get OS, uptime, CPU cores, load average, memory and swap usage for a server."""
    _ensure_connected(server)
    return system_info_impl(_ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def disk_usage(server: str) -> dict:
    """Get disk and filesystem usage for a server."""
    _ensure_connected(server)
    return disk_usage_impl(_ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_services(server: str, services: list[str] | None = None) -> dict:
    """Check systemd service status. Pass specific service names or omit for all running services."""
    _ensure_connected(server)
    return check_services_impl(_ssh, server, services=services)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_ports(server: str) -> dict:
    """List all listening TCP ports and associated processes on a server."""
    _ensure_connected(server)
    return check_ports_impl(_ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def process_list(server: str, sort_by: str = "cpu") -> dict:
    """List top processes sorted by CPU or memory usage. sort_by: 'cpu' or 'memory'."""
    _ensure_connected(server)
    return process_list_impl(_ssh, server, sort_by=sort_by)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def execute_command(server: str, command: str, timeout: int | None = None) -> dict:
    """Execute arbitrary shell code. Disabled by default; requires both local permission flags and client approval."""
    _ensure_connected(server, mutation=True, arbitrary=True, operation="execute_command")
    return execute_command_impl(_ssh, server, command, timeout=timeout)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def install_package(server: str, packages: list[str], update: bool = True) -> dict:
    """Install packages via apt on a remote server. Set update=False to skip apt update."""
    _ensure_connected(server, mutation=True, operation="install_package")
    return install_package_impl(_ssh, server, packages=packages, update=update)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def manage_service(server: str, service: str, action: str) -> dict:
    """Manage a systemd service. action: 'start', 'stop', 'restart', 'reload', 'enable', 'disable', 'status'."""
    _ensure_connected(server, mutation=action != "status", operation="manage_service")
    return manage_service_impl(_ssh, server, service=service, action=action)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def edit_config(server: str, path: str, content: str | None = None, backup: bool = True) -> dict:
    """Read or atomically replace a regular config file. Writes require local permission; unique private backups are enabled by default."""
    _ensure_connected(server, mutation=content is not None, operation="edit_config")
    return edit_config_impl(_ssh, server, path=path, content=content, backup=backup)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def docker_ps(server: str, all_containers: bool = False) -> dict:
    """List Docker containers. Set all_containers=True to include stopped containers."""
    _ensure_connected(server)
    return docker_ps_impl(_ssh, server, all_containers=all_containers)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def docker_logs(server: str, container: str, tail: int | None = None) -> dict:
    """Get logs from a Docker container. Use tail to limit number of lines."""
    _ensure_connected(server)
    return docker_logs_impl(_ssh, server, container=container, tail=tail)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def docker_compose(server: str, action: str, path: str) -> dict:
    """Run docker compose action in a directory. action: 'up', 'down', 'restart', 'stop', 'start', 'ps', 'logs', 'pull', 'build'."""
    _ensure_connected(server, mutation=action not in {"ps", "logs"}, operation="docker_compose")
    return docker_compose_impl(_ssh, server, action=action, path=path)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def docker_images(server: str) -> dict:
    """List Docker images on a server."""
    _ensure_connected(server)
    return docker_images_impl(_ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_updates(server: str, security_only: bool = False) -> dict:
    """Read available updates from the existing apt cache without refreshing it. Results may be stale."""
    _ensure_connected(server)
    return check_updates_impl(_ssh, server, security_only=security_only)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def firewall_status(server: str) -> dict:
    """Get UFW firewall status, default policies, and rules."""
    _ensure_connected(server)
    return firewall_status_impl(_ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def security_audit(server: str) -> dict:
    """Run a comprehensive security audit: SSH config, auto-updates, failed logins, root users, world-writable files."""
    _ensure_connected(server)
    return security_audit_impl(_ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def full_security_audit(server: str) -> dict:
    """Run a comprehensive security audit with scoring: SSH, firewall, users, network, filesystem, services, updates, logs, kernel, malware. Returns score, grade, findings, and markdown report."""
    _ensure_connected(server)
    return full_security_audit_impl(_ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def create_backup(server: str, source: str, dest_dir: str, name: str | None = None) -> dict:
    """Create a tar.gz backup of a directory. Auto-generates timestamped name if not provided."""
    _ensure_connected(server, mutation=True, operation="create_backup")
    return create_backup_impl(_ssh, server, source=source, dest_dir=dest_dir, name=name)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def list_backups(server: str, path: str) -> dict:
    """List .tar.gz backup files in a directory with sizes and dates."""
    _ensure_connected(server)
    return list_backups_impl(_ssh, server, path=path)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_cron(server: str, user: str | None = None) -> dict:
    """List cron jobs — user crontab and system /etc/cron.d/ entries."""
    _ensure_connected(server)
    return check_cron_impl(_ssh, server, user=user)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def generate_report(server: str) -> dict:
    """Generate a comprehensive markdown report: system info, disk usage, ports, services."""
    _ensure_connected(server)
    return generate_report_impl(_ssh, server)
