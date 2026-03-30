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
