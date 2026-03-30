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
