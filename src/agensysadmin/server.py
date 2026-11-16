from __future__ import annotations

from pathlib import Path
import logging
import os
import threading

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from agensysadmin.config import load_config
from agensysadmin.ssh_manager import SSHManager
from agensysadmin.journal import OperationJournal
from agensysadmin.validation import validate_absolute_path
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

BASE_PATH = Path(os.environ.get("AGENSYSADMIN_CONFIG_DIR") or Path.cwd()).expanduser().resolve()
_logger = logging.getLogger(__name__)


class _JournalProxy:
    def __init__(self, owner):
        self.owner = owner

    def record(self, *args, **kwargs):
        return self.owner.journal.record(*args, **kwargs)


class App:
    """Per-process state. Importing the MCP module does not read secrets or create files."""
    def __init__(self, base_path: Path | str = BASE_PATH):
        self.base_path = Path(base_path)
        self.servers: dict = {}
        self._loaded = False
        self._journal = None
        self._lock = threading.RLock()
        self.ssh = SSHManager(journal=_JournalProxy(self))

    @property
    def journal(self) -> OperationJournal:
        with self._lock:
            if self._journal is None:
                self._journal = OperationJournal(self.base_path / "logs" / "operations.jsonl")
            return self._journal

    def get_config(self):
        with self._lock:
            if not self._loaded and not self.servers:
                self.servers = load_config(self.base_path)
            self._loaded = True
            return self.servers

    def deny(self, alias: str, message: str):
        try:
            self.journal.record("policy_denied", server=alias, status="denied")
        except (OSError, ValueError):
            _logger.warning("Unable to journal denied operation")
        raise PermissionError(message)

    def ensure_connected(self, server: str, *, mutation: bool = False,
                         arbitrary: bool = False, operation: str = "inspect",
                         file_path: str | None = None, file_write: bool = False) -> str:
        configs = self.get_config()
        if server not in configs:
            raise ValueError("Unknown configured server alias; enroll it through the operator CLI")
        config = configs[server]
        if file_path is not None:
            validate_absolute_path(file_path)
            allowed = config.config_write_paths if file_write else config.config_read_paths
            if ".." in file_path.split("/") or file_path not in allowed:
                self.deny(config.name, "File path is not in the operator-owned exact configuration allowlist")
        if (mutation and config.allow_mutations is not True) or (arbitrary and config.allow_arbitrary_commands is not True):
            self.deny(config.name, "Operation disabled by local server policy; operator review and process restart are required")
        if mutation:
            self.journal.record("policy_authorized", server=config.name, status="authorized")
        self.ssh.connect(config)
        return server


app = App()


def _get_config():
    return app.get_config()


def _ensure_connected(server: str, **kwargs) -> str:
    return app.ensure_connected(server, **kwargs)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def list_servers() -> dict:
    """List all configured servers and their connection status."""
    configs = _get_config()
    result = {}
    for name, cfg in configs.items():
        session = app.ssh.connection_info(name)
        connected = session["connected"]
        result[name] = {
            "host": cfg.host,
            "port": cfg.port,
            "user": cfg.user,
            "connected": connected,
            "connected_since": session["connected_since"],
            "command_count": session["command_count"],
            "role": cfg.role,
            "description": cfg.description,
            "profile": cfg.profile,
            "host_key_pinned": bool(cfg.host_key_sha256),
            "config_read_path_count": len(cfg.config_read_paths),
            "config_write_path_count": len(cfg.config_write_paths),
            "allow_mutations": cfg.allow_mutations,
            "allow_arbitrary_commands": cfg.allow_arbitrary_commands,
        }
    return result


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def start_session(server: str) -> dict:
    """Open a persistent SSH session using an existing operator-configured alias."""
    _ensure_connected(server)
    return {"server": server, **app.ssh.connection_info(server)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def connect_server(server: str) -> dict:
    """Compatibility alias for start_session. New hosts are enrolled only through the operator CLI."""
    return start_session(server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def end_session(server: str) -> dict:
    """Close a cached SSH session. Verify remote completion before interrupting an active command."""
    connected = app.ssh.is_connected(server)
    app.ssh.disconnect(server)
    return {"server": server, "disconnected": connected}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def disconnect_server(server: str) -> dict:
    """Compatibility alias for end_session."""
    return end_session(server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def operation_journal(limit: int = 50, server: str | None = None,
                      event_type: str | None = None) -> dict:
    """Read bounded local metadata-only operation history; no command output or credentials are stored."""
    entries = app.journal.read(limit=limit, server=server, event_type=event_type)
    return {"success": True, "entries": entries, "count": len(entries)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def system_info(server: str) -> dict:
    """Get OS, uptime, CPU cores, load average, memory and swap usage for a server."""
    _ensure_connected(server)
    return system_info_impl(app.ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def disk_usage(server: str) -> dict:
    """Get disk and filesystem usage for a server."""
    _ensure_connected(server)
    return disk_usage_impl(app.ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_services(server: str, services: list[str] | None = None) -> dict:
    """Check systemd service status. Pass specific service names or omit for all running services."""
    _ensure_connected(server)
    return check_services_impl(app.ssh, server, services=services)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_ports(server: str) -> dict:
    """List all listening TCP ports and associated processes on a server."""
    _ensure_connected(server)
    return check_ports_impl(app.ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def process_list(server: str, sort_by: str = "cpu") -> dict:
    """List top processes sorted by CPU or memory usage. sort_by: 'cpu' or 'memory'."""
    _ensure_connected(server)
    return process_list_impl(app.ssh, server, sort_by=sort_by)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def execute_command(server: str, command: str, timeout: int | None = None) -> dict:
    """Execute arbitrary shell code. Disabled by default; requires both local permission flags and client approval."""
    _ensure_connected(server, mutation=True, arbitrary=True, operation="execute_command")
    return execute_command_impl(app.ssh, server, command, timeout=timeout)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def install_package(server: str, packages: list[str], update: bool = True) -> dict:
    """Install packages via apt on a remote server. Set update=False to skip apt update."""
    _ensure_connected(server, mutation=True, operation="install_package")
    return install_package_impl(app.ssh, server, packages=packages, update=update)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def manage_service(server: str, service: str, action: str) -> dict:
    """Manage a systemd service. action: 'start', 'stop', 'restart', 'reload', 'enable', 'disable', 'status'."""
    _ensure_connected(server, mutation=action != "status", operation="manage_service")
    return manage_service_impl(app.ssh, server, service=service, action=action)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def edit_config(server: str, path: str, content: str | None = None, backup: bool = True) -> dict:
    """Read or atomically replace a regular config file. Writes require local permission; unique private backups are enabled by default."""
    _ensure_connected(server, mutation=content is not None, arbitrary=content is not None,
                      file_path=path, file_write=content is not None, operation="edit_config")
    return edit_config_impl(app.ssh, server, path=path, content=content, backup=backup)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def docker_ps(server: str, all_containers: bool = False) -> dict:
    """List Docker containers. Set all_containers=True to include stopped containers."""
    _ensure_connected(server)
    return docker_ps_impl(app.ssh, server, all_containers=all_containers)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def docker_logs(server: str, container: str, tail: int | None = None) -> dict:
    """Get logs from a Docker container. Use tail to limit number of lines."""
    _ensure_connected(server)
    return docker_logs_impl(app.ssh, server, container=container, tail=tail)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def docker_compose(server: str, action: str, path: str) -> dict:
    """Run docker compose action in a directory. action: 'up', 'down', 'restart', 'stop', 'start', 'ps', 'logs', 'pull', 'build'."""
    _ensure_connected(server, mutation=action not in {"ps", "logs"},
                      arbitrary=action not in {"ps", "logs"}, operation="docker_compose")
    return docker_compose_impl(app.ssh, server, action=action, path=path)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def docker_images(server: str) -> dict:
    """List Docker images on a server."""
    _ensure_connected(server)
    return docker_images_impl(app.ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_updates(server: str, security_only: bool = False) -> dict:
    """Read available updates from the existing apt cache without refreshing it. Results may be stale."""
    _ensure_connected(server)
    return check_updates_impl(app.ssh, server, security_only=security_only)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def firewall_status(server: str) -> dict:
    """Get UFW firewall status, default policies, and rules."""
    _ensure_connected(server)
    return firewall_status_impl(app.ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def security_audit(server: str) -> dict:
    """Run a comprehensive security audit: SSH config, auto-updates, failed logins, root users, world-writable files."""
    _ensure_connected(server)
    return security_audit_impl(app.ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def full_security_audit(server: str) -> dict:
    """Run a comprehensive security audit with scoring: SSH, firewall, users, network, filesystem, services, updates, logs, kernel, malware. Returns score, grade, findings, and markdown report."""
    _ensure_connected(server)
    return full_security_audit_impl(app.ssh, server)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def create_backup(server: str, source: str, dest_dir: str, name: str | None = None) -> dict:
    """Create a tar.gz backup of a directory. Auto-generates timestamped name if not provided."""
    _ensure_connected(server, mutation=True, operation="create_backup")
    return create_backup_impl(app.ssh, server, source=source, dest_dir=dest_dir, name=name)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def list_backups(server: str, path: str) -> dict:
    """List .tar.gz backup files in a directory with sizes and dates."""
    _ensure_connected(server)
    return list_backups_impl(app.ssh, server, path=path)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def check_cron(server: str, user: str | None = None) -> dict:
    """List cron jobs — user crontab and system /etc/cron.d/ entries."""
    _ensure_connected(server)
    return check_cron_impl(app.ssh, server, user=user)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
def generate_report(server: str) -> dict:
    """Generate a comprehensive markdown report: system info, disk usage, ports, services."""
    _ensure_connected(server)
    return generate_report_impl(app.ssh, server)
