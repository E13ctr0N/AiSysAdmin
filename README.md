# AgenSysAdmin

MCP server for AI-assisted Linux administration over SSH. Works with OpenAI/Codex, Anthropic, and other MCP-compatible clients to inspect and manage Ubuntu/Debian servers.

The server exposes 21 tools for monitoring, security audits, Docker, service management, backups, package updates, and controlled command execution.

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Linux/Mac
pip install -e ".[dev]"
```

## Configuration

1. Copy `servers.yaml.example` to `servers.yaml` and edit with your server details.
2. Copy `.env.example` to `.env` and set SSH key paths or passwords.

## MCP Integration

Run the server with:

```bash
python -m agensysadmin
```

Use that command in any client that supports local MCP servers. Example configuration:

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "sysadmin": {
      "command": "python",
      "args": ["-m", "agensysadmin"],
      "cwd": "D:/AI/AgenSysAdmin"
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_servers` | List configured servers and connection status |
| `system_info` | OS, uptime, CPU, RAM, load average |
| `disk_usage` | Disk and filesystem usage |
| `check_services` | Systemd service status |
| `check_ports` | Listening TCP ports |
| `process_list` | Top processes by CPU/memory |
| `execute_command` | Run any shell command |
| `install_package` | Install packages through the detected package manager |
| `manage_service` | Start, stop, restart, enable, or disable systemd services |
| `edit_config` | Read or update a remote configuration file with optional backup |
| `docker_ps` / `docker_logs` / `docker_images` | Inspect Docker state |
| `docker_compose` | Run controlled Docker Compose actions |
| `check_updates` | Inspect available system and security updates |
| `firewall_status` | Inspect firewall configuration |
| `security_audit` | Run a focused server security audit |
| `full_security_audit` | Run the complete multi-category security audit |
| `create_backup` / `list_backups` | Create and inspect server backups |
| `check_cron` | Inspect scheduled jobs |
| `generate_report` | Generate a consolidated server report |

## Safety

- Keep `servers.yaml`, `.env`, SSH keys, passwords, and production addresses out of version control.
- Prefer read-only inspection tools before mutation tools.
- Require explicit confirmation in your AI client before package installation, service changes, configuration edits, backups, Docker Compose actions, or arbitrary commands.
- Use a dedicated SSH account with the minimum permissions required for each server.

## Tests

```bash
pytest tests/ -v
```
