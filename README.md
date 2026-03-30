# AgenSysAdmin

MCP server for remote Linux server administration via SSH. Integrates with Claude Code to manage Ubuntu/Debian servers.

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

## Claude Code Integration

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

## Tests

```bash
pytest tests/ -v
```
