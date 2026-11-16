# AgenSysAdmin

MCP server for AI-assisted Linux administration over SSH. Works with OpenAI/Codex, Anthropic, and other MCP-compatible clients to inspect and manage Ubuntu/Debian servers.

The server exposes 22 tools for monitoring, security audits, Docker, service management, backups, package updates, and controlled command execution. Remote mutations and arbitrary shell commands are disabled by default.

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Linux/Mac
pip install -e ".[dev]"
```

## Configuration

1. Copy `servers.yaml.example` to `servers.yaml` and edit with your server details.
2. Copy `.env.example` to `.env` and set SSH key paths or passwords. Existing process environment values take precedence. Loading this file does not modify the process environment; `${...}` in credentials is treated literally.
3. Independently verify each server's SSH host-key fingerprint through a trusted console or administrator, then enroll the verified public key in `~/.ssh/known_hosts` or the per-server `known_hosts_path`. For a non-default SSH port, use the OpenSSH `[host]:port` entry format. Unknown or changed keys are rejected; no automatic enrollment is offered. An unverified `ssh-keyscan` result is not proof of identity.
4. Keep `allow_mutations: false` and `allow_arbitrary_commands: false` for diagnostics. To permit managed changes, the operator must explicitly set `allow_mutations: true` for that server and restart the MCP process. Arbitrary `execute_command` additionally requires `allow_arbitrary_commands: true`. Never let an AI client edit these configuration files automatically as an approval shortcut.

```yaml
servers:
  staging:
    host: staging.example.invalid
    user: operator
    key_env: STAGING_SSH_KEY_PATH
    known_hosts_path: ~/.ssh/known_hosts
    allow_mutations: false
    allow_arbitrary_commands: false
```

`known_hosts_path` is relative to the configuration directory unless absolute; an explicit file is the exclusive trust store for that server. SSH-agent access and automatic private-key discovery are disabled by default; opt in separately with YAML booleans `allow_agent: true` or `look_for_keys: true` if needed. Missing explicitly referenced credentials fail rather than silently switching authentication methods. Configure `AGENSYSADMIN_CONFIG_DIR` in the MCP process environment to select a configuration directory explicitly, particularly for installed wheels.

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
| `execute_command` | Run shell code; requires both operator permission flags |
| `install_package` | Install packages through the detected package manager |
| `manage_service` | Start, stop, restart, enable, or disable systemd services |
| `edit_config` | Read or update a remote configuration file with optional backup |
| `docker_ps` / `docker_logs` / `docker_images` | Inspect Docker state |
| `docker_compose` | Run controlled Docker Compose actions |
| `check_updates` | Inspect system/security updates using existing apt metadata; no refresh |
| `firewall_status` | Inspect firewall configuration |
| `security_audit` | Run a focused server security audit |
| `full_security_audit` | Run the complete multi-category security audit |
| `create_backup` / `list_backups` | Create and inspect server backups |
| `check_cron` | Inspect scheduled jobs |
| `generate_report` | Generate a consolidated server report |

## Safety

- Keep `servers.yaml`, `.env`, SSH keys, passwords, and production addresses out of version control.
- Restrict local configuration/credential file access to the operator account (filesystem permissions or Windows ACLs). A process able to modify this configuration can change the policy.
- The MCP entry points enforce a per-server diagnostic policy before SSH connection: package installs, service changes, configuration writes, backup creation, Compose mutations, and arbitrary commands are denied unless opted in. Service `status`, configuration reads, and Compose `ps`/`logs` remain available. Tool annotations are hints for clients, not the authorization mechanism.
- Continue requiring explicit confirmation in your AI client for each remote change after opting in. Configuration opt-in is a capability grant, not human approval of every invocation; a model-supplied confirmation flag would not establish human consent. Authorization decisions are logged without commands, file content, or credentials; this is not a durable execution audit trail.
- Use a dedicated SSH account with the minimum permissions required for each server.
- This policy covers the MCP tool interface, not arbitrary Python code importing the internal helpers. Restrict sudo rules and filesystem access on the remote host as the actual privilege boundary; enabled mutation tools can modify sensitive system files.
- Remote output, logs, cron jobs and configuration files can contain secrets or malicious instructions. Treat them as untrusted data and review before sharing with an AI provider. Read-only tools do not guarantee confidentiality or zero resource usage.
- Commands are limited to 300 seconds and 2 MiB combined stdout/stderr. A timeout or output-limit error closes the channel; it does not prove that the remote process stopped or that a mutation was rolled back. Verify state before retrying. Configuration writes are limited to 256 KiB and sent through SSH stdin, keeping their contents out of the command line. Writes use same-directory temporary files, verify the byte count, preserve existing attributes and atomically replace the target; direct target symlinks are rejected. Backups use unique private files and return `backup_path`, leaving old backups untouched. Use trusted parent directories and separately verify platform-specific metadata such as SELinux labels.
- `docker_logs` defaults to 100 lines (maximum 10,000). Backup paths and other file operands must be absolute. New archives use private permissions and refuse to overwrite an existing archive; partial archives after a failed command require operator review. `list_backups.size` is a byte-count string, and its date uses `YYYY-MM-DD HH:MM`.
- Update checks/audits use the existing apt cache and do not run `apt-get update`. Their freshness is not verified; refresh separately as an approved change. Security audit scores are diagnostic heuristics, not a security certification. Failed checks return UNKNOWN rather than zero/empty safe-looking values. Full audit categories with a failed probe are conservatively marked incomplete and require retesting; full audits require Bash for pipeline error handling.
- SSH settings are read through `sshd -T -C` for the current SSH account/address; failures produce UNKNOWN. DNS-hostname Match rules, other accounts and daemon startup overrides still need separate verification.

See [security review and migration notes](docs/security-review-2026-11-16.md) before upgrading an existing installation. Existing configurations become diagnostic-only; SSH connectivity requires verified host keys.

## Tests

```bash
pytest tests/ -v
```
