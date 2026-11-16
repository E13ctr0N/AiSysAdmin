# AgenSysAdmin

MCP server for AI-assisted administration of Debian/Ubuntu hosts over SSH. The consolidated codebase keeps the local project's useful sessions, sudo support, role metadata, journal and extended audits while enforcing diagnostic-only defaults.

**27 MCP tools · 12 audit categories · operator-owned permissions · metadata-only history**

## Install

```text
python -m venv .venv
# Activate .venv for your platform, then:
python -m pip install -e ".[dev]"
```

Python 3.11+ is required. The MCP SDK stays on its compatible 1.x API. The `agensysadmin` console command is equivalent to `python -m agensysadmin`.

## Keep operational data private

Create a workspace outside this Git checkout using the [anonymized template](examples/private-workspace/README.md). Copy example configuration there as `servers.yaml` and `.env`. Protect the directory with operator-only permissions or Windows ACLs.

```text
python -m agensysadmin --config-dir /absolute/private/workspace config validate
python -m agensysadmin --config-dir /absolute/private/workspace
```

Use an absolute Python executable as the MCP client's stdio `command`, with `args` equivalent to:

```json
["-m", "agensysadmin", "--config-dir", "/absolute/private/workspace"]
```

This works independently of the launcher's working directory. `AGENSYSADMIN_CONFIG_DIR` is an alternative; without either setting, configuration comes from the current directory. Direct `agensysadmin.server:mcp` launchers should set the environment variable before import. Client-specific configuration wrappers differ.

Never publish real inventories, `.env`, SSH keys, logs, server notes, browser captures or downloaded executables. [Publication checks](scripts/check_publication.py) run in CI as an additional safeguard, not a comprehensive secret detector.

## Trust, credentials and permissions

```yaml
servers:
  staging:
    host: staging.example.invalid
    user: operator
    key_env: STAGING_SSH_KEY_PATH
    role: Example container host
    profile: docker_host
    known_hosts_path: ~/.ssh/known_hosts
    allow_mutations: false
    allow_arbitrary_commands: false
    config_read_paths: []
    config_write_paths: []
    # sudo_password_env: STAGING_SUDO_PASSWORD
```

Choose a verified `host_key_sha256` OR `known_hosts_path`. Verify the fingerprint through an independent trusted channel; unverified key discovery is not identity verification. Fingerprint pins are enforced before authentication. Explicit trust files are exclusive, and missing files fail. `known_hosts_file` is accepted as a safe legacy spelling; automatic trust is not supported. For a non-default SSH port use the OpenSSH `[host]:port` known-host entry format.

Credentials are resolved from named environment variables, with process environment taking precedence over the workspace `.env`. Loading does not mutate process environment or expand `${...}` inside passwords. Missing explicit references fail. SSH-agent and automatic-key discovery are opt-in via `allow_agent` and `look_for_keys`.

| Capability | Required operator settings |
| --- | --- |
| Structured diagnostics, service status, Compose ps/logs | Available by default; actual SSH/sudo permissions still apply |
| Privileged config-file read | Exact path in `config_read_paths` |
| Package/service changes and backup creation | `allow_mutations: true` |
| Direct shell commands and Compose mutations | Both permission flags |
| Config replacement | Both flags and exact path in `config_write_paths` |

File allowlists accept exact absolute POSIX file paths, without traversal or globs. Reads/writes reject direct symlinks and special files. Remote parent directories must be trusted. Restart the MCP process after changing local policy. Client per-action confirmation is still required for remote changes; a configuration grant is not human approval of every invocation.

These controls govern the MCP interface, not arbitrary Python callers or a privileged-account sandbox. Managed package/service administration is powerful. Restrict remote accounts and sudo permissions; do not grant broad sudo just to make every audit pass. Remote output can contain secrets or malicious instructions and must be treated as untrusted data.

## Enrollment and sessions

Enrolling hosts and changing trust are local operator operations, never model-supplied MCP arguments:

```text
python -m agensysadmin --config-dir /absolute/private/workspace config add-server --name staging --host staging.example.invalid --user operator --key-env STAGING_SSH_KEY_PATH --profile docker_host --known-hosts-file /absolute/private/known_hosts
```

Enrollment is offline and stores credential variable names only. `--replace` explicitly replaces an alias's complete configuration; re-specify required permissions and allowlists. `--read-config-path`/`--write-config-path` add exact file capabilities. CLI edits reserialize YAML; keep operational notes separately. `config validate --without-secrets` checks schema/references without resolving credentials.

`start_session` connects a configured alias; sessions use keepalive and expose connection time and per-session command counts. `end_session` closes it. `connect_server` and `disconnect_server` are compatibility aliases for those operations. `connect_server` no longer accepts raw hosts, passwords, trust overrides or `save=True`.

Root executes privileged operations directly, without requiring sudo installed. Non-root uses noninteractive sudo or an operator-configured `sudo_password_env`. Password and config stdin are separated by a framing marker so cached/NOPASSWD sudo cannot prepend a password to file content. Passwords never enter command arguments or the journal. Live sudo/PAM/TTY policies require staging verification.

## Tools and audits

| Area | Tools |
| --- | --- |
| Sessions/history | list_servers, start_session, end_session, connect_server, disconnect_server, operation_journal |
| Monitoring | system_info, disk_usage, check_services, check_ports, process_list |
| Administration | execute_command, install_package, manage_service, edit_config |
| Docker | docker_ps, docker_logs, docker_images, docker_compose |
| Security | security_audit, full_security_audit, check_updates, firewall_status |
| Backups/reports | create_backup, list_backups, check_cron, generate_report |

Full audit categories: SSH, firewall, users/auth, network, filesystem, services, updates, logs, kernel, malware, VPN/tunnels and Docker security. Profiles are `generic`, `vpn_node`, `docker_host`, `web`, and `database`; `role`/`description` are display metadata. Expected VPN software and forwarding are contextual rather than automatically insecure.

Docker inspection collects selected fields, excluding environment secrets, with bounded explicit coverage. VPN inventory covers TCP/UDP, IPv4/IPv6 and JSON interface kinds with custom names. Listener presence does not prove external reachability, TLS safety or authorization. TLS/Trivy/Lynis availability is inventory, not a completed vulnerability scan.

Findings distinguish PASS, WARN/FAIL, UNKNOWN and NOT_APPLICABLE. INFO/N_A do not improve scores. Incomplete categories are explicit; a category with no scored checks has `score=null`. Identical facts are reused within one full audit. Scores are heuristics, not security certification. Update inspection uses the existing apt cache without refreshing it. SSH settings use `sshd -T -C` with the SSH account/address gathered before elevation; DNS-hostname Match rules, other accounts and daemon startup overrides still need separate checks. Full audits require Bash/GNU/Linux tools and suitable permissions.

## Writes, backups and history

Commands have deadlines and a 2 MiB combined output bound. A timeout/output error closes the channel but does not prove remote termination or rollback: verify state before retrying. Config writes are bounded to 256 KiB and travel through SSH stdin. The writer verifies byte count, preserves available existing attributes and atomically replaces the file.

Config backups use unique private files and return `backup_path` plus `backup_metadata_path`. The sidecar records restoration metadata; ACL/xattr collection is best-effort when platform tools are available. Restore is a separately approved operation. Archives use private temporary files and publish only on success; existing archive names and destinations inside the source tree are rejected. Backup operands must be absolute. `list_backups.size` is a byte-count string. Docker logs default to 100 lines (maximum 10,000).

The journal stores operation types, aliases, timestamps, command hashes, result codes, durations and byte counts only. It never stores command text, stdout/stderr or credentials. Files rotate by size; reads are bounded to the current file and at most 500 entries. POSIX files use mode 0600; Windows uses inherited workspace ACLs. This is per-process troubleshooting history, not tamper-proof multi-process auditing. If a completed command returns `journal_warning=true`, do not retry it blindly.

## Validation and migration

```text
python -m pytest -q
python scripts/check_publication.py
python -m compileall -q src tests
python -m pip check
```

See [integration/migration notes](docs/local-integration.md), the [implementation plan](docs/plans/2026-11-16-local-integration.md), and the [initial security review](docs/security-review-2026-11-16.md). No production connections or deployment are required to run the synthetic tests.
