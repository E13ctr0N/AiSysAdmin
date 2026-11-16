# AiSysAdmin security review — 2026-11-16

This document records the initial hardening review. The consolidated 0.2
implementation adds sessions, root-aware sudo, metadata-only history, exact file
capabilities and extended audits. Its current behavior and migration requirements
are documented in [local integration notes](local-integration.md) and the README;
those supersede the initial upgrade snapshot below.

## Scope

Static review and local regression tests of the MCP entry points, SSH transport,
configuration loading, command builders, configuration writes, backups and SSH
audit. No production servers, credentials or customer data were accessed. This
review does not establish the current security of any remote installation.

## Findings addressed

| Finding | Change |
| --- | --- |
| Unknown SSH host keys were automatically trusted | Verified known-host entries and RejectPolicy; custom trust files are exclusive; failed connections are closed |
| Remote mutations depended only on instructions to the AI client | Per-server operator-owned permissions; mutations and arbitrary commands denied by default before SSH connection |
| Shell/option injection through package, service, container, user, path and backup parameters | Identifier validation, absolute-path checks, POSIX quoting, option separators and fixed action allowlists |
| Configuration contents appeared in remote command lines | Bounded UTF-8 content travels over SSH stdin; constant shell script uses positional metadata only |
| Configuration writes truncated files before completion | Same-directory temporary file, byte-count check, preserved attributes, atomic rename and cleanup; direct target symlinks and nonregular targets rejected |
| Predictable config backups could follow attacker-created symlinks | Unique private mktemp backup files; old backup paths remain untouched; exact new backup path returned |
| New backup files could be readable to other users or overwrite earlier archives | Private umask and exclusive shell redirection; existing archives are not overwritten |
| SSH output could deadlock before exit status; no effective overall read deadline/output bound | Interleaved stdout/stderr draining, deadline, combined output limit and channel cleanup |
| Inspection tools refreshed apt metadata | Existing-cache inspection only, explicit unverified freshness, failed update inspection is UNKNOWN |
| SSH audit guessed settings from the main config file | Effective `sshd -T -C` output for the current SSH account/IP, applying Includes and applicable Match rules; unavailable settings are UNKNOWN |
| Failed audit probes could appear as zero logins or no unsafe files | Unknown values are explicit; complete audit uses Bash pipefail and marks categories with failed probes incomplete |
| A fresh install selected incompatible MCP SDK 2.x | Bound dependency to the supported `mcp>=1.20,<2` API |
| Loading `.env` overwrote unrelated process values and could expand password strings | Local credential lookup, process-environment precedence, no credential interpolation or process-environment mutation; password excluded from dataclass repr |

## Upgrade behavior

- Existing server configurations become diagnostic-only. Set `allow_mutations`
  explicitly for managed changes; arbitrary shell also requires
  `allow_arbitrary_commands`. Restart the MCP process after configuration changes.
- The configuration file is trusted operator input. Protect it and credential
  files with local permissions/ACLs. AI-provided confirmation booleans are not a
  substitute for operator policy or the AI client's per-action approval.
- Independently verify SSH host-key fingerprints before enrolling public keys.
  Do not replace RejectPolicy with automatic trust to bypass connection failures.
- SSH agent and automatic key discovery are opt-in. Explicit missing credential
  references now fail. Relative `known_hosts_path` uses the configuration directory.
- Config paths must be absolute and refer to regular files for writes. Symlink
  targets are rejected rather than silently replacing or following them. Their
  parent directories and backup locations must be trusted and not writable by
  unrelated users. Existing attributes are preserved using GNU cp; platform-specific
  metadata such as ACLs/SELinux labels still needs staging validation on the target filesystem.
- Backup creation refuses an existing destination. Interrupted tar operations
  may leave partial archives for operator inspection. Config-write failure after
  backup creation can leave a valid unique backup; its exact `backup_path` is
  returned when the command reports it. A lost SSH connection can prevent receipt
  of that metadata even if the remote backup succeeded.
- Diagnostic tools can still reveal sensitive remote output and use CPU/network
  resources. Treat output as untrusted data. The MCP policy is not a sandbox for
  arbitrary Python callers importing internal helpers.
- Remote sudo is noninteractive. Use a dedicated account with narrowly scoped
  sudo rules; do not grant unrestricted sudo merely to make all audits pass.

## Limits and deferred work

Timeout/output-limit errors close the SSH channel but do not guarantee remote
termination, rollback or exactly-once execution. Verify remote state before
retrying. No automatic retry of mutations was introduced.

Audit probes require Bash on the Linux target to propagate pipeline errors. A
failed category is conservatively reported as UNKNOWN rather than scored from
partial evidence; it needs operator review and retesting. The SSH settings audit uses the current account/address context and the default
daemon configuration path. DNS-hostname Match rules, other accounts/connection
contexts, custom daemon `-f`/`-o` startup flags and settings not yet reloaded by the
running daemon need separate verification. Other security-score checks remain
heuristics and may be incomplete with restricted permissions; this is not a
security certification.

Real SSH interoperability, distro-specific sudo/sshd paths, production backup
restore, ACL/xattr/SELinux behavior, concurrent operators and live MCP-client
approval UX require a separately scoped staging exercise. No production
deployment or permission enablement is part of this change.

## Verification

```text
python -m pip install -e ".[dev]"
python -m pytest -q
python -m compileall -q src tests
python -m pip check
git diff --check
```

Tests cover denied operations before connection, explicit opt-in, malformed
policy settings, host-key verification, connection cleanup, output bounds,
deadlines, stdin transport, shell/option-injection attempts and local execution
of the atomic-write script against temporary files without SSH or sudo. Linux
CI additionally exercises filesystem mode and symlink semantics unavailable in
the Windows test environment.

A `pip-audit` scan of the freshly resolved development environment found no known
vulnerabilities after updating that virtual environment's pip. This is a dated
scan of resolved versions, not a guarantee for all versions allowed by dependency
ranges or for future vulnerabilities. The scanner is not a runtime dependency.

## References

- [Paramiko client trust and authentication APIs](https://docs.paramiko.org/en/stable/api/client.html)
- [Paramiko channel flow control and exit-status warning](https://docs.paramiko.org/en/stable/api/channel.html)
- [OpenSSH sshd test mode and connection contexts](https://man.openbsd.org/sshd.8)
