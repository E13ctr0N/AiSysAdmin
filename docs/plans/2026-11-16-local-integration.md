# Consolidate local functionality with GitHub hardening

## Objective and boundaries

Ship one maintainable codebase combining useful local operational features with
the safe defaults in PR #2. Work only in the GitHub checkout. The original local
working project remains untouched. Do not publish server inventories, credentials,
keys, operation logs, private baselines, browser captures or downloaded executables.
No production connections, deployments, migrations or policy enablement are part
of this work.

## Implementation sequence

1. Preserve session lifecycle, role/description metadata, keepalive and statistics.
   Retain compatibility names without duplicate session implementations.
2. Consolidate SSH trust before authentication, bounded transport and root-aware
   sudo. Retain password-based sudo without exposing passwords or config payloads
   in process arguments or mixing them into remote file contents.
3. Add a bounded metadata-only operation journal. Protect local files, rotate
   history, and avoid copying command output or credentials into logs.
4. Retain the 12 audit categories and useful host/Docker/VPN checks. Fix unknown
   and partial results, role-aware expectations, UDP/IPv6 coverage and Docker
   inspection. Keep diagnostics nonmutating.
5. Add operator-only CLI enrollment and configuration validation. MCP connects by
   configured alias; model arguments cannot enroll trust, supply credentials or
   overwrite trusted configuration. Support legacy safe config spellings through
   validation and explicit migration guidance.
6. Preserve atomic config writes, unique private backups and restoration metadata.
   Report partial reports honestly and provide an anonymized private-workspace
   template and portable MCP setup instructions.
7. Run focused tests, complete regression tests, wheel smoke tests, publication
   allowlist/secret checks and independent review. Update PR #2 around the final
   integrated behavior, then wait for Linux/Python CI.

## Acceptance criteria

- Existing useful local capabilities are present or have a documented safe
  replacement. No real configuration or operational data is copied to GitHub.
- Read-only defaults and separate arbitrary-command permission cannot be bypassed
  through MCP enrollment or session APIs.
- Host-key pinning fails before authentication; missing trust stores and ambiguous
  YAML booleans fail closed. Passwords are excluded from repr, logs and commands.
- Root works without sudo; non-root supports scoped passwordless sudo and explicit
  sudo credentials. File stdin remains exact even if sudo skips authentication.
- Audit failures never become safety passes; expected absence remains a known
  result. Profiles preserve legitimate VPN/router behavior.
- Session, journal, sudo-framing, file-write, audit and privacy regression tests
  pass, including the existing GitHub hardening suite.

## Deferred operational work

Real server enrollment, sudo-rule changes, live interoperability, production
backup restore and deployment need a separately scoped operational task. A web
dashboard, autonomous remediation and additional operating systems are outside
this consolidation.

## Local execution record

Steps 1–6 and local verification are complete in the consolidated 0.2 code.
Validation: 311 passed, 4 platform-specific Windows skips; wheel installation
and offline CLI enrollment/validation smoke passed; publication boundary,
compileall, dependency consistency and independent security review passed.
Linux/Python 3.11/3.12 CI is a required final check recorded on PR #2.

Review also strengthened exact file-read/write allowlists and broad-code grants
for config/Compose execution, failure-atomic nonrecursive archives, truthful cron
and report status, and unique private backup restoration metadata. The original
operational source files were verified unchanged after consolidation.
