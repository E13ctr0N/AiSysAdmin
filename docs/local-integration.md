# Local functionality consolidation and 0.2 migration

## Result

The integrated code preserves useful local workflows while retaining the GitHub
hardening. The original operational checkout, its uncommitted work, credentials
and private artifacts are not migration inputs for publication. Only selected
code, synthetic tests and anonymized instructions belong in this repository.

| Local capability | Integrated behavior |
| --- | --- |
| App state, role/description | Preserved; config directory is explicit and loading/journal creation is lazy |
| start/end/connect/disconnect session tools | All names retained, with one implementation per operation; connect uses configured alias only |
| Keepalive, session timestamps and command counts | Preserved; new sessions reset their own counts |
| Fingerprint pinning | Preserved and enforced before authentication, exclusive of other trust sources |
| known_hosts_file | Accepted as a legacy spelling of known_hosts_path; missing files fail |
| Root and password-based sudo | Preserved with bounded transport and separately framed config stdin |
| Operation journal | Preserved as bounded metadata-only history; raw commands/output are not transferred |
| VPN/Docker and extended host checks | 12 categories, role-aware interpretation, explicit partial/UNKNOWN/N_A results |
| Config backup | Unique private content plus restoration metadata, exact stdin, atomic file replacement |
| Ad-hoc host enrollment/save=True | Replaced by offline operator CLI; MCP cannot enroll hosts or alter trust/policy |
| Server baselines | An anonymized template is provided; real notes remain in an external private workspace |

## Migration checklist

1. Preserve the original operational workspace before upgrading. Keep actual
   inventories, `.env`, keys, notes and logs private; do not copy them into Git.
2. Install the integrated package in a dedicated Python environment. Launch with
   an absolute `--config-dir` or `AGENSYSADMIN_CONFIG_DIR`, particularly for direct
   module/MCP launchers. Cwd is the fallback, not the installed package directory.
3. Validate schema/references offline with `config validate --without-secrets`.
   Then validate credential resolution locally with `config validate`. Values
   are not printed. Existing environment takes precedence over `.env`; credential
   strings are no longer interpolated.
4. Choose a verified SHA256 pin OR one exclusive known-hosts file. Remove any
   `allow_unknown_host_key: true` or string-valued trust booleans. Unknown trust
   is never silently accepted. Do not automatically replace pins on mismatch.
5. Preserve `key_env`, `password_env` and optional `sudo_password_env` references.
   Root needs no sudo executable. Non-root requires actual sudo permission and
   a compatible PAM/TTY policy; credentials do not grant permission by themselves.
6. Start with both permission flags false and file allowlists empty. Grant exact
   read paths intentionally; config contents can contain secrets. Config writes
   need both flags and exact write paths. Compose mutations also need both flags
   because Compose can run code. Packages/services/backups require mutation
   permission. Keep client confirmation for each remote change.
7. Keep `role`/`description`; select the intended profile (`generic`, `vpn_node`,
   `docker_host`, `web`, `database`). Profiles guide interpretation, not automatic
   changes. Review expected network exposure and application requirements.
8. Replace legacy MCP calls supplying raw host/password/save with operator CLI
   enrollment and alias-based `connect_server`/`start_session`. Explicit
   `--replace` rewrites an alias's complete entry and reserializes YAML; review
   the resulting policy and restart the MCP process.
9. Keep new journal files separate from older raw-output logs. Rotation/read
   limits apply to current history. Metadata filtering is not a sanitizer for
   arbitrary old log archives. Protect Windows directories with private ACLs.

## Backup and recovery data

Configuration writes reject direct symlinks/nonregular files and assume trusted
parent directories. A successful backup returns `backup_path` and
`backup_metadata_path`. Both artifacts are private; metadata captures stat fields
and best-effort ACL/xattrs when tools are available, explicitly noting unavailable
sections. The metadata format is data, not shell code: never source/eval it.
Restoration needs a separately reviewed operation that verifies content,
ownership, permissions and platform-specific security labels.

Archive creation resolves remote canonical paths and rejects a destination equal
to or below its source, including symlink aliases. Whole-root archival is not
supported by this narrow tool. Tar writes a private temporary file; a hard-link
publishes the final name only after success and refuses overwrite. This requires
a compatible same-filesystem Linux destination. Failed/timeout operations do not
prove that all remote work stopped: verify state before retries.

## Audit interpretation and limits

Permission/tool/parse failures are UNKNOWN, not evidence of safety. Normal
negative predicates (e.g. no matching process) remain known results. Partial
container inspection reports checked/total/complete; it does not pass an unseen
inventory. Docker environment values and matching Compose secret values are not
collected. Profiles avoid recommending that a legitimate VPN/router disable its
required forwarding merely to improve a score.

INFO and NOT_APPLICABLE do not raise scores. A category without scored evidence
has score null; incomplete results remain explicit. An overall number is only a
heuristic and cannot replace the findings or measured application requirements.
TLS listener/scanner inventory is not proof of protocol safety or a CVE scan.
No scanners are installed or downloads started during diagnostics. Repeated
read-only facts are cached only within a full audit, not across later operations.

No production connection, enrollment, sudo-rule edit, deployment or restoration
is part of the consolidation. Live interoperability, distro-specific sudo/sshd
paths, ACL/xattr/SELinux behavior and client approval UI still require staging
verification with the operator's specific environment.

## Verification boundaries

Synthetic tests exercise policy composition before SSH, fingerprint mismatch
before authentication, sudo password-consumed/cached framing, exact/atomic file
writes, failure-atomic archives, journal privacy/rotation, audit coverage and
partial report behavior. Shell scripts run against temporary local files without
real SSH or sudo. Platform-specific metadata/symlink tests run on Linux CI.

The publication guard checks candidate paths and recognizable credential patterns.
It is supplementary protection, not proof that arbitrary material is safe to
publish. New operational material must stay in the private workspace regardless
of the guard's result.
