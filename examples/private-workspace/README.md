# Private operational workspace template

Copy this template outside the Git checkout. Rename `servers.yaml.example` to
`servers.yaml` and `.env.example` to `.env` only in that private directory. Keep
the directory readable only by the operator (POSIX permissions or Windows ACLs).
Never copy real data back into the examples directory.

```text
python -m agensysadmin --config-dir /absolute/private/workspace config validate
python -m agensysadmin --config-dir /absolute/private/workspace
```

For any MCP client, use its stdio transport with an absolute Python executable
as `command` and `args` equivalent to:

```json
["-m", "agensysadmin", "--config-dir", "/absolute/private/workspace"]
```

The Python environment must have AgenSysAdmin installed. This explicit path
does not depend on the client's working-directory behavior. Configure client
confirmation for remote mutations separately.

Use `list_servers`, then `start_session` with a configured alias. `connect_server`
is a compatibility alias for the same safe operation; it does not accept hosts,
passwords, trust flags or `save=True`. Enroll additional servers through the local
operator CLI:

```text
python -m agensysadmin --config-dir /absolute/private/workspace config add-server --name staging --host staging.example.invalid --user operator --key-env STAGING_SSH_KEY_PATH --profile docker_host --known-hosts-file /absolute/private/known_hosts
```

Verify host keys independently before enrollment. An explicit known-hosts file
must exist at connection time; alternatively enroll a verified SHA256 fingerprint
with `--host-key-sha256`. Choose one trust source. Duplicate aliases require
`--replace`, which replaces their complete configuration; re-specify any required
policy flags. Credential values are never accepted by enrollment arguments.

Private operational notes can follow `docs/servers/TEMPLATE.md`. Mark observations
with a date, separate expectations from measured facts, and keep credentials,
client identifiers and configuration contents out of the notes and journal.
