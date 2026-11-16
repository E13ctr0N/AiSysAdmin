"""Local operator configuration commands and the stdio MCP entry point."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path

from agensysadmin.config import ServerConfig, load_config, save_server
from agensysadmin.profiles import PROFILES


@contextmanager
def _enrollment_lock(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / ".agensysadmin-enrollment.lock"
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError("Another enrollment is active; review a stale lock manually before retrying") from None
    try:
        os.close(descriptor)
        yield
    finally:
        lock.unlink()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AgenSysAdmin MCP and operator-only configuration")
    parser.add_argument("--config-dir", type=Path,
                        default=Path(os.environ.get("AGENSYSADMIN_CONFIG_DIR") or Path.cwd()))
    commands = parser.add_subparsers(dest="command")
    config = commands.add_parser("config", help="Offline configuration management; never connects to SSH")
    operations = config.add_subparsers(dest="operation", required=True)
    validate = operations.add_parser("validate", help="Validate configuration without revealing credentials")
    validate.add_argument("--without-secrets", action="store_true", help="Validate schema and references without resolving credentials")
    add = operations.add_parser("add-server", help="Enroll or explicitly replace one server alias")
    add.add_argument("--name", required=True)
    add.add_argument("--host", required=True)
    add.add_argument("--user", required=True)
    add.add_argument("--port", type=int, default=22)
    add.add_argument("--role")
    add.add_argument("--description")
    add.add_argument("--profile", choices=sorted(PROFILES), default="generic")
    add.add_argument("--key-env")
    add.add_argument("--password-env")
    add.add_argument("--sudo-password-env")
    trust = add.add_mutually_exclusive_group()
    trust.add_argument("--host-key-sha256")
    trust.add_argument("--known-hosts-file")
    add.add_argument("--allow-agent", action="store_true")
    add.add_argument("--look-for-keys", action="store_true")
    add.add_argument("--allow-mutations", action="store_true")
    add.add_argument("--allow-arbitrary-commands", action="store_true")
    add.add_argument("--replace", action="store_true", help="Explicitly replace all fields for an existing alias")
    add.add_argument("--read-config-path", action="append", default=[], help="Allow one exact remote file for privileged reading")
    add.add_argument("--write-config-path", action="append", default=[], help="Allow one exact remote file for privileged replacement (also requires both permission flags)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    directory = args.config_dir.expanduser().resolve()
    if args.command is None:
        os.environ["AGENSYSADMIN_CONFIG_DIR"] = str(directory)
        from agensysadmin.server import mcp
        mcp.run()
        return 0
    try:
        if args.operation == "validate":
            servers = load_config(directory, resolve_credentials=not args.without_secrets)
            print(json.dumps({"valid": True, "server_count": len(servers),
                              "credentials_resolved": not args.without_secrets}))
            return 0
        config = ServerConfig(
            name=args.name, host=args.host, user=args.user, port=args.port,
            role=args.role, description=args.description, profile=args.profile,
            key_env=args.key_env, password_env=args.password_env,
            sudo_password_env=args.sudo_password_env,
            host_key_sha256=args.host_key_sha256,
            known_hosts_path=args.known_hosts_file,
            allow_agent=args.allow_agent, look_for_keys=args.look_for_keys,
            allow_mutations=args.allow_mutations,
            allow_arbitrary_commands=args.allow_arbitrary_commands,
            config_read_paths=tuple(args.read_config_path),
            config_write_paths=tuple(args.write_config_path),
        )
        with _enrollment_lock(directory):
            save_server(directory / "servers.yaml", args.name, config, replace=args.replace)
        print(json.dumps({"saved": True, "server": args.name,
                          "credentials": "environment variable references only",
                          "restart_required": True}))
        return 0
    except (ValueError, OSError):
        # User-controlled YAML and filesystem exceptions can contain secret text
        # or paths. Detailed values are intentionally not printed by this CLI.
        parser.exit(2, "Configuration operation failed. Check schema, credential references, trust settings, permissions and duplicate aliases.\n")

