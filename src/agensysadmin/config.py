from __future__ import annotations

import os
import re
import base64
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import dotenv_values
from agensysadmin.profiles import PROFILES
from agensysadmin.validation import validate_absolute_path


def _read_yaml(path: Path):
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeError):
        raise ValueError("Invalid YAML configuration; values are not included in this error") from None


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    user: str
    port: int = 22
    key_path: str | None = None
    password: str | None = field(default=None, repr=False)
    known_hosts_path: str | None = None
    allow_mutations: bool = False
    allow_arbitrary_commands: bool = False
    allow_agent: bool = False
    look_for_keys: bool = False
    role: str | None = None
    description: str | None = None
    profile: str = "generic"
    sudo_password: str | None = field(default=None, repr=False)
    host_key_sha256: str | None = None
    known_hosts_file: str | None = None  # Safe legacy spelling.
    key_env: str | None = None
    password_env: str | None = None
    sudo_password_env: str | None = None
    config_read_paths: tuple[str, ...] = ()
    config_write_paths: tuple[str, ...] = ()

    @property
    def needs_sudo(self) -> bool:
        return self.user != "root"


def normalize_fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("host_key_sha256 must be an OpenSSH SHA256 fingerprint")
    digest = value.removeprefix("SHA256:")
    try:
        decoded = base64.b64decode(digest + "=" * (-len(digest) % 4), validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("host_key_sha256 must be an OpenSSH SHA256 fingerprint") from None
    if len(decoded) != 32 or len(digest.rstrip("=")) != 43:
        raise ValueError("host_key_sha256 must contain a SHA256 digest")
    return "SHA256:" + base64.b64encode(decoded).decode("ascii").rstrip("=")


def load_config(base_path: Path | str, *, resolve_credentials: bool = True) -> dict[str, ServerConfig]:
    base_path = Path(base_path)
    servers_file = base_path / "servers.yaml"
    env_file = base_path / ".env"

    if not servers_file.exists():
        raise FileNotFoundError(f"servers.yaml not found in {base_path}")

    # Resolve only referenced credentials. Never overwrite process environment or
    # interpolate credentials containing '$' through other environment values.
    env = dotenv_values(env_file, interpolate=False) if env_file.exists() else {}

    data = _read_yaml(servers_file)

    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        raise ValueError("servers.yaml must contain a 'servers' mapping")

    servers: dict[str, ServerConfig] = {}
    for name, cfg in data.get("servers", {}).items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) or not isinstance(cfg, dict):
            raise ValueError("Each server must have a non-empty name and a mapping")
        for key in ("host", "user"):
            value = cfg.get(key)
            if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError(f"Server '{name}' requires a valid {key}")
        port = cfg.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"Server '{name}' port must be an integer from 1 to 65535")
        flags = {}
        for flag in ("allow_mutations", "allow_arbitrary_commands", "allow_agent", "look_for_keys"):
            value = cfg.get(flag, False)
            if type(value) is not bool:
                raise ValueError(f"Server '{name}' {flag} must be a YAML boolean")
            flags[flag] = value
        if flags["allow_arbitrary_commands"] and not flags["allow_mutations"]:
            raise ValueError(f"Server '{name}' arbitrary commands require allow_mutations")
        legacy_unknown = cfg.get("allow_unknown_host_key", False)
        if type(legacy_unknown) is not bool or legacy_unknown:
            raise ValueError(f"Server '{name}' requires verified host keys; remove allow_unknown_host_key")
        profile = cfg.get("profile", "generic")
        if not isinstance(profile, str) or profile not in PROFILES:
            raise ValueError(f"Server '{name}' has an unsupported profile")
        for text_field in ("role", "description"):
            value = cfg.get(text_field)
            if value is not None and (not isinstance(value, str) or len(value) > 500 or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ValueError(f"Server '{name}' {text_field} must be a short single-line string")
        file_policy = {}
        for policy in ("config_read_paths", "config_write_paths"):
            paths = cfg.get(policy, [])
            if not isinstance(paths, list) or len(paths) > 100:
                raise ValueError(f"Server '{name}' {policy} must be a bounded list of exact absolute paths")
            for path in paths:
                validate_absolute_path(path, policy)
                if ".." in path.split("/") or any(c in path for c in "*?[]") or path.endswith("/"):
                    raise ValueError(f"Server '{name}' {policy} requires exact file paths without traversal or globs")
            file_policy[policy] = tuple(paths)

        def credential(env_name: object) -> str | None:
            if env_name is None:
                return None
            if not isinstance(env_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
                raise ValueError(f"Server '{name}' credential reference must be an environment variable name")
            if not resolve_credentials:
                return None
            value = os.environ.get(env_name, env.get(env_name))
            if not value:
                raise ValueError(f"Server '{name}' credential variable '{env_name}' is missing or empty")
            return value

        key_path = credential(cfg.get("key_env"))
        password = credential(cfg.get("password_env"))
        sudo_password = credential(cfg.get("sudo_password_env"))
        if sudo_password is not None and any(c in sudo_password for c in "\r\n\x00"):
            raise ValueError(f"Server '{name}' sudo password must be a single NUL-free line")

        if cfg.get("known_hosts_path") and cfg.get("known_hosts_file") and cfg["known_hosts_path"] != cfg["known_hosts_file"]:
            raise ValueError(f"Server '{name}' has conflicting known-hosts paths")
        known_hosts_path = cfg.get("known_hosts_path") or cfg.get("known_hosts_file")
        if known_hosts_path is not None:
            if not isinstance(known_hosts_path, str) or not known_hosts_path.strip():
                raise ValueError(f"Server '{name}' known_hosts_path must be a non-empty path")
            hosts_path = Path(known_hosts_path).expanduser()
            if not hosts_path.is_absolute():
                hosts_path = base_path / hosts_path
            known_hosts_path = str(hosts_path.resolve())
        fingerprint = normalize_fingerprint(cfg.get("host_key_sha256"))
        if fingerprint and known_hosts_path:
            raise ValueError(f"Server '{name}' must choose fingerprint pinning OR a known-hosts file")
        if key_path:
            key_path = os.path.expanduser(key_path)

        servers[name] = ServerConfig(
            name=name,
            host=cfg["host"],
            port=port,
            user=cfg["user"],
            key_path=key_path,
            password=password,
            known_hosts_path=known_hosts_path,
            role=cfg.get("role"),
            description=cfg.get("description"),
            profile=profile,
            sudo_password=sudo_password,
            host_key_sha256=fingerprint,
            key_env=cfg.get("key_env"),
            password_env=cfg.get("password_env"),
            sudo_password_env=cfg.get("sudo_password_env"),
            **file_policy,
            **flags,
        )

    return servers


def save_server(servers_file: Path, name: str, config: ServerConfig, *, replace: bool = False) -> None:
    """Operator-only enrollment. Persist credential references, never credentials.

    Caller must hold the configuration directory's enrollment lock. This function
    is deliberately not exposed as an MCP tool.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) or config.name != name:
        raise ValueError("Invalid server alias")
    if any((config.password, config.sudo_password, config.key_path)):
        raise ValueError("Enrollment accepts environment variable references, not credential values")
    servers_file = Path(servers_file)
    if servers_file.is_symlink():
        raise ValueError("Refusing to replace a symbolic-link configuration")
    data = _read_yaml(servers_file) if servers_file.exists() else {"servers": {}}
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        raise ValueError("Configuration must contain a servers mapping")
    if name in data["servers"] and not replace:
        raise ValueError("Server alias already exists; explicit --replace is required")
    entry = {"host": config.host, "user": config.user, "port": config.port,
             "profile": config.profile, "allow_mutations": config.allow_mutations,
             "allow_arbitrary_commands": config.allow_arbitrary_commands,
             "allow_agent": config.allow_agent, "look_for_keys": config.look_for_keys}
    for key in ("role", "description", "key_env", "password_env", "sudo_password_env", "host_key_sha256"):
        value = getattr(config, key)
        if value is not None:
            entry[key] = value
    entry["config_read_paths"] = list(config.config_read_paths)
    entry["config_write_paths"] = list(config.config_write_paths)
    hosts = config.known_hosts_path or config.known_hosts_file
    if hosts:
        entry["known_hosts_path"] = hosts
    data["servers"][name] = entry
    # Validate the complete candidate without resolving secrets or touching the
    # real config. Validation also catches ambiguous legacy policy settings.
    with tempfile.TemporaryDirectory(prefix="agensysadmin-validate-") as folder:
        candidate = Path(folder) / "servers.yaml"
        candidate.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        load_config(folder, resolve_credentials=False)
    descriptor, temporary = tempfile.mkstemp(prefix=".servers-", dir=servers_file.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(yaml.safe_dump(data, sort_keys=False))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, servers_file)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
