from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import dotenv_values


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


def load_config(base_path: Path | str) -> dict[str, ServerConfig]:
    base_path = Path(base_path)
    servers_file = base_path / "servers.yaml"
    env_file = base_path / ".env"

    if not servers_file.exists():
        raise FileNotFoundError(f"servers.yaml not found in {base_path}")

    # Resolve only referenced credentials. Never overwrite process environment or
    # interpolate credentials containing '$' through other environment values.
    env = dotenv_values(env_file, interpolate=False) if env_file.exists() else {}

    with open(servers_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)

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

        def credential(env_name: object) -> str | None:
            if env_name is None:
                return None
            if not isinstance(env_name, str) or not env_name:
                raise ValueError(f"Server '{name}' credential reference must be an environment variable name")
            value = os.environ.get(env_name, env.get(env_name))
            if not value:
                raise ValueError(f"Server '{name}' credential variable '{env_name}' is missing or empty")
            return value

        key_path = credential(cfg.get("key_env"))
        password = credential(cfg.get("password_env"))

        known_hosts_path = cfg.get("known_hosts_path")
        if known_hosts_path is not None:
            if not isinstance(known_hosts_path, str) or not known_hosts_path.strip():
                raise ValueError(f"Server '{name}' known_hosts_path must be a non-empty path")
            hosts_path = Path(known_hosts_path).expanduser()
            if not hosts_path.is_absolute():
                hosts_path = base_path / hosts_path
            known_hosts_path = str(hosts_path.resolve())
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
            **flags,
        )

    return servers
