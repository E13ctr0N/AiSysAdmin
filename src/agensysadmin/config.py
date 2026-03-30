from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    user: str
    port: int = 22
    key_path: str | None = None
    password: str | None = None


def load_config(base_path: Path | str) -> dict[str, ServerConfig]:
    base_path = Path(base_path)
    servers_file = base_path / "servers.yaml"
    env_file = base_path / ".env"

    if not servers_file.exists():
        raise FileNotFoundError(f"servers.yaml not found in {base_path}")

    if env_file.exists():
        load_dotenv(env_file, override=True)

    with open(servers_file) as f:
        data = yaml.safe_load(f)

    servers: dict[str, ServerConfig] = {}
    for name, cfg in data.get("servers", {}).items():
        key_path = None
        password = None

        key_env = cfg.get("key_env")
        if key_env:
            key_path = os.environ.get(key_env)

        password_env = cfg.get("password_env")
        if password_env:
            password = os.environ.get(password_env)

        servers[name] = ServerConfig(
            name=name,
            host=cfg["host"],
            port=cfg.get("port", 22),
            user=cfg["user"],
            key_path=key_path,
            password=password,
        )

    return servers
