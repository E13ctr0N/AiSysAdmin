from __future__ import annotations

import time
from dataclasses import dataclass

import paramiko

from agensysadmin.config import ServerConfig


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int

    def to_dict(self) -> dict:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }


class SSHManager:
    def __init__(self, connect_timeout: int = 10, command_timeout: int = 30):
        self._connections: dict[str, paramiko.SSHClient] = {}
        self._configs: dict[str, ServerConfig] = {}
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout

    def connect(self, config: ServerConfig) -> None:
        if config.name in self._connections:
            client = self._connections[config.name]
            transport = client.get_transport()
            if transport and transport.is_active():
                return
            # Dead connection — clean up and reconnect
            client.close()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=config.host,
            port=config.port,
            username=config.user,
            key_filename=config.key_path,
            password=config.password,
            timeout=self.connect_timeout,
        )
        self._connections[config.name] = client
        self._configs[config.name] = config

    def disconnect(self, server_name: str) -> None:
        client = self._connections.pop(server_name, None)
        if client:
            client.close()
        self._configs.pop(server_name, None)

    def disconnect_all(self) -> None:
        for name in list(self._connections):
            self.disconnect(name)

    def is_connected(self, server_name: str) -> bool:
        client = self._connections.get(server_name)
        if not client:
            return False
        transport = client.get_transport()
        return transport is not None and transport.is_active()

    def execute(
        self, server_name: str, command: str, timeout: int | None = None
    ) -> CommandResult:
        client = self._connections.get(server_name)
        if not client:
            raise ConnectionError(f"Not connected to server '{server_name}'")

        timeout = timeout or self.command_timeout
        start = time.monotonic()
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        elapsed_ms = int((time.monotonic() - start) * 1000)

        return CommandResult(
            stdout=stdout.read().decode(),
            stderr=stderr.read().decode(),
            exit_code=exit_code,
            duration_ms=elapsed_ms,
        )
