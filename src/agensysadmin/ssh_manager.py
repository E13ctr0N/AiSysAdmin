from __future__ import annotations

import time
import math
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
    def __init__(self, connect_timeout: int = 10, command_timeout: int = 30,
                 max_output_bytes: int = 2 * 1024 * 1024):
        self._connections: dict[str, paramiko.SSHClient] = {}
        self._configs: dict[str, ServerConfig] = {}
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        if type(max_output_bytes) is not int or max_output_bytes < 1:
            raise ValueError("max_output_bytes must be a positive integer")
        self.max_output_bytes = max_output_bytes

    def connect(self, config: ServerConfig) -> None:
        if config.name in self._connections:
            client = self._connections[config.name]
            transport = client.get_transport()
            if transport and transport.is_active() and self._configs.get(config.name) == config:
                return
            # Dead connection — clean up and reconnect
            self.disconnect(config.name)

        client = paramiko.SSHClient()
        try:
            # A custom trust file is exclusive: do not let unrelated user keys
            # override its pins. Never enroll a host key during a tool call.
            if config.known_hosts_path:
                client.load_host_keys(config.known_hosts_path)
            else:
                client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                hostname=config.host,
                port=config.port,
                username=config.user,
                key_filename=config.key_path,
                password=config.password,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                channel_timeout=self.connect_timeout,
                allow_agent=config.allow_agent,
                look_for_keys=config.look_for_keys,
            )
        except Exception:
            client.close()
            raise
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
        self, server_name: str, command: str, timeout: int | None = None,
        *, input_data: bytes | None = None,
    ) -> CommandResult:
        client = self._connections.get(server_name)
        if not client:
            raise ConnectionError(f"Not connected to server '{server_name}'")

        timeout = self.command_timeout if timeout is None else timeout
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError("timeout must be a number greater than 0 and at most 300 seconds")
        if not isinstance(command, str) or not command.strip() or "\x00" in command or len(command.encode("utf-8")) > 256 * 1024:
            raise ValueError("command must be non-empty, NUL-free and at most 256 KiB")
        if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > 256 * 1024):
            raise ValueError("input_data must be bytes and at most 256 KiB")
        start = time.monotonic()
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        channel = stdout.channel
        output = bytearray()
        errors = bytearray()
        stdin_closed = False
        try:
            if input_data is not None:
                stdin.write(input_data)
                stdin.flush()
            stdin.close()  # No interactive password prompts or commands waiting for input.
            stdin_closed = True
            while True:
                if time.monotonic() - start >= timeout:
                    raise TimeoutError("Remote command exceeded its time limit; remote completion is unknown")
                received = False
                # Drain both streams BEFORE requesting exit status. Otherwise a
                # full SSH receive window can deadlock a verbose command.
                for ready, read, target in (
                    (channel.recv_ready, channel.recv, output),
                    (channel.recv_stderr_ready, channel.recv_stderr, errors),
                ):
                    if ready():
                        chunk = read(32768)
                        target.extend(chunk)
                        received = True
                        if len(output) + len(errors) > self.max_output_bytes:
                            raise ValueError("Remote command output exceeded the configured limit; remote completion is unknown")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    exit_code = channel.recv_exit_status()
                    break
                if not received:
                    time.sleep(0.01)
            return CommandResult(
                stdout=output.decode("utf-8", errors="replace"),
                stderr=errors.decode("utf-8", errors="replace"),
                exit_code=exit_code,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        finally:
            channel.close()
            if not stdin_closed:
                stdin.close()
            stdout.close()
            stderr.close()
