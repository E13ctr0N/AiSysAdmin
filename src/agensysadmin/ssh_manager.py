from __future__ import annotations

import time
import math
import base64
import hashlib
import hmac
import secrets
import shlex
import threading
from pathlib import Path
from dataclasses import dataclass

import paramiko

from agensysadmin.config import ServerConfig, normalize_fingerprint


def host_key_sha256(key: paramiko.PKey) -> str:
    return base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")


class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Pin the handshake key before Paramiko sends authentication credentials."""
    def __init__(self, fingerprint: str):
        self.fingerprint = normalize_fingerprint(fingerprint)

    def missing_host_key(self, client, hostname, key):
        actual = "SHA256:" + host_key_sha256(key)
        if not hmac.compare_digest(actual, self.fingerprint):
            raise paramiko.SSHException("SSH host-key fingerprint mismatch")
        client.get_host_keys().add(hostname, key.get_name(), key)


# sudo may read a password or skip it because of cached/NOPASSWD authorization.
# The child consumes a separate random framing marker in either case, so a sudo
# password can never become the first line of a configuration-file payload.
_SUDO_INPUT_SCRIPT = '''IFS= read -r first || exit 65
if [ "$first" != "$1" ]; then IFS= read -r first || exit 65; fi
[ "$first" = "$1" ] || exit 65
exec sh -c "$2"'''


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    journal_warning: bool = False

    def to_dict(self) -> dict:
        result = {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }
        if self.journal_warning:
            result["journal_warning"] = True
        return result


class SSHManager:
    def __init__(self, connect_timeout: int = 10, command_timeout: int = 30,
                 max_output_bytes: int = 2 * 1024 * 1024,
                 *, journal=None, keepalive_interval: int = 30):
        self._connections: dict[str, paramiko.SSHClient] = {}
        self._configs: dict[str, ServerConfig] = {}
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        if type(max_output_bytes) is not int or max_output_bytes < 1:
            raise ValueError("max_output_bytes must be a positive integer")
        self.max_output_bytes = max_output_bytes
        if type(keepalive_interval) is not int or keepalive_interval < 0:
            raise ValueError("keepalive_interval must be a nonnegative integer")
        self.keepalive_interval = keepalive_interval
        self.journal = journal
        self._connected_since: dict[str, float] = {}
        self._command_counts: dict[str, int] = {}
        self._lock = threading.RLock()

    def connect(self, config: ServerConfig) -> None:
        with self._lock:
            self._connect(config)

    def _connect(self, config: ServerConfig) -> None:
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
            hosts = config.known_hosts_path or config.known_hosts_file
            if config.known_hosts_path and config.known_hosts_file and config.known_hosts_path != config.known_hosts_file:
                raise ValueError("Conflicting known-hosts paths")
            if config.host_key_sha256:
                if hosts:
                    raise ValueError("Choose fingerprint pinning OR a known-hosts file")
                # Leave both host-key caches empty. This guarantees the pin
                # policy runs during the handshake, including for hosts already
                # present in the operator's unrelated system known_hosts file.
                client.set_missing_host_key_policy(PinnedHostKeyPolicy(config.host_key_sha256))
            elif hosts:
                client.load_host_keys(str(Path(hosts).expanduser()))
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
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
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(self.keepalive_interval)
            self._record("ssh_connect", config.name, "success",
                         {"host_key_pinned": bool(config.host_key_sha256)})
        except Exception:
            client.close()
            raise
        self._connections[config.name] = client
        self._configs[config.name] = config
        self._connected_since[config.name] = time.time()
        self._command_counts[config.name] = 0

    def disconnect(self, server_name: str) -> None:
        with self._lock:
            client = self._connections.pop(server_name, None)
            if client:
                client.close()
            self._configs.pop(server_name, None)
            self._connected_since.pop(server_name, None)
            self._command_counts.pop(server_name, None)
            if client:
                self._record("ssh_disconnect", server_name, "success", {})

    def disconnect_all(self) -> None:
        for name in list(self._connections):
            self.disconnect(name)

    def is_connected(self, server_name: str) -> bool:
        client = self._connections.get(server_name)
        if not client:
            return False
        transport = client.get_transport()
        return transport is not None and transport.is_active()

    def connection_info(self, server_name: str) -> dict:
        with self._lock:
            return {"connected": self.is_connected(server_name),
                    "connected_since": self._connected_since.get(server_name),
                    "command_count": self._command_counts.get(server_name, 0)}

    def server_profile(self, server_name: str) -> str:
        config = self._configs.get(server_name)
        return config.profile if config else "generic"

    def _record(self, event: str, server: str, status: str, data: dict) -> None:
        if self.journal is not None:
            self.journal.record(event, server=server, status=status, data=data)

    def execute(
        self, server_name: str, command: str, timeout: int | None = None,
        *, input_data: bytes | None = None,
    ) -> CommandResult:
        if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > 256 * 1024):
            raise ValueError("input_data must be bytes and at most 256 KiB")
        return self._execute(server_name, command, timeout, input_data=input_data)

    def execute_privileged(self, server_name: str, command: str,
                           timeout: int | None = None, *, input_data: bytes | None = None) -> CommandResult:
        config = self._configs.get(server_name)
        if config is None or server_name not in self._connections:
            raise ConnectionError("No configured SSH connection")
        if not isinstance(command, str) or not command.strip() or "\x00" in command:
            raise ValueError("command must be non-empty and NUL-free")
        if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > 256 * 1024):
            raise ValueError("input_data must be bytes and at most 256 KiB")
        if not config.needs_sudo:
            return self._execute(server_name, command, timeout, input_data=input_data, privileged=True)
        if config.sudo_password is None:
            wrapped = "sudo -n -- sh -c " + shlex.quote(command)
            return self._execute(server_name, wrapped, timeout, input_data=input_data,
                                 privileged=True, log_command=command)
        password = config.sudo_password
        if not isinstance(password, str) or not password or any(c in password for c in "\r\n\x00") or len(password.encode("utf-8")) > 4096:
            raise ValueError("sudo password must be a non-empty single line of at most 4096 bytes")
        marker = "AGENSYSADMIN_" + secrets.token_hex(24)
        wrapped = "sudo -S -p '' -- sh -c " + shlex.quote(_SUDO_INPUT_SCRIPT) + " sh " + shlex.quote(marker) + " " + shlex.quote(command)
        framed = (password + "\n" + marker + "\n").encode("utf-8") + (input_data or b"")
        return self._execute(server_name, wrapped, timeout, input_data=framed,
                             privileged=True, log_command=command)

    def _execute(self, server_name: str, command: str, timeout: int | None = None,
                 *, input_data: bytes | None = None, privileged: bool = False,
                 log_command: str | None = None) -> CommandResult:
        client = self._connections.get(server_name)
        if not client:
            raise ConnectionError(f"Not connected to server '{server_name}'")

        timeout = self.command_timeout if timeout is None else timeout
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError("timeout must be a number greater than 0 and at most 300 seconds")
        if not isinstance(command, str) or not command.strip() or "\x00" in command or len(command.encode("utf-8")) > 256 * 1024:
            raise ValueError("command must be non-empty, NUL-free and at most 256 KiB")
        if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > 512 * 1024):
            raise ValueError("input_data must be bytes and at most 512 KiB")
        metadata = {"command_sha256": hashlib.sha256((log_command or command).encode("utf-8")).hexdigest(),
                    "privileged": privileged}
        # Journal admission precedes execution: unavailable journaling prevents
        # a new operation rather than silently losing its audit record.
        self._record("ssh_command_start", server_name, "started", metadata)
        start = time.monotonic()
        with self._lock:
            self._command_counts[server_name] = self._command_counts.get(server_name, 0) + 1
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        except Exception as error:
            self._record_failure(server_name, metadata, error, start)
            raise
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
            result = CommandResult(
                stdout=output.decode("utf-8", errors="replace"),
                stderr=errors.decode("utf-8", errors="replace"),
                exit_code=exit_code,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as error:
            self._record_failure(server_name, metadata, error, start)
            raise
        finally:
            channel.close()
            if not stdin_closed:
                stdin.close()
            stdout.close()
            stderr.close()
        try:
            self._record("ssh_command", server_name, "success" if result.exit_code == 0 else "failure",
                         {**metadata, "exit_code": result.exit_code, "duration_ms": result.duration_ms,
                          "stdout_bytes": len(output), "stderr_bytes": len(errors)})
        except OSError:
            # The command has already finished. Never turn a journal failure
            # into an ambiguous retry of a completed remote mutation.
            result.journal_warning = True
        return result

    def _record_failure(self, server: str, metadata: dict, error: Exception, started: float) -> None:
        # A failed command already has an admission record. Best-effort failure
        # metadata must not mask the original timeout/transport exception.
        if self.journal is None:
            return
        try:
            self._record("ssh_command", server, "failure", {
                **metadata, "error_type": type(error).__name__,
                "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
            })
        except (OSError, ValueError):
            pass
