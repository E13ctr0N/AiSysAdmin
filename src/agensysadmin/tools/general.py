from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager


def execute_command_impl(
    ssh: SSHManager,
    server: str,
    command: str,
    timeout: int | None = None,
) -> dict:
    result = ssh.execute(server, command, timeout=timeout)
    return result.to_dict()
