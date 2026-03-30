from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager

VALID_SERVICE_ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable", "status"}


def manage_service_impl(
    ssh: SSHManager,
    server: str,
    service: str,
    action: str,
) -> dict:
    if action not in VALID_SERVICE_ACTIONS:
        raise ValueError(
            f"Invalid action '{action}'. Must be one of: {sorted(VALID_SERVICE_ACTIONS)}"
        )

    result = ssh.execute(server, f"sudo systemctl {action} {service}")

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "service": service,
        "action": action,
        "duration_ms": result.duration_ms,
    }


def install_package_impl(
    ssh: SSHManager,
    server: str,
    packages: list[str],
    update: bool = True,
) -> dict:
    if update:
        ssh.execute(server, "sudo apt-get update -qq", timeout=60)

    pkg_list = " ".join(packages)
    result = ssh.execute(
        server, f"sudo apt-get install -y {pkg_list}", timeout=120
    )

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "packages": packages,
        "duration_ms": result.duration_ms,
    }


def edit_config_impl(
    ssh: SSHManager,
    server: str,
    path: str,
    content: str | None = None,
    backup: bool = True,
) -> dict:
    if content is None:
        result = ssh.execute(server, f"sudo cat {path}")
        return {
            "success": result.exit_code == 0,
            "exit_code": result.exit_code,
            "content": result.stdout,
            "stderr": result.stderr,
            "path": path,
        }

    if backup:
        ssh.execute(server, f"sudo cp {path} {path}.bak")

    escaped_content = content.replace("'", "'\\''")
    result = ssh.execute(
        server, f"echo '{escaped_content}' | sudo tee {path} > /dev/null"
    )

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "path": path,
        "backup_created": backup,
        "duration_ms": result.duration_ms,
    }
