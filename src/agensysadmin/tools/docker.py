from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager

VALID_COMPOSE_ACTIONS = {"up", "down", "restart", "stop", "start", "ps", "logs", "pull", "build"}


def docker_ps_impl(
    ssh: SSHManager,
    server: str,
    all_containers: bool = False,
) -> dict:
    cmd = "docker ps -a" if all_containers else "docker ps"
    cmd += " --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}'"
    result = ssh.execute(server, cmd)

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "containers": [],
        }

    containers = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 5:
            containers.append({
                "id": parts[0],
                "image": parts[1],
                "status": parts[2],
                "ports": parts[3],
                "names": parts[4],
            })

    return {
        "success": True,
        "containers": containers,
    }


def docker_logs_impl(
    ssh: SSHManager,
    server: str,
    container: str,
    tail: int | None = None,
) -> dict:
    cmd = f"docker logs {container}"
    if tail is not None:
        cmd += f" --tail {tail}"
    result = ssh.execute(server, cmd)
    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "logs": result.stdout,
        "stderr": result.stderr,
        "container": container,
        "duration_ms": result.duration_ms,
    }


def docker_compose_impl(
    ssh: SSHManager,
    server: str,
    action: str,
    path: str,
) -> dict:
    if action not in VALID_COMPOSE_ACTIONS:
        raise ValueError(
            f"Invalid action '{action}'. Must be one of: {sorted(VALID_COMPOSE_ACTIONS)}"
        )
    action_cmd = f"{action} -d" if action == "up" else action
    cmd = f"cd {path} && docker compose {action_cmd}"
    result = ssh.execute(server, cmd, timeout=120)
    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "action": action,
        "path": path,
        "duration_ms": result.duration_ms,
    }
