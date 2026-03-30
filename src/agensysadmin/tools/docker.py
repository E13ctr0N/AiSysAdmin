from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager


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
