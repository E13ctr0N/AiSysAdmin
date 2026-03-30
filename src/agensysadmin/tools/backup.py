from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager


def create_backup_impl(
    ssh: SSHManager,
    server: str,
    source: str,
    dest_dir: str,
    name: str | None = None,
) -> dict:
    ssh.execute(server, f"sudo mkdir -p {dest_dir}")

    if name:
        filename = f"{name}.tar.gz"
    else:
        basename = source.strip("/").replace("/", "-")
        filename = f"{basename}-$(date +%Y%m%d-%H%M%S).tar.gz"

    dest_path = f"{dest_dir}/{filename}"
    result = ssh.execute(server, f"sudo tar czf {dest_path} {source}", timeout=300)

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "source": source,
        }

    size_result = ssh.execute(server, f"ls -lh {dest_path}")
    size = ""
    if size_result.stdout.strip():
        parts = size_result.stdout.strip().split()
        if len(parts) >= 5:
            size = parts[4]

    return {
        "success": True,
        "path": dest_path,
        "source": source,
        "size": size,
        "duration_ms": result.duration_ms,
    }


def list_backups_impl(
    ssh: SSHManager,
    server: str,
    path: str,
) -> dict:
    result = ssh.execute(server, f"ls -lh {path}/*.tar.gz 2>/dev/null")

    if result.exit_code != 0 and result.stderr.strip():
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "backups": [],
        }

    backups = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 9:
            full_path = parts[-1]
            name = full_path.split("/")[-1]
            backups.append({
                "name": name,
                "size": parts[4],
                "date": f"{parts[5]} {parts[6]} {parts[7]}",
                "path": full_path,
            })

    return {"success": True, "backups": backups}


def check_cron_impl(
    ssh: SSHManager,
    server: str,
    user: str | None = None,
) -> dict:
    user_flag = f"-u {user}" if user else ""
    user_cron_result = ssh.execute(server, f"sudo crontab {user_flag} -l 2>/dev/null")

    user_cron = []
    for line in user_cron_result.stdout.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 5)
        if len(parts) >= 6:
            user_cron.append({
                "schedule": " ".join(parts[:5]),
                "command": parts[5],
            })

    system_cron_result = ssh.execute(server, "sudo cat /etc/cron.d/* 2>/dev/null")

    return {
        "success": True,
        "user_cron": user_cron,
        "system_cron": system_cron_result.stdout.strip(),
    }
