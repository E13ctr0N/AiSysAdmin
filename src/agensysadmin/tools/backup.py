from __future__ import annotations

from datetime import datetime, timezone

from agensysadmin.ssh_manager import SSHManager
from agensysadmin.validation import (
    shell_quote,
    validate_absolute_path,
    validate_backup_name,
    validate_user_name,
)


def create_backup_impl(
    ssh: SSHManager,
    server: str,
    source: str,
    dest_dir: str,
    name: str | None = None,
) -> dict:
    source = validate_absolute_path(source, "source")
    dest_dir = validate_absolute_path(dest_dir, "dest_dir")
    requested_name = validate_backup_name(name) if name is not None else None
    mkdir_result = ssh.execute(server, f"sudo -n mkdir -p -- {shell_quote(dest_dir)}")
    if mkdir_result.exit_code != 0:
        return {
            "success": False,
            "exit_code": mkdir_result.exit_code,
            "stderr": mkdir_result.stderr,
            "source": source,
        }

    if requested_name is not None:
        filename = f"{requested_name}.tar.gz"
    else:
        basename = source.strip("/").replace("/", "-")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"{basename}-{timestamp}.tar.gz"

    dest_path = f"{dest_dir}/{filename}"
    archive_script = 'umask 077; set -C; exec tar czf - -- "$1" > "$2"'
    result = ssh.execute(
        server,
        f"sudo -n sh -c {shell_quote(archive_script)} sh {shell_quote(source)} {shell_quote(dest_path)}",
        timeout=300,
    )

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "source": source,
        }

    size_result = ssh.execute(server, f"sudo -n ls -lh -- {shell_quote(dest_path)}")
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
    path = validate_absolute_path(path)
    result = ssh.execute(server, f"find {shell_quote(path)} -maxdepth 1 -type f -name '*.tar.gz' -printf '%s\\t%TY-%Tm-%Td %TH:%TM\\t%p\\n'")

    if result.exit_code != 0:
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
        parts = line.split("\t", 2)
        if len(parts) == 3:
            size_bytes, date, full_path = parts
            name = full_path.split("/")[-1]
            backups.append({
                "name": name,
                "size": size_bytes,
                "date": date,
                "path": full_path,
            })

    return {"success": True, "backups": backups}


def check_cron_impl(
    ssh: SSHManager,
    server: str,
    user: str | None = None,
) -> dict:
    user_flag = f"-u {shell_quote(validate_user_name(user))}" if user else ""
    user_cron_result = ssh.execute(server, f"sudo -n crontab {user_flag} -l 2>/dev/null")

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

    system_cron_result = ssh.execute(server, "sudo -n cat /etc/cron.d/* 2>/dev/null")

    return {
        "success": True,
        "user_cron": user_cron,
        "system_cron": system_cron_result.stdout.strip(),
    }
