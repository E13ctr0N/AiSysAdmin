from __future__ import annotations

from datetime import datetime, timezone

from agensysadmin.ssh_manager import SSHManager
from agensysadmin.validation import (
    shell_quote,
    validate_absolute_path,
    validate_backup_name,
    validate_user_name,
)


_VALIDATE_BACKUP_DESTINATION_SCRIPT = r'''set -eu
source=$(readlink -f -- "$1")
dest_dir=$(readlink -m -- "$2")
if [ "$source" = / ]; then
  printf '%s\n' 'refusing to archive / into a descendant destination' >&2
  exit 64
fi
case "$dest_dir" in
  "$source"|"$source"/*)
    printf '%s\n' 'backup destination must not be the source or a descendant of it' >&2
    exit 64
    ;;
esac'''

_CREATE_ARCHIVE_SCRIPT = r'''set -eu
source=$1
dest=$2
dir=${dest%/*}
base=${dest##*/}
umask 077
tmp=$(mktemp "${dir}/.${base}.agensysadmin.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
tar czf "$tmp" -- "$source"
# A hard link in the destination directory publishes atomically and refuses to
# replace an existing final archive.  The temporary inode remains private.
ln -- "$tmp" "$dest"
rm -f -- "$tmp"
trap - EXIT'''

_SYSTEM_CRON_SCRIPT = r'''set -eu
found=0
for cron_file in /etc/crontab /etc/cron.d/*; do
  if [ -f "$cron_file" ]; then
    found=1
    cat -- "$cron_file"
  fi
done
exit 0'''


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
    preflight_result = ssh.execute_privileged(
        server,
        f"sh -c {shell_quote(_VALIDATE_BACKUP_DESTINATION_SCRIPT)} sh "
        f"{shell_quote(source)} {shell_quote(dest_dir)}",
    )
    if preflight_result.exit_code != 0:
        return {
            "success": False,
            "exit_code": preflight_result.exit_code,
            "stderr": preflight_result.stderr,
            "source": source,
        }
    mkdir_result = ssh.execute_privileged(server, f"mkdir -p -- {shell_quote(dest_dir)}")
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
    result = ssh.execute_privileged(
        server,
        f"sh -c {shell_quote(_CREATE_ARCHIVE_SCRIPT)} sh {shell_quote(source)} {shell_quote(dest_path)}",
        timeout=300,
    )

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "source": source,
        }

    size_result = ssh.execute_privileged(server, f"ls -lh -- {shell_quote(dest_path)}")
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
    user_cron_result = ssh.execute_privileged(server, f"LC_ALL=C crontab {user_flag} -l")

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

    expected_no_crontab = (
        user_cron_result.exit_code == 1
        and user_cron_result.stderr.strip().startswith("no crontab for ")
    )
    user_status = "no_crontab" if expected_no_crontab else (
        "complete" if user_cron_result.exit_code == 0 else "unknown"
    )
    system_cron_result = ssh.execute_privileged(
        server, f"LC_ALL=C sh -c {shell_quote(_SYSTEM_CRON_SCRIPT)}"
    )
    system_status = "complete" if system_cron_result.exit_code == 0 else "unknown"
    complete = user_status != "unknown" and system_status == "complete"

    return {
        "success": complete,
        "complete": complete,
        "user_cron_status": user_status,
        "system_cron_status": system_status,
        "user_cron": user_cron,
        "system_cron": system_cron_result.stdout.strip(),
    }
