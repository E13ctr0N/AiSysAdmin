from __future__ import annotations

from agensysadmin.ssh_manager import SSHManager
from agensysadmin.validation import (
    shell_quote,
    validate_absolute_path,
    validate_package_name,
    validate_service_name,
)

VALID_SERVICE_ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable", "status"}
MAX_CONFIG_CONTENT_BYTES = 256 * 1024
_SAFE_CONFIG_READ_SCRIPT = r'''set -eu
target=$1
if [ -L "$target" ]; then
  printf '%s\n' 'refusing to read symbolic-link config target' >&2
  exit 64
fi
if [ ! -f "$target" ]; then
  printf '%s\n' 'config target must be a regular file' >&2
  exit 64
fi
cat -- "$target"'''
_ATOMIC_CONFIG_WRITE_SCRIPT = r'''set -eu
target=$1
create_backup=$2
expected_bytes=$3
if [ -L "$target" ]; then
  printf '%s\n' "refusing to replace symbolic-link config target" >&2
  exit 64
fi
if [ -e "$target" ] && [ ! -f "$target" ]; then
  printf '%s\n' "config target must be a regular file" >&2
  exit 64
fi
dir=${target%/*}
base=${target##*/}
if [ "$dir" = "$target" ] || [ -z "$dir" ]; then dir=/; fi
umask 077
if [ "$create_backup" = 1 ]; then
  if [ ! -e "$target" ]; then
    printf '%s\n' "config target does not exist; disable backup to create it" >&2
    exit 66
  fi
  backup=$(mktemp "${dir}/.${base}.agensysadmin-backup.XXXXXX")
  if ! cat -- "$target" > "$backup"; then
    rm -f -- "$backup"
    exit 1
  fi
  # The content snapshot must remain private.  Keep restoration attributes in a
  # separate private sidecar so a future operator can restore them deliberately.
  metadata=$(mktemp "${dir}/.${base}.agensysadmin-backup-meta.XXXXXX")
  if ! (
    printf '%s\n' 'format=agensysadmin-config-backup-metadata-v1'
    printf 'target_path=%s\n' "$target"
    printf 'content_backup_path=%s\n' "$backup"
    printf '%s\n' '[stat]'
    stat --printf 'mode=%a\nuid=%u\ngid=%g\naccess_time=%x\nmodify_time=%y\nchange_time=%z\n' -- "$target" || exit 1
    if command -v getfacl >/dev/null 2>&1; then
      printf '%s\n' '[acl]'
      getfacl --absolute-names -- "$target" 2>/dev/null || printf '%s\n' 'unavailable=true'
    else
      printf '%s\n' '[acl-unavailable]'
    fi
    if command -v getfattr >/dev/null 2>&1; then
      printf '%s\n' '[xattrs]'
      getfattr --absolute-names --match=- -d -- "$target" 2>/dev/null || printf '%s\n' 'unavailable=true'
    else
      printf '%s\n' '[xattrs-unavailable]'
    fi
  ) > "$metadata"; then
    rm -f -- "$metadata" "$backup"
    exit 1
  fi
  printf 'backup_path=%s\n' "$backup"
  printf 'backup_metadata_path=%s\n' "$metadata"
fi
tmp=$(mktemp "${dir}/.${base}.agensysadmin.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
cat > "$tmp"
actual_bytes=$(wc -c < "$tmp")
if [ "$actual_bytes" -ne "$expected_bytes" ]; then
  printf '%s\n' "incomplete configuration input" >&2
  exit 65
fi
if [ -e "$target" ]; then
  cp --attributes-only --preserve=all -- "$target" "$tmp"
fi
mv -T -- "$tmp" "$target"
trap - EXIT'''


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

    service = validate_service_name(service)
    result = ssh.execute_privileged(
        server, f"systemctl --no-pager {action} -- {shell_quote(service)}"
    )

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
    if not packages:
        raise ValueError("At least one package is required")
    packages = [validate_package_name(package) for package in packages]

    if update:
        update_result = ssh.execute_privileged(server, "apt-get update -qq", timeout=60)
        if update_result.exit_code != 0:
            return {
                "success": False,
                "exit_code": update_result.exit_code,
                "stdout": update_result.stdout,
                "stderr": update_result.stderr,
                "packages": packages,
                "duration_ms": update_result.duration_ms,
            }

    pkg_list = " ".join(shell_quote(package) for package in packages)
    result = ssh.execute_privileged(
        server, f"apt-get install -y -- {pkg_list}", timeout=120
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
    path = validate_absolute_path(path)
    quoted_path = shell_quote(path)
    if content is None:
        result = ssh.execute_privileged(
            server,
            f"sh -c {shell_quote(_SAFE_CONFIG_READ_SCRIPT)} sh {quoted_path}",
        )
        return {
            "success": result.exit_code == 0,
            "exit_code": result.exit_code,
            "content": result.stdout,
            "stderr": result.stderr,
            "path": path,
        }

    content_bytes = _encode_config_content(content)

    result = ssh.execute_privileged(
        server,
        f"sh -c {shell_quote(_ATOMIC_CONFIG_WRITE_SCRIPT)} sh {quoted_path} {1 if backup else 0} {len(content_bytes)}",
        input_data=content_bytes,
    )
    backup_path = _extract_backup_path(result.stdout) if backup else None
    backup_metadata_path = _extract_backup_metadata_path(result.stdout) if backup else None

    return {
        "success": result.exit_code == 0,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "path": path,
        "backup_created": backup_path is not None,
        "backup_path": backup_path,
        "backup_metadata_path": backup_metadata_path,
        "duration_ms": result.duration_ms,
    }


def _encode_config_content(content: str | None) -> bytes:
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    if "\x00" in content:
        raise ValueError("content must not contain a NUL byte")
    try:
        encoded = content.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("content must be valid UTF-8") from error
    if len(encoded) > MAX_CONFIG_CONTENT_BYTES:
        raise ValueError("content must be at most 256 KiB")
    return encoded


def _extract_backup_path(stdout: str) -> str | None:
    for line in stdout.splitlines():
        if line.startswith("backup_path="):
            return validate_absolute_path(line.removeprefix("backup_path="), "backup_path")
    return None


def _extract_backup_metadata_path(stdout: str) -> str | None:
    for line in stdout.splitlines():
        if line.startswith("backup_metadata_path="):
            return validate_absolute_path(
                line.removeprefix("backup_metadata_path="), "backup_metadata_path"
            )
    return None
