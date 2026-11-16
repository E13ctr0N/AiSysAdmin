from __future__ import annotations

import re
import shlex


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:-]*\Z")
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9@_.:-]*\Z")
_CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_USER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
_BACKUP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


def shell_quote(value: str) -> str:
    """Quote one remote POSIX shell operand.

    Newlines are valid configuration-file contents, so callers validate path and
    identifier operands separately. NUL cannot be represented by a shell word.
    """
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("value must not contain a NUL byte")
    return shlex.quote(value)


def validate_absolute_path(value: str, label: str = "path") -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"{label} must be an absolute path")
    _reject_control_characters(value, label)
    return value


def validate_package_name(value: str) -> str:
    return _validate_identifier(value, _PACKAGE_NAME, "package name")


def validate_service_name(value: str) -> str:
    return _validate_identifier(value, _SERVICE_NAME, "service name")


def validate_container_name(value: str) -> str:
    return _validate_identifier(value, _CONTAINER_NAME, "container name")


def validate_user_name(value: str) -> str:
    return _validate_identifier(value, _USER_NAME, "user name")


def validate_backup_name(value: str) -> str:
    return _validate_identifier(value, _BACKUP_NAME, "backup name")


def _validate_identifier(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"Invalid {label}: {value!r}")
    return value


def _reject_control_characters(value: str, label: str) -> None:
    if not isinstance(value, str) or _CONTROL_CHARACTERS.search(value):
        raise ValueError(f"{label} must not contain control characters")
