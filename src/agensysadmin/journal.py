"""A small, privacy-preserving local operation journal.

The journal intentionally records operational facts, not commands, output, host
names, addresses, or credentials.  It is suitable for local troubleshooting,
not for audit-grade cross-process logging.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_ERROR_TYPE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_UUID_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_MAX_LIMIT = 500
_DEFAULT_MAX_BYTES = 1024 * 1024

# ``error_type`` is deliberately included: a class/category such as
# ``TimeoutError`` helps diagnosis, while a raw error message often contains a
# hostname, command, or credential.
_METADATA_KEYS = frozenset(
    {
        "command_sha256",
        "privileged",
        "exit_code",
        "duration_ms",
        "stdout_bytes",
        "stderr_bytes",
        "connected_since",
        "command_count",
        "host_key_pinned",
        "error_type",
    }
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_label(value: str, name: str) -> str:
    if not isinstance(value, str) or not _LABEL_RE.fullmatch(value):
        raise ValueError(f"{name} must be a short identifier without control characters")
    return value


def _validate_optional_label(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    return _validate_label(value, name)


def sanitize_command(command: str) -> dict[str, str]:
    """Return only a stable command fingerprint; never retain the command."""
    if not isinstance(command, str):
        raise TypeError("command must be a string")
    return {"command_sha256": hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()}


class OperationJournal:
    """Bounded JSONL journal with per-process locking and conservative fields.

    On POSIX journal files are chmod'ed to ``0600``.  Windows ACLs are inherited
    from the journal directory, so callers should place it in a private user
    directory.
    """

    def __init__(self, path: Path | str, max_bytes: int = _DEFAULT_MAX_BYTES, backup_count: int = 3) -> None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 256:
            raise ValueError("max_bytes must be an integer of at least 256")
        if isinstance(backup_count, bool) or not isinstance(backup_count, int) or not 0 <= backup_count <= 99:
            raise ValueError("backup_count must be an integer between 0 and 99")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._assert_regular_or_missing(self.path):
            self._make_private(self.path)

    def record(
        self,
        event_type: str,
        server: str | None = None,
        status: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {"id": uuid4().hex, "ts": _utc_now(), "event_type": _validate_label(event_type, "event_type")}
        server = _validate_optional_label(server, "server")
        status = _validate_optional_label(status, "status")
        if server is not None:
            entry["server"] = server
        if status is not None:
            entry["status"] = status
        metadata = self._sanitize_metadata(data)
        if metadata:
            entry["data"] = metadata

        encoded = (json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise ValueError("journal entry exceeds max_bytes")
        with self._lock:
            self._assert_regular_or_missing(self.path)
            self._rotate_if_needed(len(encoded))
            # os.open gives the requested mode on creation; chmod also tightens
            # an existing journal created under a permissive umask.
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("journal path is not a regular file")
                self._make_private(self.path)
                with os.fdopen(descriptor, "ab", closefd=True) as journal_file:
                    journal_file.write(encoded)
                    journal_file.flush()
                    os.fsync(journal_file.fileno())
            except Exception:
                # fdopen closes the descriptor on normal context-manager exit;
                # close it here only if fdopen/write failed before that happens.
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
        return entry

    def read(
        self,
        limit: int = 50,
        server: str | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIMIT:
            raise ValueError(f"limit must be an integer between 1 and {_MAX_LIMIT}")
        server = _validate_optional_label(server, "server")
        event_type = _validate_optional_label(event_type, "event_type")
        # Never read an unbounded/possibly externally modified log.  A current
        # journal should be <= max_bytes, but twice that permits recovery from a
        # prior interrupted rotation while staying bounded.
        with self._lock:
            try:
                if not self._assert_regular_or_missing(self.path):
                    return []
                size = os.lstat(self.path).st_size
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self.path, flags)
                try:
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise OSError("journal path is not a regular file")
                    with os.fdopen(descriptor, "rb", closefd=True) as journal_file:
                        offset = max(0, size - (self.max_bytes * 2))
                        journal_file.seek(offset)
                        raw = journal_file.read(self.max_bytes * 2)
                except Exception:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    raise
            except FileNotFoundError:
                return []
        if offset:
            raw = raw.split(b"\n", 1)[1] if b"\n" in raw else b""

        entries: list[dict[str, Any]] = []
        for line in raw.splitlines():
            try:
                parsed = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                continue
            entry = self._safe_entry(parsed)
            if entry is None:
                continue
            if server is not None and entry.get("server") != server:
                continue
            if event_type is not None and entry.get("event_type") != event_type:
                continue
            entries.append(entry)
        return entries[-limit:]

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        try:
            if not self._assert_regular_or_missing(self.path):
                return
            current_size = os.lstat(self.path).st_size
        except FileNotFoundError:  # defensive against a concurrent external deletion
            return
        if current_size + incoming_bytes <= self.max_bytes:
            return
        for number in range(1, self.backup_count + 1):
            self._assert_regular_or_missing(self._backup_path(number))
        if self.backup_count == 0:
            self.path.unlink()
            return
        oldest = self._backup_path(self.backup_count)
        try:
            oldest.unlink()
        except FileNotFoundError:
            pass
        for number in range(self.backup_count - 1, 0, -1):
            source = self._backup_path(number)
            if source.exists():
                os.replace(source, self._backup_path(number + 1))
                self._make_private(self._backup_path(number + 1))
        os.replace(self.path, self._backup_path(1))
        self._make_private(self._backup_path(1))

    def _backup_path(self, number: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{number}")

    @staticmethod
    def _make_private(path: Path) -> None:
        if os.name != "nt":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def _assert_regular_or_missing(path: Path) -> bool:
        """Return whether *path* exists, refusing links and special files."""
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise OSError(f"journal path must be a regular file: {path}")
        return True

    @staticmethod
    def _sanitize_metadata(data: dict[str, Any] | None) -> dict[str, Any]:
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise TypeError("data must be a dictionary")
        cleaned: dict[str, Any] = {}
        command_hash = data.get("command_sha256")
        if isinstance(command_hash, str) and _SHA256_RE.fullmatch(command_hash):
            cleaned["command_sha256"] = command_hash.lower()
        for key in ("privileged", "host_key_pinned"):
            if isinstance(data.get(key), bool):
                cleaned[key] = data[key]
        exit_code = data.get("exit_code")
        if isinstance(exit_code, int) and not isinstance(exit_code, bool) and -1 <= exit_code <= 255:
            cleaned["exit_code"] = exit_code
        for key in ("duration_ms", "stdout_bytes", "stderr_bytes", "command_count"):
            value = data.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1:
                cleaned[key] = value
        connected_since = data.get("connected_since")
        if isinstance(connected_since, (int, float)) and not isinstance(connected_since, bool) and math.isfinite(connected_since) and connected_since >= 0:
            cleaned["connected_since"] = connected_since
        error_type = data.get("error_type")
        if isinstance(error_type, str) and _ERROR_TYPE_RE.fullmatch(error_type):
            cleaned["error_type"] = error_type
        return cleaned

    @classmethod
    def _safe_entry(cls, value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        try:
            entry_id = value["id"]
            timestamp = value["ts"]
            if not isinstance(entry_id, str) or not _UUID_HEX_RE.fullmatch(entry_id):
                return None
            if not cls._is_utc_timestamp(timestamp):
                return None
            entry: dict[str, Any] = {"id": entry_id.lower(), "ts": timestamp, "event_type": _validate_label(value["event_type"], "event_type")}
            for key in ("server", "status"):
                if key in value:
                    entry[key] = _validate_label(value[key], key)
        except (KeyError, ValueError, TypeError):
            return None
        if "data" in value and not isinstance(value["data"], dict):
            return None
        metadata = cls._sanitize_metadata(value.get("data"))
        if metadata:
            entry["data"] = metadata
        return entry

    @staticmethod
    def _is_utc_timestamp(value: Any) -> bool:
        if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
            return False
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            return False
        return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
