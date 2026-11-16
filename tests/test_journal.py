from __future__ import annotations

import hashlib
import json
import os
import stat
import threading

import pytest

from agensysadmin.journal import OperationJournal, sanitize_command


def test_record_never_persists_payload_or_secrets(tmp_path):
    journal_path = tmp_path / "journal.jsonl"
    journal = OperationJournal(journal_path)
    secret = "ultra-secret-value"
    entry = journal.record(
        "command.finished",
        server="prod-1",
        status="failed",
        data={
            **sanitize_command("curl https://admin:password@example.test --header 'Bearer token'"),
            "duration_ms": 25,
            "error_type": "TimeoutError",
            "command": "rm -rf /",
            "stdout": secret,
            "password": secret,
            "authorization": "Bearer token-value",
            "api_key": "api-value",
            "url": "https://user:password@example.test",
            "pem": "-----BEGIN PRIVATE KEY-----",
            "nested": {"token": secret, "output": secret},
        },
    )

    raw = journal_path.read_text(encoding="utf-8")
    for forbidden in (secret, "Bearer", "api-value", "example.test", "BEGIN PRIVATE", "rm -rf"):
        assert forbidden not in raw
    assert entry["data"] == {
        "command_sha256": hashlib.sha256(
            b"curl https://admin:password@example.test --header 'Bearer token'"
        ).hexdigest(),
        "duration_ms": 25,
        "error_type": "TimeoutError",
    }


def test_metadata_filter_validation_and_malformed_lines(tmp_path):
    journal_path = tmp_path / "journal.jsonl"
    journal = OperationJournal(journal_path)
    journal.record("session.open", server="safe-alias", data={"privileged": True, "duration_ms": 1, "unknown": "drop"})
    with journal_path.open("a", encoding="utf-8") as file:
        file.write("not-json\n")
        file.write(json.dumps({"event_type": "bad", "data": {"password": "leak"}}) + "\n")
        file.write(json.dumps({"id": "Bearer private-token", "ts": "https://user:password@example.test", "event_type": "audit.done", "data": []}) + "\n")

    assert journal.read(server="safe-alias") == [
        {
            "id": journal.read()[0]["id"],
            "ts": journal.read()[0]["ts"],
            "event_type": "session.open",
            "server": "safe-alias",
            "data": {"privileged": True, "duration_ms": 1},
        }
    ]
    with pytest.raises(ValueError):
        journal.record("x\nno")
    with pytest.raises(ValueError):
        journal.read(limit=True)
    with pytest.raises(ValueError):
        journal.read(limit=501)


def test_read_refuses_symlink_journal_files(tmp_path):
    target = tmp_path / "sensitive-target"
    target.write_text("do not touch", encoding="utf-8")
    journal_path = tmp_path / "journal.jsonl"
    journal = OperationJournal(journal_path)
    try:
        journal_path.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable for this test environment")

    with pytest.raises(OSError):
        journal.read()
    with pytest.raises(OSError):
        journal.record("audit.done")
    assert target.read_text(encoding="utf-8") == "do not touch"


def test_rotation_recent_filter_and_bounded_backups(tmp_path):
    journal_path = tmp_path / "journal.jsonl"
    journal = OperationJournal(journal_path, max_bytes=350, backup_count=2)
    for number in range(20):
        journal.record("command.finished", server="one" if number % 2 else "two", data={"duration_ms": number})

    assert journal_path.stat().st_size <= 350
    assert (tmp_path / "journal.jsonl.1").exists()
    assert (tmp_path / "journal.jsonl.2").exists()
    assert not (tmp_path / "journal.jsonl.3").exists()
    latest = journal.read(limit=3, server="one", event_type="command.finished")
    assert len(latest) <= 3
    assert all(item["server"] == "one" for item in latest)


def test_concurrent_records_are_all_valid(tmp_path):
    journal = OperationJournal(tmp_path / "journal.jsonl")
    errors: list[Exception] = []

    def append(number: int) -> None:
        try:
            journal.record("audit.done", server="local", data={"command_count": number})
        except Exception as error:  # pragma: no cover - assertion below gives context
            errors.append(error)

    threads = [threading.Thread(target=append, args=(number,)) for number in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    entries = journal.read(limit=100, event_type="audit.done")
    assert len(entries) == 40
    assert {entry["data"]["command_count"] for entry in entries} == set(range(40))


@pytest.mark.skipif(os.name == "nt", reason="Windows uses inherited ACLs")
def test_journal_files_are_private_on_posix(tmp_path):
    journal_path = tmp_path / "journal.jsonl"
    journal = OperationJournal(journal_path, max_bytes=256, backup_count=1)
    for _ in range(4):
        journal.record("x", data={"duration_ms": 1})
    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "journal.jsonl.1").stat().st_mode) == 0o600
