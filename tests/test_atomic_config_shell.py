"""Execute the production POSIX script against temporary local files, without SSH/sudo."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from agensysadmin.tools.management import _ATOMIC_CONFIG_WRITE_SCRIPT


@pytest.fixture
def bash():
    executable = shutil.which("bash")
    if os.name == "nt":
        executable = r"C:\Program Files\Git\bin\bash.exe"
        if not Path(executable).is_file():
            pytest.skip("Git Bash unavailable")
    if not executable:
        pytest.skip("POSIX shell unavailable")
    return executable


def write_config(bash, target, data, backup=True, expected_bytes=None):
    return subprocess.run(
        [bash, "-c", _ATOMIC_CONFIG_WRITE_SCRIPT, "sh", target.as_posix(),
         "1" if backup else "0", str(len(data) if expected_bytes is None else expected_bytes)],
        input=data, capture_output=True, timeout=10,
    )


def test_atomic_write_preserves_exact_content_and_unique_backup(bash, tmp_path):
    target = tmp_path / "app ' $(inert).conf"
    target.write_bytes(b"original\n")
    content = b"TOKEN='secret'\nno trailing newline"
    result = write_config(bash, target, content)
    assert result.returncode == 0, result.stderr
    assert target.read_bytes() == content
    backup_lines = [line for line in result.stdout.decode().splitlines() if line.startswith("backup_path=")]
    assert len(backup_lines) == 1
    backup = Path(backup_lines[0].removeprefix("backup_path="))
    assert backup.parent == target.parent
    assert backup.read_bytes() == b"original\n"
    assert backup.name.startswith(".app ' $(inert).conf.agensysadmin-backup.")
    assert not Path(str(target) + ".bak").exists()
    assert not list(tmp_path.glob(".*.agensysadmin.*"))


def test_truncated_stdin_leaves_original_and_cleans_temp(bash, tmp_path):
    target = tmp_path / "app.conf"
    target.write_bytes(b"keep this")
    result = write_config(bash, target, b"partial", expected_bytes=100)
    assert result.returncode == 65
    assert target.read_bytes() == b"keep this"
    assert not list(tmp_path.glob(".*.agensysadmin.*"))


def test_create_requires_explicit_no_backup_and_allows_empty_file(bash, tmp_path):
    target = tmp_path / "new.conf"
    assert write_config(bash, target, b"new").returncode == 66
    assert not target.exists()
    result = write_config(bash, target, b"", backup=False)
    assert result.returncode == 0, result.stderr
    assert target.read_bytes() == b""
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o600


def test_nonregular_target_is_rejected(bash, tmp_path):
    target = tmp_path / "directory"
    target.mkdir()
    assert write_config(bash, target, b"content", backup=False).returncode == 64
    assert target.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="Linux filesystem metadata and symlink semantics")
def test_preserves_mode_refuses_target_symlink_and_leaves_planted_bak_alone(bash, tmp_path):
    target = tmp_path / "app.conf"
    target.write_bytes(b"old")
    target.chmod(0o640)
    xattr_name = b"user.agensysadmin-test"
    xattr_value = b"preserve-me"
    if not hasattr(os, "setxattr"):
        pytest.skip("extended attributes unavailable")
    try:
        os.setxattr(target, xattr_name, xattr_value)
    except OSError as error:
        pytest.skip(f"filesystem does not support test extended attributes: {error}")
    result = write_config(bash, target, b"new", backup=False)
    assert result.returncode == 0, result.stderr
    assert target.stat().st_mode & 0o777 == 0o640
    assert os.getxattr(target, xattr_name) == xattr_value
    victim = tmp_path / "victim"
    victim.write_bytes(b"unchanged")
    link = tmp_path / "link.conf"
    link.symlink_to(victim)
    assert write_config(bash, link, b"bad", backup=False).returncode == 64
    Path(str(target) + ".bak").symlink_to(victim)
    result = write_config(bash, target, b"bad")
    assert result.returncode == 0, result.stderr
    assert victim.read_bytes() == b"unchanged"
    assert Path(str(target) + ".bak").is_symlink()
    assert target.read_bytes() == b"bad"
