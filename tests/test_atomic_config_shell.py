"""Execute the production POSIX script against temporary local files, without SSH/sudo."""
import os
from pathlib import Path
import shlex
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


def write_config(bash, target, data, backup=True, expected_bytes=None, env=None):
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-c", _ATOMIC_CONFIG_WRITE_SCRIPT, "sh", target.as_posix(),
         "1" if backup else "0", str(len(data) if expected_bytes is None else expected_bytes)],
        input=data, capture_output=True, timeout=10, env=env,
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
    metadata_lines = [line for line in result.stdout.decode().splitlines() if line.startswith("backup_metadata_path=")]
    assert len(metadata_lines) == 1
    metadata = Path(metadata_lines[0].removeprefix("backup_metadata_path="))
    assert metadata.parent == target.parent
    assert "format=agensysadmin-config-backup-metadata-v1" in metadata.read_text()
    assert "content_backup_path=" + backup.as_posix() in metadata.read_text()
    assert not Path(str(target) + ".bak").exists()
    assert not list(tmp_path.glob(".*.agensysadmin.??????"))


def test_truncated_stdin_leaves_original_and_cleans_temp(bash, tmp_path):
    target = tmp_path / "app.conf"
    target.write_bytes(b"keep this")
    result = write_config(bash, target, b"partial", expected_bytes=100)
    assert result.returncode == 65
    assert target.read_bytes() == b"keep this"
    assert not list(tmp_path.glob(".*.agensysadmin.??????"))


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


@pytest.mark.skipif(os.name != "posix", reason="Linux filesystem metadata")
def test_backup_metadata_is_private_and_records_restore_attributes(bash, tmp_path):
    target = tmp_path / "app.conf"
    target.write_bytes(b"old")
    target.chmod(0o640)
    result = write_config(bash, target, b"new")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.decode().splitlines()
    backup = Path(next(line.removeprefix("backup_path=") for line in lines if line.startswith("backup_path=")))
    metadata = Path(next(line.removeprefix("backup_metadata_path=") for line in lines if line.startswith("backup_metadata_path=")))
    assert backup.stat().st_mode & 0o777 == 0o600
    assert metadata.stat().st_mode & 0o777 == 0o600
    record = metadata.read_text()
    assert f"target_path={target.as_posix()}" in record
    assert f"content_backup_path={backup.as_posix()}" in record
    assert "mode=640" in record
    assert "uid=" in record
    assert "gid=" in record


def test_metadata_capture_failure_cleans_private_artifacts_and_preserves_target(bash, tmp_path):
    target = tmp_path / "app.conf"
    target.write_bytes(b"original")
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    stat_shim = shim_dir / "stat"
    stat_shim.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    stat_shim.chmod(0o700)
    env = os.environ.copy()
    if os.name == "nt":
        shim_path = subprocess.check_output(
            [bash, "-c", "cygpath -u \"$1\"", "sh", str(shim_dir)], text=True
        ).strip()
    else:
        shim_path = str(shim_dir)
    bash_env = tmp_path / "bash_env"
    bash_env.write_text(
        f"PATH={shlex.quote(shim_path)}:$PATH\nexport PATH\n", encoding="utf-8"
    )
    env["BASH_ENV"] = str(bash_env)

    result = write_config(bash, target, b"replacement", env=env)

    assert result.returncode != 0
    assert target.read_bytes() == b"original"
    assert not list(tmp_path.glob(".app.conf.agensysadmin-backup.*"))
    assert not list(tmp_path.glob(".app.conf.agensysadmin-backup-meta.*"))
