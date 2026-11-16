import json
from pathlib import Path

import pytest

from agensysadmin.cli import main
from agensysadmin.config import load_config


def enroll(directory, *extra):
    return main(["--config-dir", str(directory), "config", "add-server",
                 "--name", "staging", "--host", "example.invalid", "--user", "operator",
                 "--key-env", "STAGING_SSH_KEY", "--sudo-password-env", "STAGING_SUDO_PASSWORD", *extra])


def test_offline_enrollment_keeps_refs_and_defaults_private(tmp_path, capsys):
    assert enroll(tmp_path, "--role", "Container host", "--profile", "docker_host") == 0
    config = load_config(tmp_path, resolve_credentials=False)["staging"]
    assert config.key_env == "STAGING_SSH_KEY"
    assert config.sudo_password_env == "STAGING_SUDO_PASSWORD"
    assert config.profile == "docker_host"
    assert config.allow_mutations is False
    assert config.password is None and config.sudo_password is None
    assert main(["--config-dir", str(tmp_path), "config", "validate", "--without-secrets"]) == 0
    assert "credentials_resolved" in capsys.readouterr().out


def test_enrollment_does_not_overwrite_alias_without_operator_flag(tmp_path):
    enroll(tmp_path)
    before = (tmp_path / "servers.yaml").read_bytes()
    with pytest.raises(SystemExit) as error:
        enroll(tmp_path, "--profile", "vpn_node")
    assert error.value.code == 2
    assert (tmp_path / "servers.yaml").read_bytes() == before
    assert enroll(tmp_path, "--profile", "vpn_node", "--replace") == 0
    assert load_config(tmp_path, resolve_credentials=False)["staging"].profile == "vpn_node"


def test_explicit_shell_grant_requires_mutation_grant(tmp_path):
    with pytest.raises(SystemExit):
        enroll(tmp_path, "--allow-arbitrary-commands")
    assert not (tmp_path / "servers.yaml").exists()
    assert enroll(tmp_path, "--allow-mutations", "--allow-arbitrary-commands") == 0


def test_lock_and_symlink_do_not_clobber_files(tmp_path):
    (tmp_path / ".agensysadmin-enrollment.lock").write_text("in use")
    with pytest.raises(SystemExit):
        enroll(tmp_path)
    assert not (tmp_path / "servers.yaml").exists()


def test_cli_does_not_print_credential_values_on_validation_failure(tmp_path, monkeypatch, capsys):
    enroll(tmp_path)
    monkeypatch.delenv("STAGING_SSH_KEY", raising=False)
    (tmp_path / ".env").write_text("STAGING_SUDO_PASSWORD=EXAMPLE_VALUE_NOT_REAL\n")
    with pytest.raises(SystemExit):
        main(["--config-dir", str(tmp_path), "config", "validate"])
    captured = capsys.readouterr()
    assert "EXAMPLE_VALUE_NOT_REAL" not in captured.err + captured.out


def test_exact_file_allowlists_are_operator_enrollment_only(tmp_path):
    assert enroll(tmp_path, "--read-config-path", "/etc/example.conf",
                  "--write-config-path", "/etc/example.conf") == 0
    config = load_config(tmp_path, resolve_credentials=False)["staging"]
    assert config.config_read_paths == ("/etc/example.conf",)
    assert config.config_write_paths == ("/etc/example.conf",)
    assert config.allow_arbitrary_commands is False
