import os
import pytest
from pathlib import Path
from agensysadmin.config import ServerConfig, load_config


@pytest.fixture
def config_dir(tmp_path):
    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text("""
servers:
  prod:
    host: 192.0.2.11
    port: 22
    user: admin
    key_env: PROD_SSH_KEY_PATH
  staging:
    host: 192.0.2.12
    port: 2222
    user: deploy
    password_env: STAGING_SSH_PASSWORD
""")
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PROD_SSH_KEY_PATH=/keys/prod_key\nSTAGING_SSH_PASSWORD=secret123\n"
    )
    return tmp_path


def test_load_config_returns_dict_of_server_configs(config_dir):
    servers = load_config(config_dir)
    assert "prod" in servers
    assert "staging" in servers
    assert isinstance(servers["prod"], ServerConfig)


def test_server_config_fields(config_dir):
    servers = load_config(config_dir)
    prod = servers["prod"]
    assert prod.host == "192.0.2.11"
    assert prod.port == 22
    assert prod.user == "admin"
    assert prod.key_path == "/keys/prod_key"
    assert prod.password is None


def test_server_config_password_auth(config_dir):
    servers = load_config(config_dir)
    staging = servers["staging"]
    assert staging.host == "192.0.2.12"
    assert staging.port == 2222
    assert staging.password == "secret123"
    assert staging.key_path is None


def test_load_config_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path)


def test_server_config_default_port(tmp_path):
    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text("""
servers:
  minimal:
    host: 192.0.2.13
    user: root
""")
    (tmp_path / ".env").write_text("")
    servers = load_config(tmp_path)
    assert servers["minimal"].port == 22


def test_secure_defaults_and_secret_repr():
    config = ServerConfig("test", "example.invalid", "admin", password="do-not-print")
    assert config.allow_mutations is False
    assert config.allow_arbitrary_commands is False
    assert config.allow_agent is False
    assert config.look_for_keys is False
    assert "do-not-print" not in repr(config)


@pytest.mark.parametrize("setting,value", [
    ("allow_mutations", '"false"'),
    ("allow_arbitrary_commands", '"true"'),
    ("allow_agent", "1"),
    ("look_for_keys", "null"),
    ("port", "true"),
    ("port", "0"),
    ("port", "65536"),
])
def test_rejects_ambiguous_security_settings(tmp_path, setting, value):
    (tmp_path / "servers.yaml").write_text(
        f"servers:\n  test:\n    host: example.invalid\n    user: admin\n    {setting}: {value}\n")
    with pytest.raises(ValueError):
        load_config(tmp_path)


def test_shell_permission_requires_mutation_permission(tmp_path):
    (tmp_path / "servers.yaml").write_text(
        "servers:\n  test:\n    host: example.invalid\n    user: admin\n    allow_arbitrary_commands: true\n")
    with pytest.raises(ValueError, match="require allow_mutations"):
        load_config(tmp_path)


def test_env_is_not_overwritten_and_password_not_interpolated(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_KEY_PATH", "/operator/key")
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    (tmp_path / "servers.yaml").write_text(
        "servers:\n  test:\n    host: example.invalid\n    user: admin\n"
        "    key_env: ADMIN_KEY_PATH\n    password_env: ADMIN_PASSWORD\n")
    (tmp_path / ".env").write_text("ADMIN_KEY_PATH=/project/key\nADMIN_PASSWORD='${ADMIN_KEY_PATH}'\n")
    config = load_config(tmp_path)["test"]
    assert config.key_path == "/operator/key"
    assert config.password == "${ADMIN_KEY_PATH}"
    assert os.environ["ADMIN_KEY_PATH"] == "/operator/key"
    assert "ADMIN_PASSWORD" not in os.environ


def test_missing_credential_fails_without_value_disclosure(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_ADMIN_KEY", raising=False)
    (tmp_path / "servers.yaml").write_text(
        "servers:\n  test:\n    host: example.invalid\n    user: admin\n    key_env: MISSING_ADMIN_KEY\n")
    with pytest.raises(ValueError, match="missing or empty"):
        load_config(tmp_path)


def test_custom_known_hosts_resolves_relative_to_config(tmp_path):
    (tmp_path / "servers.yaml").write_text(
        "servers:\n  test:\n    host: example.invalid\n    user: admin\n    known_hosts_path: trusted_hosts\n")
    assert load_config(tmp_path)["test"].known_hosts_path == str((tmp_path / "trusted_hosts").resolve())


@pytest.mark.parametrize("value", ['"false"', '"true"', "true", "1"])
def test_legacy_unknown_host_trust_cannot_be_enabled(tmp_path, value):
    (tmp_path / "servers.yaml").write_text(
        f"servers:\n  test:\n    host: example.invalid\n    user: operator\n    allow_unknown_host_key: {value}\n")
    with pytest.raises(ValueError, match="verified host keys"):
        load_config(tmp_path)


def test_local_config_metadata_and_sudo_refs_are_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_SUDO_PASSWORD", "not-a-real-password")
    (tmp_path / "servers.yaml").write_text(
        "servers:\n  test:\n    host: example.invalid\n    user: operator\n"
        "    role: Container host\n    description: Example only\n    profile: docker_host\n"
        "    sudo_password_env: TEST_SUDO_PASSWORD\n    known_hosts_file: ./trusted_hosts\n")
    config = load_config(tmp_path)["test"]
    assert config.role == "Container host" and config.profile == "docker_host"
    assert config.sudo_password == "not-a-real-password"
    assert "not-a-real-password" not in repr(config)
    assert config.known_hosts_path == str((tmp_path / "trusted_hosts").resolve())


@pytest.mark.parametrize("paths", ['"/etc/example"', '["/etc/../shadow"]', '["/etc/*"]', '["relative"]'])
def test_config_file_allowlists_require_exact_absolute_paths(tmp_path, paths):
    (tmp_path / "servers.yaml").write_text(
        f"servers:\n  test:\n    host: example.invalid\n    user: root\n    config_read_paths: {paths}\n")
    with pytest.raises(ValueError):
        load_config(tmp_path)
