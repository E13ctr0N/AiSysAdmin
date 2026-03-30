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
    host: 10.0.0.1
    port: 22
    user: admin
    key_env: PROD_SSH_KEY_PATH
  staging:
    host: 10.0.0.2
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
    assert prod.host == "10.0.0.1"
    assert prod.port == 22
    assert prod.user == "admin"
    assert prod.key_path == "/keys/prod_key"
    assert prod.password is None


def test_server_config_password_auth(config_dir):
    servers = load_config(config_dir)
    staging = servers["staging"]
    assert staging.host == "10.0.0.2"
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
    host: 10.0.0.3
    user: root
""")
    (tmp_path / ".env").write_text("")
    servers = load_config(tmp_path)
    assert servers["minimal"].port == 22
