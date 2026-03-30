import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.docker import docker_ps_impl, docker_logs_impl


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestDockerPs:
    def test_docker_ps_running(self, mock_ssh):
        # --format output: tab-separated ID, Image, Status, Ports, Names
        mock_ssh.execute.return_value = CommandResult(
            stdout="a1b2c3d4e5f6\tnginx:latest\tUp 2 hours\t0.0.0.0:80->80/tcp\tweb\nf6e5d4c3b2a1\tpostgres:15\tUp 3 days\t5432/tcp\tdb\n",
            stderr="", exit_code=0, duration_ms=100,
        )

        result = docker_ps_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert len(result["containers"]) == 2
        assert result["containers"][0]["names"] == "web"
        assert result["containers"][0]["image"] == "nginx:latest"
        assert result["containers"][1]["names"] == "db"

    def test_docker_ps_all(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="a1b2c3d4e5f6\tnginx:latest\tUp 2 hours\t80/tcp\tweb\nb2c3d4e5f6a1\tredis:7\tExited (0) 5 hours ago\t\tcache\n",
            stderr="", exit_code=0, duration_ms=100,
        )

        result = docker_ps_impl(mock_ssh, "prod", all_containers=True)
        assert "docker ps -a" in mock_ssh.execute.call_args.args[1]
        assert len(result["containers"]) == 2

    def test_docker_ps_no_containers(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=50,
        )

        result = docker_ps_impl(mock_ssh, "prod")
        assert result["containers"] == []

    def test_docker_not_installed(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="bash: docker: command not found\n",
            exit_code=127, duration_ms=20,
        )

        result = docker_ps_impl(mock_ssh, "prod")
        assert result["success"] is False


class TestDockerLogs:
    def test_docker_logs_default(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="2026-03-31 10:00:00 [info] Starting nginx\n2026-03-31 10:00:01 [info] Ready\n",
            stderr="", exit_code=0, duration_ms=50,
        )
        result = docker_logs_impl(mock_ssh, "prod", container="web")
        assert result["success"] is True
        assert "Starting nginx" in result["logs"]
        assert "docker logs" in mock_ssh.execute.call_args.args[1]
        assert "web" in mock_ssh.execute.call_args.args[1]

    def test_docker_logs_with_tail(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="last line\n", stderr="", exit_code=0, duration_ms=50,
        )
        result = docker_logs_impl(mock_ssh, "prod", container="web", tail=10)
        assert "--tail 10" in mock_ssh.execute.call_args.args[1]

    def test_docker_logs_container_not_found(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="Error: No such container: missing\n",
            exit_code=1, duration_ms=20,
        )
        result = docker_logs_impl(mock_ssh, "prod", container="missing")
        assert result["success"] is False
