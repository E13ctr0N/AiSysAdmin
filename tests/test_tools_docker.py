import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.docker import docker_ps_impl, docker_logs_impl, docker_compose_impl, docker_images_impl


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

    @pytest.mark.parametrize("container", ["web;id", "--tail", "$(id)"])
    def test_docker_logs_rejects_container_injection(self, mock_ssh, container):
        with pytest.raises(ValueError, match="container name"):
            docker_logs_impl(mock_ssh, "prod", container=container)
        mock_ssh.execute.assert_not_called()

    @pytest.mark.parametrize("tail", [-1, 10_001, "10", True])
    def test_docker_logs_bounds_tail(self, mock_ssh, tail):
        with pytest.raises(ValueError, match="tail"):
            docker_logs_impl(mock_ssh, "prod", container="web", tail=tail)

    def test_docker_logs_default_is_bounded(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1)
        docker_logs_impl(mock_ssh, "prod", container="web")
        assert "--tail 100" in mock_ssh.execute.call_args.args[1]

    def test_docker_logs_container_not_found(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="Error: No such container: missing\n",
            exit_code=1, duration_ms=20,
        )
        result = docker_logs_impl(mock_ssh, "prod", container="missing")
        assert result["success"] is False


class TestDockerCompose:
    def test_compose_up(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Creating network app_default\nCreating app_web_1\n",
            stderr="", exit_code=0, duration_ms=5000,
        )
        result = docker_compose_impl(mock_ssh, "prod", action="up", path="/opt/app")
        assert result["success"] is True
        cmd = mock_ssh.execute.call_args.args[1]
        assert "docker compose" in cmd
        assert "up -d" in cmd

    def test_compose_down(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Stopping app_web_1\n", stderr="", exit_code=0, duration_ms=3000,
        )
        result = docker_compose_impl(mock_ssh, "prod", action="down", path="/opt/app")
        assert result["success"] is True
        assert "down" in mock_ssh.execute.call_args.args[1]

    def test_compose_restart(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="Restarting\n", stderr="", exit_code=0, duration_ms=2000,
        )
        result = docker_compose_impl(mock_ssh, "prod", action="restart", path="/opt/app")
        assert "restart" in mock_ssh.execute.call_args.args[1]

    def test_compose_ps(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="NAME  IMAGE  SERVICE  STATUS\n", stderr="", exit_code=0, duration_ms=500,
        )
        result = docker_compose_impl(mock_ssh, "prod", action="ps", path="/opt/app")
        assert result["success"] is True

    def test_compose_invalid_action(self, mock_ssh):
        with pytest.raises(ValueError, match="Invalid action"):
            docker_compose_impl(mock_ssh, "prod", action="destroy", path="/opt/app")

    def test_compose_failure(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="no configuration file provided\n",
            exit_code=1, duration_ms=100,
        )
        result = docker_compose_impl(mock_ssh, "prod", action="up", path="/opt/missing")
        assert result["success"] is False

    @pytest.mark.parametrize("path", ["relative", "/opt/app\nnext"])
    def test_compose_rejects_unsafe_path(self, mock_ssh, path):
        with pytest.raises(ValueError):
            docker_compose_impl(mock_ssh, "prod", action="ps", path=path)
        mock_ssh.execute.assert_not_called()

    def test_compose_quotes_shell_metacharacters_in_path(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1)
        docker_compose_impl(mock_ssh, "prod", action="ps", path="/opt/app;id")
        assert "'/opt/app;id'" in mock_ssh.execute.call_args.args[1]

    def test_compose_quotes_path_with_spaces(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(stdout="", stderr="", exit_code=0, duration_ms=1)
        docker_compose_impl(mock_ssh, "prod", action="ps", path="/opt/my app")
        command = mock_ssh.execute.call_args.args[1]
        assert "cd -- '/opt/my app'" in command
        assert "docker compose ps" in command


class TestDockerImages:
    def test_docker_images(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="nginx\tlatest\ta1b2c3d4e5f6\t2 weeks ago\t142MB\npostgres\t15\tf6e5d4c3b2a1\t3 weeks ago\t379MB\n",
            stderr="", exit_code=0, duration_ms=80,
        )
        result = docker_images_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert len(result["images"]) == 2
        assert result["images"][0]["repository"] == "nginx"
        assert result["images"][0]["tag"] == "latest"
        assert result["images"][0]["size"] == "142MB"

    def test_docker_images_empty(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout="", stderr="", exit_code=0, duration_ms=50,
        )
        result = docker_images_impl(mock_ssh, "prod")
        assert result["images"] == []
