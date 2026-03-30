import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.monitoring import (
    system_info_impl,
    disk_usage_impl,
    check_services_impl,
    check_ports_impl,
    process_list_impl,
)


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestSystemInfo:
    def test_system_info_parses_output(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # uname -a
            CommandResult(
                stdout="Linux prod 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
            # uptime -p
            CommandResult(
                stdout="up 14 days, 3 hours, 22 minutes\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
            # free -b  (bytes for precision)
            CommandResult(
                stdout=(
                    "              total        used        free      shared  buff/cache   available\n"
                    "Mem:     8368730112  2147483648  4194304000   134217728  2027942464  5905580032\n"
                    "Swap:    2147483648           0  2147483648\n"
                ),
                stderr="", exit_code=0, duration_ms=10,
            ),
            # nproc
            CommandResult(
                stdout="4\n", stderr="", exit_code=0, duration_ms=10,
            ),
            # cat /proc/loadavg
            CommandResult(
                stdout="0.52 0.38 0.29 1/234 12345\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
        ]

        result = system_info_impl(mock_ssh, "prod")
        assert "Linux" in result["uname"]
        assert "up 14 days" in result["uptime"]
        assert result["cpu_cores"] == 4
        assert result["load_average"] == "0.52 0.38 0.29"
        assert "total" in result["memory"]
        assert "total" in result["swap"]


class TestDiskUsage:
    def test_disk_usage_parses_df(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        50G   20G   28G  42% /\n"
                "/dev/sdb1       100G   60G   35G  63% /data\n"
            ),
            stderr="", exit_code=0, duration_ms=15,
        )

        result = disk_usage_impl(mock_ssh, "prod")
        assert len(result["filesystems"]) == 2
        assert result["filesystems"][0]["mounted_on"] == "/"
        assert result["filesystems"][0]["use_percent"] == "42%"


class TestCheckServices:
    def test_check_services_with_list(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "nginx.service - A high performance web server\n"
                "   Loaded: loaded\n"
                "   Active: active (running) since Mon 2026-03-30 10:00:00 UTC\n"
            ),
            stderr="", exit_code=0, duration_ms=20,
        )

        result = check_services_impl(mock_ssh, "prod", services=["nginx"])
        assert "nginx" in result["services"]
        assert result["services"]["nginx"]["active"] is True

    def test_check_services_inactive(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "redis.service - Redis\n"
                "   Loaded: loaded\n"
                "   Active: inactive (dead)\n"
            ),
            stderr="", exit_code=3, duration_ms=20,
        )

        result = check_services_impl(mock_ssh, "prod", services=["redis"])
        assert result["services"]["redis"]["active"] is False

    def test_check_services_all(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "  UNIT                   LOAD   ACTIVE SUB     DESCRIPTION\n"
                "  nginx.service          loaded active running A high performance web server\n"
                "  ssh.service            loaded active running OpenBSD Secure Shell server\n"
            ),
            stderr="", exit_code=0, duration_ms=20,
        )

        result = check_services_impl(mock_ssh, "prod", services=None)
        assert result["raw_output"] is not None


class TestCheckPorts:
    def test_check_ports(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:((\"nginx\",pid=1234,fd=6))\n"
                "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=567,fd=3))\n"
            ),
            stderr="", exit_code=0, duration_ms=25,
        )

        result = check_ports_impl(mock_ssh, "prod")
        assert len(result["ports"]) == 2
        assert result["ports"][0]["port"] == 80
        assert result["ports"][0]["process"] == "nginx"


class TestProcessList:
    def test_process_list_by_cpu(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "  PID USER      %CPU %MEM    RSS COMMAND\n"
                " 1234 www-data  45.2  3.1  256000 nginx\n"
                " 5678 postgres  22.1 12.5 1024000 postgres\n"
            ),
            stderr="", exit_code=0, duration_ms=30,
        )

        result = process_list_impl(mock_ssh, "prod", sort_by="cpu")
        assert len(result["processes"]) == 2
        assert result["processes"][0]["pid"] == 1234
        assert result["processes"][0]["cpu_percent"] == 45.2

    def test_process_list_by_memory(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(
            stdout=(
                "  PID USER      %CPU %MEM    RSS COMMAND\n"
                " 5678 postgres  22.1 12.5 1024000 postgres\n"
                " 1234 www-data  45.2  3.1  256000 nginx\n"
            ),
            stderr="", exit_code=0, duration_ms=30,
        )

        result = process_list_impl(mock_ssh, "prod", sort_by="memory")
        assert result["processes"][0]["mem_percent"] == 12.5
