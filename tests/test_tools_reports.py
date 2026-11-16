import pytest
from unittest.mock import MagicMock
from agensysadmin.ssh_manager import SSHManager, CommandResult
from agensysadmin.tools.reports import generate_report_impl
import agensysadmin.tools.reports as reports


@pytest.fixture
def mock_ssh():
    return MagicMock(spec=SSHManager)


class TestGenerateReport:
    def test_report_returns_markdown(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="Linux prod 5.15.0\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="up 14 days\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="              total\nMem:     8000000000  4000000000  2000000000  100000000  1900000000  3900000000\nSwap:    2000000000  0  2000000000\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="4\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="0.5 0.3 0.2 1/100 1234\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Filesystem Size Used Avail Use% Mounted\n/dev/sda1 50G 20G 28G 42% /\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
        ]
        result = generate_report_impl(mock_ssh, "prod")
        assert result["success"] is True
        assert "# Server Report: prod" in result["report"]
        assert "## System Info" in result["report"]
        assert "## Disk Usage" in result["report"]

    def test_report_includes_all_sections(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="Linux prod 5.15.0\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="up 1 day\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="              total\nMem:     8000000000  4000000000  2000000000  100000000  1900000000  3900000000\nSwap:    2000000000  0  2000000000\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="2\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="1.0 0.8 0.5 2/50 999\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Filesystem Size Used Avail Use% Mounted\n/dev/sda1 100G 80G 15G 85% /\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
        ]
        result = generate_report_impl(mock_ssh, "prod")
        report = result["report"]
        assert "## System Info" in report
        assert "## Disk Usage" in report
        assert "## Open Ports" in report
        assert "## Services" in report

    def test_report_format_is_string(self, mock_ssh):
        mock_ssh.execute.return_value = CommandResult(stdout="test\n", stderr="", exit_code=0, duration_ms=10)
        result = generate_report_impl(mock_ssh, "prod")
        assert isinstance(result["report"], str)

    def test_partial_report_is_not_success_and_sanitizes_error(self, mock_ssh, monkeypatch):
        secret = "password=should-not-appear"
        monkeypatch.setattr(reports, "system_info_impl", lambda *_: (_ for _ in ()).throw(RuntimeError(secret)))
        monkeypatch.setattr(reports, "disk_usage_impl", lambda *_: {"filesystems": []})
        monkeypatch.setattr(reports, "check_ports_impl", lambda *_: {"ports": []})
        monkeypatch.setattr(reports, "check_services_impl", lambda *_: {"raw_output": ""})

        result = generate_report_impl(mock_ssh, "prod")

        assert result["success"] is False
        assert result["complete"] is False
        assert result["section_status"]["system_info"] == "failed:RuntimeError"
        assert secret not in result["report"]
        assert "Unavailable (RuntimeError)." in result["report"]

    def test_report_marks_command_status_failure_incomplete(self, mock_ssh, monkeypatch):
        monkeypatch.setattr(reports, "system_info_impl", lambda *_: {"success": True})
        monkeypatch.setattr(reports, "disk_usage_impl", lambda *_: {"success": False, "error_type": "CommandUnavailable"})
        monkeypatch.setattr(reports, "check_ports_impl", lambda *_: {"success": True, "ports": []})
        monkeypatch.setattr(reports, "check_services_impl", lambda *_: {"success": True, "raw_output": ""})
        result = generate_report_impl(mock_ssh, "prod")
        assert result["success"] is False
        assert result["section_status"]["disk_usage"] == "failed:CommandUnavailable"
