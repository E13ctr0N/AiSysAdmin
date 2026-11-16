import json
from unittest.mock import MagicMock

import pytest

from agensysadmin.ssh_manager import CommandResult
from agensysadmin.tools.security_docker import _audit_docker_security, MAX_CONTAINERS


def result(value="", code=0):
    return CommandResult(value, "denied" if code else "", code, 0)


def container(number=1, **host):
    config = {"Privileged": False, "NetworkMode": "bridge", "PidMode": "", "CapAdd": None}
    config.update(host)
    return {"Id": f"{number:064x}", "Name": f"/test-{number}", "HostConfig": config, "Mounts": []}


def docker_ssh(objects=None, listeners="", inspect_override=None, deny=False):
    objects = [container()] if objects is None else objects
    ssh = MagicMock()
    def execute(server, command, timeout=None):
        if command == "command -v docker":
            return result("/usr/bin/docker")
        if command == "command -v trivy":
            return CommandResult("", "", 1, 0)
        if command == "ss -H -lntu":
            return result(listeners)
        raise AssertionError(command)
    def privileged(server, command, timeout=None):
        if deny:
            return result(code=1)
        if command.startswith("docker ps"):
            return result("\n".join(item["Id"] for item in objects))
        if command.startswith("docker inspect"):
            value = json.dumps(objects[:MAX_CONTAINERS]) if inspect_override is None else inspect_override
            return result(value)
        if command.startswith("set -e"):
            return result("")
        raise AssertionError(command)
    ssh.execute.side_effect = execute
    ssh.execute_privileged.side_effect = privileged
    return ssh


def test_pid_host_is_detected_independently_of_network_mode():
    ssh = docker_ssh([container(PidMode="host", NetworkMode="bridge")])
    findings = _audit_docker_security(ssh, "test")
    assert next(f for f in findings if f["check"] == "Host network/PID")["status"] == "WARN"


def test_more_than_twenty_containers_are_inspected_in_one_selected_field_batch():
    ssh = docker_ssh([container(i) for i in range(1, 26)])
    findings = _audit_docker_security(ssh, "test")
    coverage = next(f for f in findings if f["check"] == "Privileged containers")
    assert coverage["checked"] == coverage["total"] == 25
    assert coverage["complete"] is True
    calls = [call.args[1] for call in ssh.execute_privileged.call_args_list if call.args[1].startswith("docker inspect")]
    assert len(calls) == 1
    assert "Config.Env" not in calls[0]
    assert "{{json .}}" not in calls[0]


def test_container_limit_reports_partial_coverage():
    ssh = docker_ssh([container(i) for i in range(1, MAX_CONTAINERS + 2)])
    findings = _audit_docker_security(ssh, "test")
    coverage = next(f for f in findings if f["check"] == "Docker container coverage")
    assert coverage["status"] == "UNKNOWN"
    assert coverage["checked"] == MAX_CONTAINERS
    assert coverage["total"] == MAX_CONTAINERS + 1
    assert coverage["complete"] is False


@pytest.mark.parametrize("data", ["not json", "[]", '[{"Id":"missing-fields"}]'])
def test_bad_or_incomplete_inspect_is_unknown(data):
    findings = _audit_docker_security(docker_ssh(inspect_override=data), "test")
    assert next(f for f in findings if f["check"] == "Privileged containers")["status"] == "UNKNOWN"


def test_denied_daemon_access_never_reports_safe_container_state():
    findings = _audit_docker_security(docker_ssh(deny=True), "test")
    for finding in findings:
        if finding["check"] in {"Privileged containers", "Dangerous mounts", "Host network/PID", "Added capabilities", "Compose sensitive fields"}:
            assert finding["status"] == "UNKNOWN"


@pytest.mark.parametrize("address,status", [("127.0.0.1:2376", "INFO"), ("[::1]:2375", "INFO"), ("[::]:2376", "UNKNOWN"), ("0.0.0.0:2375", "UNKNOWN")])
def test_api_binding_does_not_invent_tls_or_external_reachability(address, status):
    ssh = docker_ssh(listeners=f"tcp LISTEN 0 0 {address} *:*\n")
    finding = next(f for f in _audit_docker_security(ssh, "test") if f["check"] == "Docker API exposure")
    assert finding["status"] == status
    assert finding["severity"] != "critical"
    assert finding["tls_verified"] is False


def test_absent_docker_is_not_applicable_not_safe_score():
    ssh = MagicMock()
    ssh.execute.return_value = CommandResult("", "", 1, 0)
    findings = _audit_docker_security(ssh, "test")
    assert findings[0]["status"] == "NOT_APPLICABLE"
    ssh.execute_privileged.assert_not_called()


def test_docker_host_profile_reports_missing_expected_runtime():
    ssh = MagicMock()
    ssh.server_profile.return_value = "docker_host"
    ssh.execute.return_value = CommandResult("", "", 1, 0)
    assert _audit_docker_security(ssh, "test")[0]["status"] == "WARN"
