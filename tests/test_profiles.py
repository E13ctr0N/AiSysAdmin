from unittest.mock import MagicMock

import pytest

from agensysadmin.profiles import PROFILES, forwarding_expected, profile_for
from agensysadmin.ssh_manager import CommandResult
from agensysadmin.tools.security import _audit_kernel, _compute_scores


def test_operator_profile_contract():
    assert PROFILES == {"generic", "vpn_node", "docker_host", "web", "database"}
    ssh = MagicMock()
    assert profile_for(ssh, "test") == "generic"
    ssh.server_profile.return_value = "vpn_node"
    assert profile_for(ssh, "test") == "vpn_node"
    ssh.server_profile.return_value = "invented"
    assert profile_for(ssh, "test") == "generic"


@pytest.mark.parametrize("profile,value,status", [("generic", "1", "INFO"), ("vpn_node", "1", "PASS"), ("docker_host", "1", "PASS"), ("web", "1", "WARN"), ("database", "0", "PASS")])
def test_forwarding_depends_on_profile(profile, value, status):
    ssh = MagicMock()
    ssh.server_profile.return_value = profile
    ssh.execute.return_value = CommandResult("net.ipv4.ip_forward = " + value, "", 0, 0)
    findings = _audit_kernel(ssh, "test")
    assert next(f for f in findings if f["check"] == "IP forwarding")["status"] == status
    if profile in {"vpn_node", "docker_host"}:
        assert not any("Disable: sysctl -w net.ipv4.ip_forward=0" in f["recommendation"] for f in findings)


def test_information_and_not_applicable_do_not_improve_security_score():
    findings = [{"severity": "info", "status": "NOT_APPLICABLE"}, {"severity": "info", "status": "INFO"}]
    result = _compute_scores({"optional": {"weight": 20, "findings": findings}})
    assert result["categories"]["optional"]["score"] is None
    assert result["score"] == 0
