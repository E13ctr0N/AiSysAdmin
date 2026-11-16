import json
from unittest.mock import MagicMock

import pytest

from agensysadmin.ssh_manager import CommandResult
from agensysadmin.tools.security_vpn import _audit_vpn


def result(value="", code=0):
    return CommandResult(value, "denied" if code else "", code, 0)


def test_all_failed_vpn_probes_are_unknown():
    ssh = MagicMock()
    ssh.execute.return_value = result(code=1)
    ssh.execute_privileged.return_value = result(code=1)
    assert all(f["status"] == "UNKNOWN" for f in _audit_vpn(ssh, "test"))


def test_udp_ipv6_and_custom_named_tunnel_are_detected_without_warning_on_vpn_node():
    ssh = MagicMock()
    ssh.server_profile.return_value = "vpn_node"
    ssh.execute.side_effect = [
        result("wireguard-tools\tii \nbase-files\tii \n"),
        result(json.dumps([{"ifname": "company-tunnel", "linkinfo": {"info_kind": "wireguard"}}])),
        result("udp UNCONN 0 0 [::]:51820 [::]:*\ntcp LISTEN 0 0 127.0.0.1:1194 0.0.0.0:*\n"),
    ]
    ssh.execute_privileged.return_value = result("/etc/wireguard/company.conf\n")
    findings = _audit_vpn(ssh, "test")
    assert all(f["status"] == "INFO" for f in findings)
    assert next(f for f in findings if f["check"] == "VPN network interfaces")["count"] == 1
    ports = next(f for f in findings if f["check"] == "VPN ports listening")
    assert ports["count"] == 2
    assert ports["protocols"] == ["tcp", "udp"]
    assert not any("cat" in call.args[1] for call in ssh.execute_privileged.call_args_list)


@pytest.mark.parametrize("links", ["bad-json", "{}", '[{"ifname": 3}]'])
def test_malformed_link_inventory_is_unknown(links):
    ssh = MagicMock()
    ssh.execute.side_effect = [result("base-files\tii \n"), result(links), result("")]
    ssh.execute_privileged.return_value = result("")
    findings = _audit_vpn(ssh, "test")
    assert next(f for f in findings if f["check"] == "VPN network interfaces")["status"] == "UNKNOWN"
