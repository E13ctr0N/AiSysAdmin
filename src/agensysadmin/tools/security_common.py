from __future__ import annotations

import ipaddress
import json


def make_finding(severity: str, check: str, status: str, detail: str, recommendation: str = "", **metadata) -> dict:
    return {"severity": severity, "check": check, "status": status, "detail": detail,
            "recommendation": recommendation, **metadata}


def unknown(check: str, detail: str = "Probe failed or returned unrecognised data", **metadata) -> dict:
    return make_finding("warning", check, "UNKNOWN", detail,
                        "Check command availability and permissions before drawing a conclusion", **metadata)


def not_applicable(check: str, detail: str) -> dict:
    return make_finding("info", check, "NOT_APPLICABLE", detail)


def run(ssh, server: str, command: str, *, privileged: bool = False, timeout=None):
    method = ssh.execute_privileged if privileged else ssh.execute
    return method(server, command, timeout=timeout)


def json_result(result, expected_type):
    if result.exit_code != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, expected_type) else None


def listeners(text: str) -> list[dict] | None:
    """Parse ss -H -lntu: protocol/state/recv/send/local/peer. No process text."""
    found = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6 or parts[0] not in {"tcp", "udp", "tcp6", "udp6"}:
            return None
        endpoint = parts[4]
        if ":" not in endpoint:
            return None
        address, raw_port = endpoint.rsplit(":", 1)
        if not raw_port.isdecimal() or not 0 < int(raw_port) <= 65535:
            return None
        address = address.strip("[]")
        try:
            loopback = ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
        except ValueError:
            if address not in {"*", ""}:
                return None
            loopback = False
        found.append({"protocol": "udp" if parts[0].startswith("udp") else "tcp",
                      "address": address, "port": int(raw_port), "loopback": loopback})
    return found


def capability(ssh, server: str, binary: str):
    # Binary names are fixed application strings, never MCP arguments.
    result = run(ssh, server, "command -v " + binary)
    if result.exit_code == 0 and result.stdout.strip():
        return True
    if result.exit_code == 1 and not result.stderr.strip() and not result.stdout.strip():
        return False
    return None
