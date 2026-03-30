from __future__ import annotations

import re

from agensysadmin.ssh_manager import SSHManager


def check_updates_impl(
    ssh: SSHManager,
    server: str,
    security_only: bool = False,
) -> dict:
    ssh.execute(server, "sudo apt-get update -qq", timeout=60)
    result = ssh.execute(server, "apt list --upgradable 2>/dev/null")

    packages = []
    for line in result.stdout.strip().split("\n"):
        if line.startswith("Listing") or not line.strip():
            continue
        match = re.match(r"^(\S+)/(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            name, source, version, arch = match.groups()
            if security_only and "security" not in source:
                continue
            packages.append({
                "name": name,
                "source": source,
                "version": version,
                "arch": arch,
            })

    return {
        "success": result.exit_code == 0,
        "update_count": len(packages),
        "packages": packages,
    }


def firewall_status_impl(ssh: SSHManager, server: str) -> dict:
    result = ssh.execute(server, "sudo ufw status verbose")

    if result.exit_code != 0:
        return {
            "success": False,
            "exit_code": result.exit_code,
            "stderr": result.stderr,
            "active": False,
            "rules": [],
        }

    lines = result.stdout.strip().split("\n")
    active = any("Status: active" in line for line in lines)

    default_incoming = ""
    default_outgoing = ""
    for line in lines:
        if "Default:" in line:
            match_in = re.search(r"(\w+)\s*\(incoming\)", line)
            match_out = re.search(r"(\w+)\s*\(outgoing\)", line)
            if match_in:
                default_incoming = match_in.group(1)
            if match_out:
                default_outgoing = match_out.group(1)

    rules = []
    in_rules = False
    for line in lines:
        if line.startswith("--"):
            in_rules = True
            continue
        if in_rules and line.strip():
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                action_parts = []
                from_source = "Anywhere"
                for i, p in enumerate(parts[1:], 1):
                    if p in ("Anywhere",) or re.match(r"\d+\.\d+\.\d+\.\d+", p):
                        from_source = " ".join(parts[i:])
                        break
                    action_parts.append(p)
                rules.append({
                    "port": port,
                    "action": " ".join(action_parts),
                    "from": from_source,
                })

    return {
        "success": True,
        "active": active,
        "default_incoming": default_incoming,
        "default_outgoing": default_outgoing,
        "rules": rules,
        "raw_output": result.stdout.strip(),
    }
