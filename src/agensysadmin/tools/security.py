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


def security_audit_impl(ssh: SSHManager, server: str) -> dict:
    root_login = ssh.execute(
        server, "sudo grep -i '^PermitRootLogin' /etc/ssh/sshd_config | tail -1"
    ).stdout.strip()
    root_login_val = root_login.split()[-1] if root_login else "unknown"

    password_auth = ssh.execute(
        server, "sudo grep -i '^PasswordAuthentication' /etc/ssh/sshd_config | tail -1"
    ).stdout.strip()
    password_auth_val = password_auth.split()[-1] if password_auth else "unknown"

    auto_updates = ssh.execute(
        server, "ls /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null"
    )
    auto_updates_enabled = auto_updates.exit_code == 0 and auto_updates.stdout.strip() != ""

    failed_logins = ssh.execute(
        server, "sudo grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0"
    )
    try:
        failed_count = int(failed_logins.stdout.strip())
    except ValueError:
        failed_count = 0

    root_users = ssh.execute(server, "awk -F: '$3 == 0 {print $1}' /etc/passwd")
    root_users_list = [u for u in root_users.stdout.strip().split("\n") if u.strip()]

    world_writable = ssh.execute(
        server, "sudo find /etc -type f -perm -o+w 2>/dev/null"
    )
    ww_files = [f for f in world_writable.stdout.strip().split("\n") if f.strip()]

    return {
        "success": True,
        "checks": {
            "ssh": {"root_login": root_login_val, "password_auth": password_auth_val},
            "auto_updates": {"enabled": auto_updates_enabled},
            "failed_logins": {"count": failed_count},
            "root_users": {"users": root_users_list},
            "world_writable": {"files": ww_files},
        },
    }
