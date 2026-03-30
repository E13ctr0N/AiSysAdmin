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
