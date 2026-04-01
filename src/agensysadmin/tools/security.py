from __future__ import annotations

import re
from datetime import datetime, timezone

from agensysadmin.ssh_manager import SSHManager


def _make_finding(
    severity: str, check: str, status: str, detail: str, recommendation: str
) -> dict:
    return {
        "severity": severity,
        "check": check,
        "status": status,
        "detail": detail,
        "recommendation": recommendation,
    }


def _compute_scores(categories: dict) -> dict:
    summary = {"critical": 0, "warning": 0, "info": 0, "pass": 0}
    cat_scores = {}
    total_weight = 0

    for name, cat in categories.items():
        findings = cat["findings"]
        weight = cat["weight"]
        total_weight += weight

        has_critical = False
        pass_count = 0
        total_count = 0

        for f in findings:
            sev = f["severity"]
            summary[sev] = summary.get(sev, 0) + 1
            if sev == "critical":
                has_critical = True
            if sev == "pass":
                pass_count += 1
            total_count += 1

        if has_critical:
            cat_score = 0
        elif total_count == 0:
            cat_score = 100
        else:
            cat_score = int(pass_count / total_count * 100)

        cat_scores[name] = {"score": cat_score, "findings": findings}

    if total_weight == 0:
        overall = 0
    else:
        overall = int(
            sum(
                cat_scores[n]["score"] * categories[n]["weight"]
                for n in categories
            )
            / total_weight
        )

    if overall >= 90:
        grade = "A"
    elif overall >= 70:
        grade = "B"
    elif overall >= 50:
        grade = "C"
    elif overall >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": overall,
        "grade": grade,
        "summary": summary,
        "categories": cat_scores,
    }


def _format_report(
    hostname: str, ip: str, scores: dict, categories: dict
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Security Audit Report",
        f"**Server:** {hostname} ({ip})",
        f"**Date:** {timestamp}",
        f"**Score:** {scores['score']}/100 (Grade: {scores['grade']})",
        "",
        "## Summary",
        f"- Critical: {scores['summary']['critical']}",
        f"- Warning: {scores['summary']['warning']}",
        f"- Info: {scores['summary']['info']}",
        f"- Pass: {scores['summary']['pass']}",
        "",
    ]

    category_titles = {
        "ssh": "SSH",
        "firewall": "Firewall",
        "users": "Users & Auth",
        "network": "Network",
        "filesystem": "Filesystem",
        "services": "Services",
        "updates": "Updates",
        "logs": "Logs & Audit",
        "kernel": "Kernel & Sysctl",
        "malware": "Malware/Rootkit",
    }

    recommendations = []

    for name, cat in categories.items():
        cat_score = scores["categories"][name]["score"]
        title = category_titles.get(name, name.title())
        lines.append(f"## {title} (score: {cat_score}/100)")
        lines.append("")
        lines.append("| Status | Check | Detail |")
        lines.append("|---|---|---|")

        for f in cat["findings"]:
            lines.append(f"| {f['status']} | {f['check']} | {f['detail']} |")
            if f["recommendation"] and f["status"] != "PASS":
                tag = f["severity"].upper()
                recommendations.append(f"[{tag}] {f['recommendation']}")

        lines.append("")

    if recommendations:
        lines.append("## Recommendations")
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    return "\n".join(lines)


def _audit_firewall(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    fw_type = None
    for cmd, name in [("which ufw", "ufw"), ("which iptables", "iptables"), ("which nft", "nft")]:
        r = ssh.execute(server, cmd)
        if r.exit_code == 0 and r.stdout.strip():
            fw_type = name
            break

    if not fw_type:
        findings.append(_make_finding("critical", "Firewall installed and active", "FAIL", "No firewall found (ufw/iptables/nft)", "Install and configure ufw: apt install ufw && ufw enable"))
        findings.append(_make_finding("critical", "Default INPUT policy", "FAIL", "No firewall", "Configure default deny incoming"))
        findings.append(_make_finding("info", "Firewall rules", "INFO", "No firewall installed", ""))
        return findings

    if fw_type == "ufw":
        r = ssh.execute(server, "sudo ufw status verbose")
        output = r.stdout.strip()
        active = "Status: active" in output

        if not active:
            findings.append(_make_finding("critical", "Firewall installed and active", "FAIL", "ufw installed but inactive", "Enable ufw: sudo ufw enable"))
        else:
            findings.append(_make_finding("pass", "Firewall installed and active", "PASS", "ufw active", ""))

        if "deny (incoming)" in output or "reject (incoming)" in output:
            findings.append(_make_finding("pass", "Default INPUT policy", "PASS", "Default deny/reject incoming", ""))
        else:
            findings.append(_make_finding("critical", "Default INPUT policy", "FAIL", "Default incoming is not deny/reject", "Set default deny: sudo ufw default deny incoming"))

        rule_lines = [l for l in output.split("\n") if l.strip() and not l.startswith(("Status:", "Default:", "New", "Logging", "To", "--", ""))]
        findings.append(_make_finding("info", "Firewall rules", "INFO", f"{len(rule_lines)} rules configured", ""))

    else:
        if fw_type == "iptables":
            r = ssh.execute(server, "sudo iptables -L INPUT -n 2>/dev/null | tail -n +3")
        else:
            r = ssh.execute(server, "sudo nft list ruleset 2>/dev/null")

        has_rules = bool(r.stdout.strip())
        if has_rules:
            findings.append(_make_finding("pass", "Firewall installed and active", "PASS", f"{fw_type} with rules", ""))
        else:
            findings.append(_make_finding("critical", "Firewall installed and active", "FAIL", f"{fw_type} installed but no rules", f"Configure {fw_type} rules"))

        if fw_type == "iptables":
            r = ssh.execute(server, "sudo iptables -L INPUT -n 2>/dev/null | head -1")
            if "DROP" in r.stdout or "REJECT" in r.stdout:
                findings.append(_make_finding("pass", "Default INPUT policy", "PASS", "INPUT policy DROP/REJECT", ""))
            else:
                findings.append(_make_finding("critical", "Default INPUT policy", "FAIL", r.stdout.strip(), "Set INPUT policy to DROP"))
        else:
            findings.append(_make_finding("info", "Default INPUT policy", "INFO", "nft — check manually", ""))

        findings.append(_make_finding("info", "Firewall rules", "INFO", f"{fw_type} active", ""))

    return findings


def _audit_network(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute(server, "sudo ss -tlnp 2>/dev/null || sudo netstat -tlnp 2>/dev/null")
    lines = [l for l in r.stdout.strip().split("\n") if l.strip() and "LISTEN" in l]
    port_details = []
    for l in lines:
        parts = l.split()
        for p in parts:
            if "0.0.0.0:" in p or ":::" in p:
                port_details.append(p)
                break
    findings.append(_make_finding("info", "Listening ports", "INFO", f"{len(lines)} ports listening: {', '.join(port_details[:10])}", "Review and close unnecessary ports"))

    r = ssh.execute(server, "ss -tnp state established 2>/dev/null | grep -v '127.0.0.1' | tail -n +2")
    outbound = [l for l in r.stdout.strip().split("\n") if l.strip()]
    if outbound:
        findings.append(_make_finding("warning", "Outbound connections", "WARN", f"{len(outbound)} established outbound connections", "Review outbound connections for suspicious activity"))
    else:
        findings.append(_make_finding("pass", "Outbound connections", "PASS", "No outbound connections", ""))

    r = ssh.execute(server, "cat /sys/module/ipv6/parameters/disable 2>/dev/null || echo 0")
    disabled = r.stdout.strip()
    if disabled == "1":
        findings.append(_make_finding("pass", "IPv6 status", "PASS", "IPv6 disabled", ""))
    else:
        findings.append(_make_finding("info", "IPv6 status", "INFO", "IPv6 enabled", "Disable IPv6 if not needed: net.ipv6.conf.all.disable_ipv6=1"))

    return findings


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
