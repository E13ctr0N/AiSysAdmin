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


def _audit_ssh(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute(server, "sudo grep -i '^PermitRootLogin' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "yes"
    if val.lower() == "yes":
        findings.append(_make_finding("critical", "Root login", "FAIL", f"PermitRootLogin {val}", "Set PermitRootLogin to no in /etc/ssh/sshd_config"))
    else:
        findings.append(_make_finding("pass", "Root login", "PASS", f"PermitRootLogin {val}", ""))

    r = ssh.execute(server, "sudo grep -i '^PasswordAuthentication' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "yes"
    if val.lower() == "yes":
        findings.append(_make_finding("warning", "Password authentication", "WARN", f"PasswordAuthentication {val}", "Disable password auth, use SSH keys instead"))
    else:
        findings.append(_make_finding("pass", "Password authentication", "PASS", f"PasswordAuthentication {val}", ""))

    r = ssh.execute(server, "sudo grep -i '^PubkeyAuthentication' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "yes"
    if val.lower() != "yes":
        findings.append(_make_finding("warning", "Public key authentication", "WARN", f"PubkeyAuthentication {val}", "Enable PubkeyAuthentication in sshd_config"))
    else:
        findings.append(_make_finding("pass", "Public key authentication", "PASS", f"PubkeyAuthentication {val}", ""))

    r = ssh.execute(server, "sudo grep -i '^Port' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "22"
    if val == "22":
        findings.append(_make_finding("info", "SSH port", "INFO", "Port 22 (default)", "Consider changing SSH port to reduce scan noise"))
    else:
        findings.append(_make_finding("pass", "SSH port", "PASS", f"Port {val}", ""))

    r = ssh.execute(server, "sudo grep -i '^MaxAuthTries' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "6"
    try:
        max_tries = int(val)
    except ValueError:
        max_tries = 6
    if max_tries > 3:
        findings.append(_make_finding("warning", "Max auth tries", "WARN", f"MaxAuthTries {max_tries}", "Set MaxAuthTries to 3 or less in sshd_config"))
    else:
        findings.append(_make_finding("pass", "Max auth tries", "PASS", f"MaxAuthTries {max_tries}", ""))

    r = ssh.execute(server, "sudo grep -iE '^(AllowUsers|AllowGroups)' /etc/ssh/sshd_config | tail -1")
    if r.stdout.strip():
        findings.append(_make_finding("pass", "Access restrictions", "PASS", r.stdout.strip(), ""))
    else:
        findings.append(_make_finding("info", "Access restrictions", "INFO", "No AllowUsers/AllowGroups set", "Consider restricting SSH access with AllowUsers or AllowGroups"))

    return findings


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

        rule_lines = [l for l in output.split("\n") if l.strip() and not l.startswith(("Status:", "Default:", "New", "Logging", "To", "--"))]
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


def _audit_users(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute(server, "awk -F: '$3 == 0 {print $1}' /etc/passwd")
    uid0_users = [u for u in r.stdout.strip().split("\n") if u.strip()]
    extra = [u for u in uid0_users if u != "root"]
    if extra:
        findings.append(_make_finding("critical", "Extra UID 0 users", "FAIL", f"UID 0 users: {', '.join(extra)}", "Remove extra UID 0 accounts or change their UID"))
    else:
        findings.append(_make_finding("pass", "Extra UID 0 users", "PASS", "Only root has UID 0", ""))

    r = ssh.execute(server, "sudo awk -F: '$2 == \"\" {print $1}' /etc/shadow 2>/dev/null")
    empty_pw = [u for u in r.stdout.strip().split("\n") if u.strip()]
    if empty_pw:
        findings.append(_make_finding("critical", "Empty passwords", "FAIL", f"Accounts without password: {', '.join(empty_pw)}", "Set passwords or lock these accounts: passwd -l <user>"))
    else:
        findings.append(_make_finding("pass", "Empty passwords", "PASS", "No accounts with empty passwords", ""))

    r = ssh.execute(server, "lastlog -b 90 2>/dev/null | tail -n +2 | awk 'NF > 1 {print $1}'")
    inactive = [u for u in r.stdout.strip().split("\n") if u.strip()]
    if inactive:
        findings.append(_make_finding("warning", "Inactive accounts", "WARN", f"Inactive >90 days: {', '.join(inactive[:5])}", "Review and disable inactive accounts: usermod -L <user>"))
    else:
        findings.append(_make_finding("pass", "Inactive accounts", "PASS", "No inactive accounts found", ""))

    r = ssh.execute(server, "sudo grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    if r.stdout.strip():
        lines = r.stdout.strip().split("\n")
        findings.append(_make_finding("warning", "NOPASSWD in sudoers", "WARN", f"{len(lines)} NOPASSWD entries found", "Remove NOPASSWD from sudoers unless absolutely required"))
    else:
        findings.append(_make_finding("pass", "NOPASSWD in sudoers", "PASS", "No NOPASSWD entries", ""))

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

    r = ssh.execute(server, "sudo ss -tnp state established 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' | tail -n +2")
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


_KNOWN_SUID = {
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/su", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/crontab",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/sbin/unix_chkpwd", "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/bin/expiry", "/usr/bin/wall", "/usr/bin/ssh-agent",
    "/usr/bin/dotlockfile", "/usr/lib/x86_64-linux-gnu/utempter/utempter",
}


def _audit_filesystem(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute(server, "find / -perm /6000 -type f 2>/dev/null | head -50", timeout=60)
    suid_files = [f for f in r.stdout.strip().split("\n") if f.strip()]
    unknown_suid = [f for f in suid_files if f not in _KNOWN_SUID]
    if unknown_suid:
        findings.append(_make_finding("warning", "SUID/SGID binaries", "WARN", f"{len(unknown_suid)} non-standard: {', '.join(unknown_suid[:5])}", "Review and remove unnecessary SUID/SGID bits: chmod -s <file>"))
    else:
        findings.append(_make_finding("pass", "SUID/SGID binaries", "PASS", f"{len(suid_files)} standard SUID/SGID binaries", ""))

    r = ssh.execute(server, "find / -path /tmp -prune -o -path /var/tmp -prune -o -path /proc -prune -o -path /sys -prune -o -type f -perm -o+w -print 2>/dev/null | head -20", timeout=60)
    ww_files = [f for f in r.stdout.strip().split("\n") if f.strip()]
    if ww_files:
        findings.append(_make_finding("warning", "World-writable files", "WARN", f"{len(ww_files)} files: {', '.join(ww_files[:5])}", "Remove world-writable permissions: chmod o-w <file>"))
    else:
        findings.append(_make_finding("pass", "World-writable files", "PASS", "No world-writable files outside /tmp", ""))

    r = ssh.execute(server, "mount | grep ' /tmp '")
    if r.stdout.strip():
        mount_opts = r.stdout.strip()
        has_noexec = "noexec" in mount_opts
        has_nosuid = "nosuid" in mount_opts
        if has_noexec and has_nosuid:
            findings.append(_make_finding("pass", "/tmp mount options", "PASS", "noexec,nosuid on /tmp", ""))
        else:
            missing = []
            if not has_noexec:
                missing.append("noexec")
            if not has_nosuid:
                missing.append("nosuid")
            findings.append(_make_finding("warning", "/tmp mount options", "WARN", f"/tmp missing: {','.join(missing)}", f"Add {','.join(missing)} to /tmp in /etc/fstab"))
    else:
        findings.append(_make_finding("warning", "/tmp mount options", "WARN", "/tmp not a separate mount", "Mount /tmp as separate partition with noexec,nosuid"))

    r = ssh.execute(server, "ls -la /etc/shadow /etc/passwd /etc/ssh 2>/dev/null")
    output = r.stdout.strip()
    bad_perms = False
    if output:
        for line in output.split("\n"):
            if "/etc/shadow" in line and (line[7] != "-" or line[8] != "-" or line[9] != "-"):
                bad_perms = True
            if "/etc/ssh" in line and line[7] != "-":
                bad_perms = True
    if bad_perms:
        findings.append(_make_finding("critical", "Sensitive file permissions", "FAIL", "Insecure permissions detected", "Fix: chmod 640 /etc/shadow; chmod 700 /etc/ssh"))
    else:
        findings.append(_make_finding("pass", "Sensitive file permissions", "PASS", "Correct permissions on sensitive files", ""))

    return findings


_UNNECESSARY_SERVICES = {
    "avahi-daemon", "cups", "cups-browsed", "rpcbind", "rpc.mountd",
    "rpc.statd", "bluetooth", "ModemManager", "whoopsie",
}


def _audit_services(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute(server, "systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}'")
    services = [s for s in r.stdout.strip().split("\n") if s.strip()]
    findings.append(_make_finding("info", "Running daemons", "INFO", f"{len(services)} services running", ""))

    running = {s.replace(".service", "") for s in services}
    found_unnecessary = running & _UNNECESSARY_SERVICES
    if found_unnecessary:
        findings.append(_make_finding("warning", "Unnecessary services", "WARN", f"Running: {', '.join(sorted(found_unnecessary))}", f"Disable with: systemctl disable --now {' '.join(sorted(found_unnecessary))}"))
    else:
        findings.append(_make_finding("pass", "Unnecessary services", "PASS", "No unnecessary services detected", ""))

    r = ssh.execute(server, "which xinetd inetd 2>/dev/null")
    if r.stdout.strip():
        findings.append(_make_finding("warning", "Legacy inetd/xinetd", "WARN", f"Found: {r.stdout.strip()}", "Remove legacy inetd/xinetd: apt remove xinetd"))
    else:
        findings.append(_make_finding("pass", "Legacy inetd/xinetd", "PASS", "No inetd/xinetd found", ""))

    return findings


def _audit_updates(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    ssh.execute(server, "sudo apt-get update -qq 2>/dev/null", timeout=60)

    r = ssh.execute(server, "apt list --upgradable 2>/dev/null")
    pkg_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("Listing")]
    if pkg_lines:
        findings.append(_make_finding("warning", "Pending updates", "WARN", f"{len(pkg_lines)} packages need updating", "Run: sudo apt upgrade"))
    else:
        findings.append(_make_finding("pass", "Pending updates", "PASS", "All packages up to date", ""))

    r = ssh.execute(server, "apt list --upgradable 2>/dev/null | grep -i security")
    sec_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("Listing")]
    if sec_lines:
        findings.append(_make_finding("critical", "Security updates", "FAIL", f"{len(sec_lines)} security updates pending", "Run immediately: sudo apt upgrade"))
    else:
        findings.append(_make_finding("pass", "Security updates", "PASS", "No pending security updates", ""))

    r = ssh.execute(server, "uname -r | sed 's/-[a-z].*//'; apt-cache policy linux-image-$(dpkg --print-architecture) 2>/dev/null | grep Candidate | awk '{print $2}' | sed 's/-[a-z].*//'")
    versions = [v.strip() for v in r.stdout.strip().split("\n") if v.strip()]
    if len(versions) >= 2 and versions[0] != versions[1]:
        findings.append(_make_finding("warning", "Kernel version", "WARN", f"Running {versions[0]}, available {versions[1]}", "Update kernel and reboot"))
    else:
        current = versions[0] if versions else "unknown"
        findings.append(_make_finding("pass", "Kernel version", "PASS", f"Kernel {current} is current", ""))

    r = ssh.execute(server, "ls /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null")
    if r.exit_code == 0 and r.stdout.strip():
        findings.append(_make_finding("pass", "Unattended upgrades", "PASS", "Auto-upgrades configured", ""))
    else:
        findings.append(_make_finding("warning", "Unattended upgrades", "WARN", "Unattended-upgrades not configured", "Install: apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades"))

    return findings


def _audit_logs(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute(server, "systemctl is-active fail2ban 2>/dev/null")
    if r.stdout.strip() == "active":
        findings.append(_make_finding("pass", "fail2ban", "PASS", "fail2ban active", ""))
    else:
        findings.append(_make_finding("warning", "fail2ban", "WARN", "fail2ban not active", "Install: apt install fail2ban && systemctl enable --now fail2ban"))

    r = ssh.execute(server, "systemctl is-active auditd 2>/dev/null")
    if r.stdout.strip() == "active":
        findings.append(_make_finding("pass", "auditd", "PASS", "auditd active", ""))
    else:
        findings.append(_make_finding("info", "auditd", "INFO", "auditd not active", "Consider installing: apt install auditd"))

    r = ssh.execute(server, "ls /etc/logrotate.conf 2>/dev/null")
    if r.exit_code == 0 and r.stdout.strip():
        findings.append(_make_finding("pass", "Logrotate", "PASS", "Logrotate configured", ""))
    else:
        findings.append(_make_finding("info", "Logrotate", "INFO", "Logrotate not found", "Install: apt install logrotate"))

    r = ssh.execute(server, "sudo grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0")
    try:
        count = int(r.stdout.strip())
    except ValueError:
        count = 0
    findings.append(_make_finding("info", "Failed login attempts", "INFO", f"{count} failed login attempts in auth.log", ""))

    r = ssh.execute(server, "sudo grep 'COMMAND=' /var/log/auth.log 2>/dev/null | tail -10")
    lines = [l for l in r.stdout.strip().split("\n") if l.strip()]
    findings.append(_make_finding("info", "Recent sudo activity", "INFO", f"{len(lines)} recent sudo commands", ""))

    return findings


_SYSCTL_CHECKS = [
    ("net.ipv4.ip_forward", "0", "warning", "IP forwarding", "Disable: sysctl -w net.ipv4.ip_forward=0"),
    ("net.ipv4.tcp_syncookies", "1", "warning", "SYN cookies", "Enable: sysctl -w net.ipv4.tcp_syncookies=1"),
    ("net.ipv4.conf.all.rp_filter", "1", "warning", "Reverse path filtering", "Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"),
    ("net.ipv4.conf.all.accept_redirects", "0", "warning", "ICMP redirects", "Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"),
    ("net.ipv4.conf.all.send_redirects", "0", "warning", "Send redirects", "Disable: sysctl -w net.ipv4.conf.all.send_redirects=0"),
    ("kernel.randomize_va_space", "2", "critical", "ASLR (randomize_va_space)", "Enable: sysctl -w kernel.randomize_va_space=2"),
    ("fs.protected_hardlinks", "1", "warning", "Protected hardlinks", "Enable: sysctl -w fs.protected_hardlinks=1"),
    ("fs.protected_symlinks", "1", "warning", "Protected symlinks", "Enable: sysctl -w fs.protected_symlinks=1"),
]


def _audit_kernel(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    keys = " ".join(c[0] for c in _SYSCTL_CHECKS)
    r = ssh.execute(server, f"sysctl {keys} 2>/dev/null")
    values = {}
    for line in r.stdout.strip().split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()

    for key, expected, severity, check_name, recommendation in _SYSCTL_CHECKS:
        actual = values.get(key, "unknown")
        if actual == expected:
            findings.append(_make_finding("pass", check_name, "PASS", f"{key} = {actual}", ""))
        else:
            findings.append(_make_finding(severity, check_name, "FAIL" if severity == "critical" else "WARN", f"{key} = {actual} (expected {expected})", recommendation))

    return findings


def _audit_malware(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute(server, "for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done; cat /etc/crontab /etc/cron.d/* 2>/dev/null")
    cron_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("#")]
    suspicious_cron = [l for l in cron_lines if any(kw in l.lower() for kw in ["curl", "wget", "bash -c", "/dev/tcp", "base64", "eval", "nc ", "ncat"])]
    if suspicious_cron:
        findings.append(_make_finding("warning", "Suspicious crontab entries", "WARN", f"{len(suspicious_cron)} suspicious entries found", "Review crontab entries for malicious commands"))
    else:
        findings.append(_make_finding("pass", "Suspicious crontab entries", "PASS", "No suspicious crontab entries", ""))

    r = ssh.execute(server, "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'")
    deleted = [l for l in r.stdout.strip().split("\n") if l.strip()]
    if deleted:
        findings.append(_make_finding("critical", "Processes without binary", "FAIL", f"{len(deleted)} processes with deleted binaries", "Investigate processes running from deleted binaries"))
    else:
        findings.append(_make_finding("pass", "Processes without binary", "PASS", "All processes have on-disk binaries", ""))

    r = ssh.execute(server, "ls -la /tmp/.ice-unix/.x /tmp/.font-unix/.x /dev/shm/.x /usr/lib/libamplify.so /usr/bin/.sshd 2>/dev/null")
    if r.stdout.strip():
        findings.append(_make_finding("critical", "Known rootkit paths", "FAIL", f"Found: {r.stdout.strip()}", "Investigate immediately — possible rootkit"))
    else:
        findings.append(_make_finding("pass", "Known rootkit paths", "PASS", "No known rootkit files found", ""))

    r = ssh.execute(server, "find /tmp /dev/shm -maxdepth 2 -name '.*' -not -name '.' -not -name '..' -not -name '.ICE-unix' -not -name '.X11-unix' -not -name '.font-unix' -not -name '.XIM-unix' 2>/dev/null")
    hidden = [f for f in r.stdout.strip().split("\n") if f.strip()]
    if hidden:
        findings.append(_make_finding("warning", "Hidden files in /tmp, /dev/shm", "WARN", f"{len(hidden)} hidden files: {', '.join(hidden[:5])}", "Review hidden files in /tmp and /dev/shm"))
    else:
        findings.append(_make_finding("pass", "Hidden files in /tmp, /dev/shm", "PASS", "No suspicious hidden files", ""))

    r = ssh.execute(server, "cat /etc/hosts 2>/dev/null")
    hosts_lines = [l.strip() for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("#")]
    suspicious_hosts = [l for l in hosts_lines if not any(kw in l for kw in ["localhost", "ip6-", "ff02::", "fe00::", "127.0.0.1", "::1"])]
    if suspicious_hosts:
        findings.append(_make_finding("warning", "Suspicious /etc/hosts entries", "WARN", f"{len(suspicious_hosts)} non-standard entries", "Review /etc/hosts for hijacked domains"))
    else:
        findings.append(_make_finding("pass", "Suspicious /etc/hosts entries", "PASS", "Only standard entries in /etc/hosts", ""))

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


def full_security_audit_impl(ssh: SSHManager, server: str) -> dict:
    hostname = ssh.execute(server, "hostname").stdout.strip() or server
    ip = ssh.execute(server, "hostname -I 2>/dev/null | awk '{print $1}'").stdout.strip() or "unknown"

    categories = {
        "ssh":        {"weight": 15, "findings": _audit_ssh(ssh, server)},
        "firewall":   {"weight": 15, "findings": _audit_firewall(ssh, server)},
        "users":      {"weight": 15, "findings": _audit_users(ssh, server)},
        "network":    {"weight": 10, "findings": _audit_network(ssh, server)},
        "filesystem": {"weight": 10, "findings": _audit_filesystem(ssh, server)},
        "services":   {"weight":  5, "findings": _audit_services(ssh, server)},
        "updates":    {"weight": 10, "findings": _audit_updates(ssh, server)},
        "logs":       {"weight":  5, "findings": _audit_logs(ssh, server)},
        "kernel":     {"weight": 10, "findings": _audit_kernel(ssh, server)},
        "malware":    {"weight":  5, "findings": _audit_malware(ssh, server)},
    }

    scores = _compute_scores(categories)
    report = _format_report(hostname, ip, scores, categories)

    return {
        "score": scores["score"],
        "grade": scores["grade"],
        "summary": scores["summary"],
        "categories": scores["categories"],
        "report_markdown": report,
    }
