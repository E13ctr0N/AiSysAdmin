from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone
from html import escape
from paramiko import SSHException
from agensysadmin.ssh_manager import CommandResult

from agensysadmin.ssh_manager import SSHManager
from agensysadmin.profiles import profile_for, forwarding_expected
from agensysadmin.tools.security_common import make_finding as _make_finding
from agensysadmin.tools.security_vpn import _audit_vpn
from agensysadmin.tools.security_docker import _audit_docker_security
from agensysadmin.tools.security_extended import (audit_password_policy, audit_network_details, audit_custom_units, audit_update_details, audit_monitoring)


class _AuditProbe:
    """Track failed probes and cache identical read-only facts within one audit."""
    def __init__(self, ssh: SSHManager, cache: dict | None = None):
        self.ssh = ssh
        self.failed = False
        self.cache = cache if cache is not None else {}

    def _run(self, server, command, timeout, privileged):
        key = (server, command, timeout, privileged)
        if key not in self.cache:
            method = self.ssh.execute_privileged if privileged else self.ssh.execute
            try:
                self.cache[key] = method(server, f"bash -o pipefail -c {shlex.quote(command)}", timeout=timeout)
            except (OSError, ValueError, SSHException):
                self.cache[key] = CommandResult("", "Audit probe could not complete", 255, 0)
        result = self.cache[key]
        no_failed_logins = "grep -c 'Failed password'" in command and result.exit_code == 1 and result.stdout.strip() == "0"
        missing_program = (command.startswith("which ") or command.startswith("command -v ")) and result.exit_code == 1 and not result.stderr.strip()
        inactive_service = command.startswith("systemctl is-active ") and result.exit_code in {3, 4} and result.stdout.strip() in {"inactive", "failed", "unknown"} and not result.stderr.strip()
        if result.exit_code != 0 and not (no_failed_logins or missing_program or inactive_service):
            self.failed = True
        return result

    def execute(self, server, command, timeout=None):
        return self._run(server, command, timeout, False)

    def execute_privileged(self, server, command, timeout=None):
        return self._run(server, command, timeout, True)

    def server_profile(self, server):
        return profile_for(self.ssh, server)


def _grep_or_empty(command: str) -> str:
    # Only fixed grep invocations supplied by this module. Preserve genuine grep
    # errors, but normalize its documented no-match status inside a pipeline.
    return "{ " + command + '; rc=$?; [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; }'


def _optional_file(path: str) -> str:
    parent = path.rsplit("/", 1)[0] or "/"
    return f"test -r {shlex.quote(parent)} && test -x {shlex.quote(parent)} && if test -f {shlex.quote(path)}; then printf '%s' {shlex.quote(path)}; fi"


def _compute_scores(categories: dict) -> dict:
    summary = {"critical": 0, "warning": 0, "info": 0, "pass": 0, "unknown": 0}
    cat_scores = {}
    scored_weight = 0
    weighted_score = 0
    for name, cat in categories.items():
        findings = cat["findings"]
        for finding in findings:
            severity = finding["severity"]
            summary[severity] = summary.get(severity, 0) + 1
            summary["unknown"] += finding["status"] == "UNKNOWN"
        complete = cat.get("complete", True) and not any(f["status"] == "UNKNOWN" for f in findings)
        assessed = [f for f in findings if f["status"] in {"PASS", "WARN", "FAIL"}]
        if not complete:
            score = 0
        elif not assessed:
            score = None  # INFO and NOT_APPLICABLE are not proof of hardening.
        elif any(f["severity"] == "critical" for f in assessed):
            score = 0
        else:
            score = int(sum(f["status"] == "PASS" for f in assessed) / len(assessed) * 100)
        cat_scores[name] = {"score": score, "findings": findings, "complete": complete}
        if score is not None:
            scored_weight += cat["weight"]
            weighted_score += score * cat["weight"]
    overall = int(weighted_score / scored_weight) if scored_weight else 0
    grade = "A" if overall >= 90 else "B" if overall >= 70 else "C" if overall >= 50 else "D" if overall >= 30 else "F"
    return {"score": overall, "grade": grade, "summary": summary, "categories": cat_scores}


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
        "vpn": "VPN/Tunnels",
        "docker": "Docker Security",
    }

    recommendations = []

    for name, cat in categories.items():
        cat_score = scores["categories"][name]["score"]
        title = category_titles.get(name, name.title())
        score_label = "not scored" if cat_score is None else f"{cat_score}/100"
        lines.append(f"## {title} (score: {score_label})")
        lines.append("")
        lines.append("| Status | Check | Detail |")
        lines.append("|---|---|---|")

        for f in cat["findings"]:
            def cell(value):
                return escape(str(value)).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
            lines.append(f"| {cell(f['status'])} | {cell(f['check'])} | {cell(f['detail'])} |")
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


# Use the actual SSH account/address context, including Include and applicable
# Match rules. Hostname-based Match rules still need a separately verified DNS
# context; the peer IP is supplied as host here and this limitation is reported.
_SSH_CONTEXT_COMMAND = 'printf "%s\\n" "$(id -un)" "$SSH_CONNECTION"'


def _effective_ssh_settings(ssh: SSHManager, server: str) -> dict[str, str]:
    context = ssh.execute(server, _SSH_CONTEXT_COMMAND)
    lines = context.stdout.splitlines()
    if context.exit_code != 0 or len(lines) != 2 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*[$]?", lines[0]):
        return {}
    fields = lines[1].split()
    if len(fields) != 4:
        return {}
    import ipaddress
    try:
        peer, local = str(ipaddress.ip_address(fields[0])), str(ipaddress.ip_address(fields[2]))
    except ValueError:
        return {}
    if not all(value.isdecimal() and 0 < int(value) <= 65535 for value in (fields[1], fields[3])):
        return {}
    specification = f"user={lines[0]},addr={peer},host={peer},laddr={local},lport={fields[3]}"
    result = ssh.execute_privileged(server, "/usr/sbin/sshd -T -C " + shlex.quote(specification))
    if result.exit_code != 0:
        return {}
    settings: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            key, value = parts
            settings[key.lower()] = (settings.get(key.lower(), "") + " " + value).strip()
    return settings


def _audit_ssh(ssh: SSHManager, server: str) -> list[dict]:
    settings = _effective_ssh_settings(ssh, server)
    findings = [_make_finding(
        "info", "SSH audit scope", "INFO",
        "sshd -T for the current SSH account/IP; DNS-hostname Match rules, other accounts and daemon startup overrides are not verified",
        "Check additional connection contexts and the running daemon's startup configuration separately",
    )]

    def unknown(label: str):
        findings.append(_make_finding("warning", label, "UNKNOWN",
            "Effective SSH setting unavailable", "Check sudo permission for sshd -T and the daemon configuration"))

    for key, label, safe, unsafe, severity, recommendation in (
        ("permitrootlogin", "Root login", {"no", "prohibit-password", "without-password", "forced-commands-only"}, {"yes"}, "critical", "Disable unrestricted root login"),
        ("passwordauthentication", "Password authentication", {"no"}, {"yes"}, "warning", "Disable password authentication after verifying key access"),
        ("pubkeyauthentication", "Public key authentication", {"yes"}, {"no"}, "warning", "Enable public key authentication"),
    ):
        value = settings.get(key, "").lower()
        if value in safe:
            findings.append(_make_finding("pass", label, "PASS", f"{key} {value}", ""))
        elif value in unsafe:
            findings.append(_make_finding(severity, label, "FAIL" if severity == "critical" else "WARN", f"{key} {value}", recommendation))
        else:
            unknown(label)

    port = settings.get("port", "")
    if not port or not all(p.isdecimal() and 1 <= int(p) <= 65535 for p in port.split()):
        unknown("SSH port")
    else:
        findings.append(_make_finding("info" if "22" in port.split() else "pass", "SSH port", "INFO" if "22" in port.split() else "PASS", f"Port {port}", ""))

    tries = settings.get("maxauthtries", "")
    if not tries.isdecimal() or not 0 < int(tries) <= 1024:
        unknown("Max auth tries")
    else:
        findings.append(_make_finding("warning" if int(tries) > 3 else "pass", "Max auth tries", "WARN" if int(tries) > 3 else "PASS", f"MaxAuthTries {tries}", "Reduce authentication attempts" if int(tries) > 3 else ""))

    restrictions = " ".join(settings.get(k, "") for k in ("allowusers", "allowgroups")).strip()
    if not settings:
        unknown("Access restrictions")
    else:
        findings.append(_make_finding("pass" if restrictions else "info", "Access restrictions", "PASS" if restrictions else "INFO", restrictions or "No AllowUsers/AllowGroups restrictions in this context", ""))
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
        r = ssh.execute_privileged(server, "ufw status verbose")
        output = r.stdout.strip()
        active = "Status: active" in output

        if not active:
            findings.append(_make_finding("critical", "Firewall installed and active", "FAIL", "ufw installed but inactive", "Enable ufw: sudo -n ufw enable"))
        else:
            findings.append(_make_finding("pass", "Firewall installed and active", "PASS", "ufw active", ""))

        if "deny (incoming)" in output or "reject (incoming)" in output:
            findings.append(_make_finding("pass", "Default INPUT policy", "PASS", "Default deny/reject incoming", ""))
        else:
            findings.append(_make_finding("critical", "Default INPUT policy", "FAIL", "Default incoming is not deny/reject", "Set default deny: sudo -n ufw default deny incoming"))

        rule_lines = [l for l in output.split("\n") if l.strip() and not l.startswith(("Status:", "Default:", "New", "Logging", "To", "--"))]
        findings.append(_make_finding("info", "Firewall rules", "INFO", f"{len(rule_lines)} rules configured", ""))

    else:
        if fw_type == "iptables":
            r = ssh.execute_privileged(server, "iptables -L INPUT -n 2>/dev/null | tail -n +3")
        else:
            r = ssh.execute_privileged(server, "nft list ruleset 2>/dev/null")

        has_rules = bool(r.stdout.strip())
        if has_rules:
            findings.append(_make_finding("pass", "Firewall installed and active", "PASS", f"{fw_type} with rules", ""))
        else:
            findings.append(_make_finding("critical", "Firewall installed and active", "FAIL", f"{fw_type} installed but no rules", f"Configure {fw_type} rules"))

        if fw_type == "iptables":
            r = ssh.execute_privileged(server, "iptables -L INPUT -n 2>/dev/null | head -1")
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

    r = ssh.execute_privileged(server, "awk -F: '$2 == \"\" {print $1}' /etc/shadow 2>/dev/null")
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

    grep_script = _grep_or_empty("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/")
    r = ssh.execute_privileged(server, f"sh -c {shlex.quote(grep_script)}")
    if r.stdout.strip():
        lines = r.stdout.strip().split("\n")
        findings.append(_make_finding("warning", "NOPASSWD in sudoers", "WARN", f"{len(lines)} NOPASSWD entries found", "Remove NOPASSWD from sudoers unless absolutely required"))
    else:
        findings.append(_make_finding("pass", "NOPASSWD in sudoers", "PASS", "No NOPASSWD entries", ""))

    return findings


def _audit_network(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    r = ssh.execute_privileged(server, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    lines = [l for l in r.stdout.strip().split("\n") if l.strip() and "LISTEN" in l]
    port_details = []
    for l in lines:
        parts = l.split()
        for p in parts:
            if "0.0.0.0:" in p or ":::" in p:
                port_details.append(p)
                break
    findings.append(_make_finding("info", "Listening ports", "INFO", f"{len(lines)} ports listening: {', '.join(port_details[:10])}", "Review and close unnecessary ports"))

    r = ssh.execute_privileged(server, "ss -tnp state established | " + _grep_or_empty("grep -v '127.0.0.1'") + " | " + _grep_or_empty("grep -v '::1'") + " | tail -n +2")
    outbound = [l for l in r.stdout.strip().split("\n") if l.strip()]
    if outbound:
        findings.append(_make_finding("warning", "Outbound connections", "WARN", f"{len(outbound)} established outbound connections", "Review outbound connections for suspicious activity"))
    else:
        findings.append(_make_finding("pass", "Outbound connections", "PASS", "No outbound connections", ""))

    r = ssh.execute(server, "cat /sys/module/ipv6/parameters/disable")
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

    r = ssh.execute_privileged(server, "find / -perm /6000 -type f 2>/dev/null | head -50", timeout=60)
    suid_files = [f for f in r.stdout.strip().split("\n") if f.strip()]
    unknown_suid = [f for f in suid_files if f not in _KNOWN_SUID]
    if unknown_suid:
        findings.append(_make_finding("warning", "SUID/SGID binaries", "WARN", f"{len(unknown_suid)} non-standard: {', '.join(unknown_suid[:5])}", "Review and remove unnecessary SUID/SGID bits: chmod -s <file>"))
    else:
        findings.append(_make_finding("pass", "SUID/SGID binaries", "PASS", f"{len(suid_files)} standard SUID/SGID binaries", ""))

    r = ssh.execute_privileged(server, "find / -path /tmp -prune -o -path /var/tmp -prune -o -path /proc -prune -o -path /sys -prune -o -type f -perm -o+w -print 2>/dev/null | head -20", timeout=60)
    ww_files = [f for f in r.stdout.strip().split("\n") if f.strip()]
    if ww_files:
        findings.append(_make_finding("warning", "World-writable files", "WARN", f"{len(ww_files)} files: {', '.join(ww_files[:5])}", "Remove world-writable permissions: chmod o-w <file>"))
    else:
        findings.append(_make_finding("pass", "World-writable files", "PASS", "No world-writable files outside /tmp", ""))

    r = ssh.execute(server, "mount | " + _grep_or_empty("grep ' /tmp '"))
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

    # /etc/shadow — must not be world-readable (critical)
    r = ssh.execute(server, "ls -la /etc/shadow 2>/dev/null")
    shadow_line = r.stdout.strip()
    shadow_bad = False
    if shadow_line and len(shadow_line) > 9:
        shadow_bad = shadow_line[7] != "-" or shadow_line[8] != "-" or shadow_line[9] != "-"
    if shadow_bad:
        findings.append(_make_finding("critical", "Sensitive file permissions", "FAIL", f"/etc/shadow has insecure permissions: {shadow_line[:10]}", "Fix: chmod 640 /etc/shadow"))
    else:
        # /etc/ssh directory — 700 is ideal but 755 is Debian default (warning)
        r = ssh.execute(server, "stat -c '%a %n' /etc/ssh 2>/dev/null")
        ssh_perms = r.stdout.strip().split()[0] if r.stdout.strip() else ""
        if ssh_perms and ssh_perms != "700":
            findings.append(_make_finding("warning", "Sensitive file permissions", "WARN", f"/etc/ssh has permissions {ssh_perms} (recommended 700)", "Harden: chmod 700 /etc/ssh"))
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
    findings = [_make_finding("info", "Package cache", "INFO",
                              "Existing package metadata only; freshness is not verified",
                              "Refresh package metadata separately with operator approval")]

    r = ssh.execute(server, "apt list --upgradable 2>/dev/null")
    pkg_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("Listing")]
    if r.exit_code != 0:
        findings.append(_make_finding("warning", "Pending updates", "UNKNOWN", "Could not read package metadata", "Check apt availability and permissions"))
    elif pkg_lines:
        findings.append(_make_finding("warning", "Pending updates", "WARN", f"{len(pkg_lines)} packages need updating", "Run: sudo -n apt upgrade"))
    else:
        findings.append(_make_finding("pass", "Pending updates", "PASS", "No upgrades in cached package metadata", ""))

    sec_lines = [line for line in pkg_lines if "security" in line.split()[0].lower()]
    if r.exit_code != 0:
        findings.append(_make_finding("warning", "Security updates", "UNKNOWN", "Could not read package metadata", "Check apt availability and permissions"))
    elif sec_lines:
        findings.append(_make_finding("critical", "Security updates", "FAIL", f"{len(sec_lines)} security updates pending", "Run immediately: sudo -n apt upgrade"))
    else:
        findings.append(_make_finding("pass", "Security updates", "PASS", "No pending security updates", ""))

    r = ssh.execute(server, "uname -r | sed 's/-[a-z].*//'; apt-cache policy linux-image-$(dpkg --print-architecture) | " + _grep_or_empty("grep Candidate") + " | awk '{print $2}' | sed 's/-[a-z].*//'")
    versions = [v.strip() for v in r.stdout.strip().split("\n") if v.strip()]
    if len(versions) >= 2 and versions[0] != versions[1]:
        findings.append(_make_finding("warning", "Kernel version", "WARN", f"Running {versions[0]}, available {versions[1]}", "Update kernel and reboot"))
    elif len(versions) >= 2:
        current = versions[0]
        findings.append(_make_finding("pass", "Kernel version", "PASS", f"Kernel {current} is current", ""))
    else:
        findings.append(_make_finding("warning", "Kernel version", "UNKNOWN", "Kernel comparison unavailable", "Check package metadata and kernel package naming"))

    r = ssh.execute(server, _optional_file("/etc/apt/apt.conf.d/20auto-upgrades"))
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

    r = ssh.execute(server, _optional_file("/etc/logrotate.conf"))
    if r.exit_code == 0 and r.stdout.strip():
        findings.append(_make_finding("pass", "Logrotate", "PASS", "Logrotate configured", ""))
    else:
        findings.append(_make_finding("info", "Logrotate", "INFO", "Logrotate not found", "Install: apt install logrotate"))

    r = ssh.execute_privileged(server, "grep -c 'Failed password' /var/log/auth.log")
    try:
        count = int(r.stdout.strip())
    except ValueError:
        count = 0
    findings.append(_make_finding("info", "Failed login attempts", "INFO", f"{count} failed login attempts in auth.log", ""))

    r = ssh.execute_privileged(server, "cat /var/log/auth.log | " + _grep_or_empty("grep 'COMMAND='") + " | tail -10")
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

    profile = profile_for(ssh, server)
    for key, expected, severity, check_name, recommendation in _SYSCTL_CHECKS:
        actual = values.get(key, "unknown")
        if actual == "unknown":
            findings.append(_make_finding("warning", check_name, "UNKNOWN", f"{key} unavailable", "Check sysctl availability"))
            continue
        if key == "net.ipv4.ip_forward":
            policy = forwarding_expected(profile)
            if policy is None:
                findings.append(_make_finding("info", check_name, "INFO", f"{key}={actual}; generic profile has no forwarding policy", "Set the intended server profile before recommending a change"))
                continue
            expected = policy
            recommendation = f"Review forwarding against the {profile} profile; no automatic change is performed"
        if key == "net.ipv4.conf.all.rp_filter" and profile == "vpn_node":
            findings.append(_make_finding("info", check_name, "INFO", f"{key}={actual}; tunnel/asymmetric routing needs contextual policy", "Review routing before changing reverse-path filtering"))
            continue
        if actual == expected:
            findings.append(_make_finding("pass", check_name, "PASS", f"{key} = {actual}", ""))
        else:
            findings.append(_make_finding(severity, check_name, "FAIL" if severity == "critical" else "WARN", f"{key} = {actual} (expected {expected})", recommendation))

    return findings


def _audit_malware(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    cron_script = 'set -e; if [ -f /etc/crontab ]; then cat /etc/crontab; fi; for d in /etc/cron.d /var/spool/cron/crontabs; do if [ -d "$d" ]; then find "$d" -maxdepth 1 -type f -exec cat -- {} +; fi; done'
    r = ssh.execute_privileged(server, f"sh -c {shlex.quote(cron_script)}")
    cron_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("#")]
    suspicious_cron = [l for l in cron_lines if any(kw in l.lower() for kw in ["curl", "wget", "bash -c", "/dev/tcp", "base64", "eval", "nc ", "ncat"])]
    if suspicious_cron:
        findings.append(_make_finding("warning", "Suspicious crontab entries", "WARN", f"{len(suspicious_cron)} suspicious entries found", "Review crontab entries for malicious commands"))
    else:
        findings.append(_make_finding("pass", "Suspicious crontab entries", "PASS", "No suspicious crontab entries", ""))

    r = ssh.execute_privileged(server, "find /proc -maxdepth 3 -path '/proc/[0-9]*/exe' -lname '* (deleted)' -ls")
    deleted = [l for l in r.stdout.strip().split("\n") if l.strip()]
    if deleted:
        findings.append(_make_finding("critical", "Processes without binary", "FAIL", f"{len(deleted)} processes with deleted binaries", "Investigate processes running from deleted binaries"))
    else:
        findings.append(_make_finding("pass", "Processes without binary", "PASS", "All processes have on-disk binaries", ""))

    r = ssh.execute_privileged(server, r"find /tmp /dev/shm /usr/lib /usr/bin -maxdepth 2 \( -path '/tmp/.ice-unix/.x' -o -path '/tmp/.font-unix/.x' -o -path '/dev/shm/.x' -o -path '/usr/lib/libamplify.so' -o -path '/usr/bin/.sshd' \) -ls")
    if r.stdout.strip():
        findings.append(_make_finding("critical", "Known rootkit paths", "FAIL", f"Found: {r.stdout.strip()}", "Investigate immediately — possible rootkit"))
    else:
        findings.append(_make_finding("pass", "Known rootkit paths", "PASS", "No known rootkit files found", ""))

    r = ssh.execute_privileged(server, "find /tmp /dev/shm -maxdepth 2 -name '.*' -not -name '.' -not -name '..' -not -name '.ICE-unix' -not -name '.X11-unix' -not -name '.font-unix' -not -name '.XIM-unix' 2>/dev/null")
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
        "metadata_source": "existing_apt_cache",
        "freshness_verified": False,
        "exit_code": result.exit_code,
        "stderr": result.stderr,
        "update_count": len(packages),
        "packages": packages,
    }


def firewall_status_impl(ssh: SSHManager, server: str) -> dict:
    result = ssh.execute_privileged(server, "ufw status verbose")

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
    settings = _effective_ssh_settings(ssh, server)
    root_login_val = settings.get("permitrootlogin", "unknown")
    password_auth_val = settings.get("passwordauthentication", "unknown")
    ssh_known = root_login_val in {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"} and password_auth_val in {"yes", "no"}

    auto_updates = ssh.execute(server,
        "test -r /etc/apt/apt.conf.d && test -x /etc/apt/apt.conf.d && "
        "if test -f /etc/apt/apt.conf.d/20auto-upgrades; then printf present; else printf absent; fi")
    auto_known = auto_updates.exit_code == 0 and auto_updates.stdout.strip() in {"present", "absent"}

    failed_logins = ssh.execute_privileged(server, "grep -c 'Failed password' /var/log/auth.log")
    count_known = failed_logins.exit_code in {0, 1} and failed_logins.stdout.strip().isdecimal()
    failed_count = int(failed_logins.stdout.strip()) if count_known else None

    root_users = ssh.execute(server, "awk -F: '$3 == 0 {print $1}' /etc/passwd")
    users_known = root_users.exit_code == 0
    root_users_list = [u for u in root_users.stdout.splitlines() if u.strip()] if users_known else None

    world_writable = ssh.execute_privileged(server, "find /etc -type f -perm -o+w")
    files_known = world_writable.exit_code == 0
    ww_files = [f for f in world_writable.stdout.splitlines() if f.strip()] if files_known else None

    return {
        "success": all((ssh_known, auto_known, count_known, users_known, files_known)),
        "checks": {
            "ssh": {"root_login": root_login_val, "password_auth": password_auth_val,
                    "status": "CHECKED" if ssh_known else "UNKNOWN",
                    "source": "sshd -T", "scope": "current_account_and_ip",
                    "hostname_match_verified": False, "runtime_overrides_verified": False},
            "auto_updates": {"enabled": auto_updates.stdout.strip() == "present" if auto_known else None,
                             "status": "CHECKED" if auto_known else "UNKNOWN"},
            "failed_logins": {"count": failed_count, "status": "CHECKED" if count_known else "UNKNOWN"},
            "root_users": {"users": root_users_list, "status": "CHECKED" if users_known else "UNKNOWN"},
            "world_writable": {"files": ww_files, "status": "CHECKED" if files_known else "UNKNOWN"},
        },
    }


def full_security_audit_impl(ssh: SSHManager, server: str) -> dict:
    hostname_result = ssh.execute(server, "hostname")
    ip_result = ssh.execute(server, "hostname -I")
    hostname = hostname_result.stdout.strip() or server
    ip = ip_result.stdout.strip().split()[0] if ip_result.stdout.strip() else "unknown"
    metadata_complete = hostname_result.exit_code == 0 and ip_result.exit_code == 0 and bool(hostname_result.stdout.strip()) and bool(ip_result.stdout.strip())

    def combined(base, extra):
        return lambda probe, name: base(probe, name) + extra(probe, name)

    definitions = {
        "ssh": (12, _audit_ssh), "firewall": (12, _audit_firewall),
        "users": (12, combined(_audit_users, audit_password_policy)),
        "network": (12, combined(_audit_network, audit_network_details)),
        "filesystem": (8, _audit_filesystem),
        "services": (5, combined(_audit_services, audit_custom_units)),
        "updates": (10, combined(_audit_updates, audit_update_details)),
        "logs": (5, combined(_audit_logs, audit_monitoring)),
        "kernel": (8, _audit_kernel), "malware": (5, _audit_malware),
        "vpn": (6, _audit_vpn), "docker": (5, _audit_docker_security),
    }
    categories = {}
    cache = {}
    for name, (weight, audit) in definitions.items():
        probe = _AuditProbe(ssh, cache)
        findings = audit(probe, server)
        complete = not probe.failed and not any(f["status"] == "UNKNOWN" for f in findings)
        if not complete and name not in {"vpn", "docker"}:
            # Avoid presenting empty output after permission/tool errors as proof
            # of safety. Retesting this category is required before using its score.
            findings = [_make_finding("warning", "Incomplete category", "UNKNOWN",
                "One or more probes failed or settings were unavailable; this category cannot be scored as safe",
                "Review command availability and narrowly scoped sudo permissions, then repeat the audit")]
        categories[name] = {"weight": weight, "findings": findings, "complete": complete}

    scores = _compute_scores(categories)
    report = _format_report(hostname, ip, scores, categories)

    return {
        "success": metadata_complete and all(cat["complete"] for cat in categories.values()),
        "complete": metadata_complete and all(cat["complete"] for cat in categories.values()),
        "metadata_complete": metadata_complete,
        "profile": profile_for(ssh, server),
        "score": scores["score"],
        "grade": scores["grade"],
        "summary": scores["summary"],
        "categories": scores["categories"],
        "report_markdown": report,
    }
