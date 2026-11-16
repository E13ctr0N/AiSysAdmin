from __future__ import annotations

import re
import shlex

from agensysadmin.profiles import profile_for
from agensysadmin.tools.security_common import make_finding, unknown, not_applicable, run, capability, listeners
from agensysadmin.tools.security_vpn import LISTENER_COMMAND


def _optional_text(ssh, server: str, path: str):
    parent = path.rsplit("/", 1)[0] or "/"
    command = (f"test -r {shlex.quote(parent)} && test -x {shlex.quote(parent)} && "
               f"if test -f {shlex.quote(path)}; then cat -- {shlex.quote(path)}; else printf '__ABSENT__'; fi")
    return run(ssh, server, command, privileged=True)


def audit_password_policy(ssh, server: str) -> list[dict]:
    findings = []
    result = _optional_text(ssh, server, "/etc/login.defs")
    if result.exit_code != 0:
        findings.append(unknown("Password age policy"))
    elif result.stdout == "__ABSENT__":
        findings.append(not_applicable("Password age policy", "login.defs is absent on this target"))
    else:
        values = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] in {"PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE"} and len(parts) >= 2:
                values[parts[0]] = parts[1]
        if not values or any(not value.isdecimal() for value in values.values()):
            findings.append(unknown("Password age policy", "Age settings were absent or malformed"))
        else:
            findings.append(make_finding("info", "Password age policy", "INFO",
                "; ".join(f"{key}={value}" for key, value in sorted(values.items())),
                "These defaults do not prove account-specific policy or justify automatic password rotation"))
    result = _optional_text(ssh, server, "/etc/pam.d/common-password")
    if result.exit_code != 0:
        findings.append(unknown("PAM password policy"))
    elif result.stdout == "__ABSENT__":
        findings.append(not_applicable("PAM password policy", "Debian/Ubuntu PAM file absent; platform-specific policy not assessed"))
    else:
        active = [line for line in result.stdout.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        detected = any("pam_pwquality.so" in line or "pam_cracklib.so" in line for line in active)
        findings.append(make_finding("info", "PAM password policy", "INFO",
            "Complexity-module reference found" if detected else "No known complexity-module reference found",
            "Verify PAM control flow, module options and account policy before changing it"))
    return findings


def audit_network_details(ssh, server: str) -> list[dict]:
    findings = []
    result = run(ssh, server, LISTENER_COMMAND)
    endpoints = listeners(result.stdout) if result.exit_code == 0 else None
    if endpoints is None:
        findings.extend([unknown("Sensitive service bindings"), unknown("TLS listener inventory")])
    else:
        ports = {3306, 5432, 6379, 11211, 27017, 9200}
        exposed = [item for item in endpoints if item["port"] in ports and not item["loopback"]]
        findings.append(make_finding("warning" if exposed else "pass", "Sensitive service bindings", "WARN" if exposed else "PASS",
            f"{len(exposed)} database/cache listeners outside loopback; firewall reachability and authentication are unverified",
            "Compare bindings with the server profile and intended client networks" if exposed else ""))
        tls = any(item["protocol"] == "tcp" and item["port"] == 443 for item in endpoints)
        findings.append(make_finding("info", "TLS listener inventory", "INFO" if tls else "NOT_APPLICABLE",
            "Port 443 listener observed; protocol versions and certificate were not tested because no verified target/SNI was configured" if tls else "No conventional TCP 443 listener observed",
            "Perform a separately targeted TLS test with the intended hostname/SNI" if tls else "", protocol_tested=False))
    available = capability(ssh, server, "fail2ban-client")
    if available is None:
        findings.append(unknown("Fail2ban jails"))
    elif not available:
        findings.append(not_applicable("Fail2ban jails", "fail2ban-client executable not found"))
    else:
        result = run(ssh, server, "fail2ban-client status", privileged=True)
        if result.exit_code != 0:
            findings.append(unknown("Fail2ban jails"))
        else:
            lines = [line.split(":", 1)[1] for line in result.stdout.splitlines() if "Jail list:" in line]
            if not lines:
                findings.append(unknown("Fail2ban jails", "Unrecognised fail2ban status response"))
            else:
                jails = [jail.strip() for jail in lines[0].split(",") if jail.strip()]
                if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", jail) for jail in jails):
                    findings.append(unknown("Fail2ban jails", "Invalid jail identifier in status response"))
                else:
                    total_bans = 0
                    checked = 0
                    failed = False
                    for jail in jails[:20]:
                        result = run(ssh, server, "fail2ban-client status " + shlex.quote(jail), privileged=True)
                        match = re.search(r"Total banned:\s*(\d+)", result.stdout)
                        if result.exit_code != 0 or not match:
                            failed = True
                            break
                        checked += 1
                        total_bans += int(match.group(1))
                    if failed or len(jails) > 20:
                        findings.append(unknown("Fail2ban jails", "Jail inspection incomplete", checked=checked, total=len(jails), complete=False))
                    else:
                        findings.append(make_finding("info", "Fail2ban jails", "INFO", f"{checked} jails checked; {total_bans} cumulative bans", checked=checked, total=len(jails), complete=True))
    return findings


def audit_custom_units(ssh, server: str) -> list[dict]:
    result = run(ssh, server, "find /etc/systemd/system -maxdepth 3 -type f -name '*.service' -print", privileged=True)
    if result.exit_code != 0:
        return [unknown("Custom systemd units")]
    paths = [line for line in result.stdout.splitlines() if line]
    if any(not path.startswith("/etc/systemd/system/") or any(ord(c) < 32 for c in path) for path in paths):
        return [unknown("Custom systemd units", "Invalid unit path in discovery response")]
    suspicious = 0
    for path in paths[:50]:
        result = run(ssh, server, "cat -- " + shlex.quote(path), privileged=True)
        if result.exit_code != 0:
            return [unknown("Custom systemd units", checked=0, total=len(paths), complete=False)]
        suspicious += any(pattern in result.stdout.lower() for pattern in ("/tmp/", "/dev/shm/", "curl ", "wget "))
    if len(paths) > 50:
        return [unknown("Custom systemd units", "Unit inspection exceeded bounded coverage", checked=50, total=len(paths), complete=False)]
    return [make_finding("info", "Custom systemd units", "INFO", f"{len(paths)} custom unit files reviewed; {suspicious} contain patterns needing operator context",
        "Command patterns alone do not prove malware; unit contents were not returned", checked=len(paths), total=len(paths), complete=True)]


def audit_update_details(ssh, server: str) -> list[dict]:
    findings = []
    result = _optional_text(ssh, server, "/var/run/reboot-required")
    if result.exit_code != 0:
        findings.append(unknown("Reboot required"))
    elif result.stdout == "__ABSENT__":
        findings.append(make_finding("pass", "Reboot required", "PASS", "No Debian/Ubuntu reboot-required marker"))
    else:
        findings.append(make_finding("warning", "Reboot required", "WARN", "Reboot-required marker exists", "Schedule an approved maintenance window; do not reboot automatically"))
    available = capability(ssh, server, "lynis")
    findings.append(unknown("Lynis availability") if available is None else make_finding("info", "Lynis availability", "INFO",
        "Lynis installed; no scanner was run" if available else "Lynis not installed; no scanner was run"))
    # Collect only a bounded timeline, not the potentially huge complete package log.
    result = run(ssh, server, "if test -f /var/log/dpkg.log; then tail -n 200 -- /var/log/dpkg.log; else printf '__ABSENT__'; fi", privileged=True)
    if result.exit_code != 0:
        findings.append(unknown("Recent package installs"))
    elif result.stdout == "__ABSENT__":
        findings.append(not_applicable("Recent package installs", "dpkg log unavailable on this platform"))
    else:
        count = sum(" install " in line for line in result.stdout.splitlines())
        findings.append(make_finding("info", "Recent package installs", "INFO", f"{count} install records in the last 200 package-log lines", log_lines_checked=min(len(result.stdout.splitlines()), 200)))
    versions = []
    for binary, flag in (("ssh", "-V"), ("nginx", "-v"), ("openssl", "version"), ("python3", "--version"), ("node", "--version")):
        available = capability(ssh, server, binary)
        if available is None:
            findings.append(unknown("Service version inventory", "Could not discover an optional version command"))
            continue
        if not available:
            continue
        result = run(ssh, server, binary + " " + flag)
        output = (result.stdout or result.stderr).strip().splitlines()
        if result.exit_code != 0 or not output:
            findings.append(unknown("Service version inventory", "An available version command failed"))
        else:
            versions.append(binary + ": " + output[0][:160])
    findings.append(make_finding("info", "Service version inventory", "INFO", "; ".join(versions) or "No optional version commands available", "Version inventory does not establish patch/CVE status"))
    return findings


def audit_monitoring(ssh, server: str) -> list[dict]:
    states = []
    for unit in ("zabbix-agent", "zabbix-agent2", "prometheus-node-exporter"):
        result = run(ssh, server, "systemctl is-active " + unit)
        value = result.stdout.strip()
        if result.exit_code == 0 and value == "active":
            states.append(True)
        elif result.exit_code in {3, 4} and value in {"inactive", "failed", "unknown"} and not result.stderr.strip():
            states.append(False)
        else:
            return [unknown("Monitoring agents")]
    findings = [make_finding("info", "Monitoring agents", "INFO", f"{sum(states)} known systemd monitoring agents active", "Other deployment methods and collector health are not assessed")]
    command = r"""set -e
if [ -f /etc/rsyslog.conf ]; then cat /etc/rsyslog.conf; fi
if [ -d /etc/rsyslog.d ]; then find /etc/rsyslog.d -maxdepth 1 -type f -name '*.conf' -exec cat -- {} +; fi"""
    result = run(ssh, server, command, privileged=True)
    if result.exit_code != 0:
        findings.append(unknown("Remote syslog inventory"))
    else:
        active = [line for line in result.stdout.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        forwarding = any("@@" in line or "omfwd" in line.lower() for line in active)
        findings.append(make_finding("info", "Remote syslog inventory", "INFO", "Forwarding configuration reference found" if forwarding else "No known forwarding reference found", "Receiver reachability and delivery were not verified"))
    return findings
