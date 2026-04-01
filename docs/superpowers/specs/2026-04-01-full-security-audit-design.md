# Full Security Audit — Design Spec

**Date:** 2026-04-01
**Scope:** One-shot security audit tool for Debian/Ubuntu servers
**Approach:** Monolithic function in `security.py` (Approach A)

## Overview

A single MCP tool `full_security_audit` that runs ~50 checks across 10 categories, returns a scored JSON response with all findings, and generates a Markdown report. Works on both new and existing servers.

## MCP Tool Interface

```
Tool: full_security_audit
Args: server (str)
Returns: JSON with score, grade, findings, and report_markdown
```

## Response Structure

```python
{
  "score": 62,              # 0-100, weighted average across categories
  "grade": "C",             # A (90+) / B (70-89) / C (50-69) / D (30-49) / F (<30)
  "summary": {
    "critical": 3,
    "warning": 5,
    "info": 8,
    "pass": 12
  },
  "categories": {
    "ssh": {"score": 40, "findings": [...]},
    "firewall": {"score": 0, "findings": [...]},
    ...
  },
  "report_markdown": "# Security Audit Report\n..."
}
```

### Finding Structure

```python
{
  "severity": "critical",       # critical / warning / info / pass
  "check": "SSH root login",
  "status": "FAIL",             # FAIL / WARN / INFO / PASS
  "detail": "PermitRootLogin yes",
  "recommendation": "Set PermitRootLogin to no in /etc/ssh/sshd_config"
}
```

## Categories and Checks

### 1. SSH (weight: 15%)

| Check | Severity if FAIL |
|---|---|
| PermitRootLogin != yes | critical |
| PasswordAuthentication != yes | warning |
| PubkeyAuthentication = yes | warning |
| Port != 22 | info |
| MaxAuthTries <= 3 | warning |
| AllowUsers or AllowGroups set | info |

### 2. Firewall (weight: 15%)

| Check | Severity if FAIL |
|---|---|
| ufw / iptables / nftables installed and active | critical |
| Default INPUT policy = DROP/DENY | critical |
| Number of rules reported | info |

### 3. Users & Auth (weight: 15%)

| Check | Severity if FAIL |
|---|---|
| No extra UID 0 users besides root | critical |
| No accounts with empty passwords | critical |
| No inactive accounts (>90 days no login) | warning |
| No NOPASSWD in sudoers | warning |

### 4. Network (weight: 10%)

| Check | Severity if FAIL |
|---|---|
| Listening ports on 0.0.0.0 (enumerate) | info |
| Suspicious outbound connections | warning |
| IPv6 enabled without need | info |

### 5. Filesystem (weight: 10%)

| Check | Severity if FAIL |
|---|---|
| Non-standard SUID/SGID binaries | warning |
| World-writable files outside /tmp | warning |
| /tmp, /var/tmp have noexec/nosuid | warning |
| Correct permissions on /etc/shadow, /etc/passwd, /etc/ssh/ | critical |

### 6. Services (weight: 5%)

| Check | Severity if FAIL |
|---|---|
| List running daemons | info |
| Unnecessary services (avahi, cups, rpcbind, etc.) | warning |
| No xinetd/inetd running | warning |

### 7. Updates (weight: 10%)

| Check | Severity if FAIL |
|---|---|
| Pending package updates count | warning |
| Security-only updates pending | critical |
| Kernel version vs available | warning |
| Unattended-upgrades configured | warning |

### 8. Logs & Audit (weight: 5%)

| Check | Severity if FAIL |
|---|---|
| fail2ban installed and active | warning |
| auditd installed and active | info |
| Logrotate configured | info |
| Failed login count from auth.log | info |
| Last 10 sudo commands | info |

### 9. Kernel & Sysctl (weight: 10%)

| Check | Severity if FAIL |
|---|---|
| net.ipv4.ip_forward = 0 | warning |
| net.ipv4.tcp_syncookies = 1 | warning |
| net.ipv4.conf.all.rp_filter = 1 | warning |
| net.ipv4.conf.all.accept_redirects = 0 | warning |
| net.ipv4.conf.all.send_redirects = 0 | warning |
| kernel.randomize_va_space = 2 (ASLR) | critical |
| fs.protected_hardlinks = 1 | warning |
| fs.protected_symlinks = 1 | warning |

### 10. Malware/Rootkit (weight: 5%)

| Check | Severity if FAIL |
|---|---|
| Suspicious crontab entries (all users) | warning |
| Processes without on-disk binary | critical |
| Known rootkit files/paths | critical |
| Hidden files in /tmp, /dev/shm | warning |
| Suspicious entries in /etc/hosts | warning |

## Scoring

- Each category score: `pass_count / total_checks * 100`
- A critical finding in a category sets that category score to 0
- Overall score: weighted average of category scores
- Grade thresholds: A (90+), B (70-89), C (50-69), D (30-49), F (<30)

### Category Weights

| Category | Weight |
|---|---|
| SSH | 15% |
| Firewall | 15% |
| Users & Auth | 15% |
| Network | 10% |
| Filesystem | 10% |
| Services | 5% |
| Updates | 10% |
| Logs & Audit | 5% |
| Kernel & Sysctl | 10% |
| Malware/Rootkit | 5% |

## Markdown Report Format

```markdown
# Security Audit Report
**Server:** {hostname} ({ip})
**Date:** {date}
**Score:** {score}/100 (Grade: {grade})

## Summary
- Critical: {n}
- Warning: {n}
- Info: {n}
- Pass: {n}

## SSH (score: {n}/100)
| Status | Check | Detail |
|---|---|---|
| FAIL | Root login | PermitRootLogin yes |
| PASS | Pubkey auth | PubkeyAuthentication yes |
...

## Firewall (score: {n}/100)
...

## Recommendations
1. [CRITICAL] Set PermitRootLogin to no in /etc/ssh/sshd_config
2. [CRITICAL] Install and enable ufw
3. [WARNING] Install fail2ban
...
```

## Implementation

- File: `src/agensysadmin/tools/security.py`
- Function: `full_security_audit_impl(ssh, server) -> dict`
- Register as MCP tool in `server.py`
- Existing `security_audit` tool remains unchanged (backward compat)
- Timeout: 120 seconds (many SSH commands sequentially)

## Known Limitations

- SUID/SGID check compares against a hardcoded known-good list for Debian/Ubuntu
- Rootkit checks are basic pattern matching, not a replacement for rkhunter/chkrootkit
- Network connection analysis is point-in-time, not continuous monitoring
- No CIS Benchmark scoring — this is a practical checklist, not compliance
