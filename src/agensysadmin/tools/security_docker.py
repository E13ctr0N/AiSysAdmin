from __future__ import annotations

import json
import re
import shlex

from agensysadmin.profiles import profile_for

from agensysadmin.tools.security_common import make_finding, unknown, not_applicable, run, listeners, capability
from agensysadmin.tools.security_vpn import LISTENER_COMMAND

MAX_CONTAINERS = 200
MAX_COMPOSE_FILES = 100
_CONTAINER_ID = re.compile(r"[a-fA-F0-9]{12,64}\Z")
_INSPECT_FORMAT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"HostConfig":{'
    '"Privileged":{{json .HostConfig.Privileged}},"NetworkMode":{{json .HostConfig.NetworkMode}},'
    '"PidMode":{{json .HostConfig.PidMode}},"CapAdd":{{json .HostConfig.CapAdd}}},"Mounts":{{json .Mounts}}}')
_COMPOSE_DISCOVERY = r"""set -e
for d in /etc /srv /opt /var/www; do
  if [ -d "$d" ]; then
    find "$d" -maxdepth 5 -type f \( -name docker-compose.yml -o -name docker-compose.yaml -o -name compose.yml -o -name compose.yaml \) -print
  fi
done"""


def _inspect_objects(text: str):
    try:
        parsed = json.loads(text)
        objects = parsed if isinstance(parsed, list) else [parsed]
    except ValueError:
        try:
            objects = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError:
            return None
    return objects if all(isinstance(item, dict) for item in objects) else None


def _container_findings(ssh, server: str) -> list[dict]:
    labels = ("Privileged containers", "Dangerous mounts", "Host network/PID", "Added capabilities")
    result = run(ssh, server, "docker ps --no-trunc --format '{{.ID}}'", privileged=True)
    if result.exit_code != 0:
        return [unknown(label) for label in labels]
    ids = list(dict.fromkeys(line.strip() for line in result.stdout.splitlines() if line.strip()))
    if any(not _CONTAINER_ID.fullmatch(cid) for cid in ids):
        return [unknown(label, "Docker returned an invalid container identifier") for label in labels]
    if not ids:
        return [not_applicable(label, "No running containers") for label in labels]
    selected = ids[:MAX_CONTAINERS]
    command = "docker inspect --format " + shlex.quote(_INSPECT_FORMAT) + " -- " + " ".join(shlex.quote(cid) for cid in selected)
    result = run(ssh, server, command, privileged=True)
    objects = _inspect_objects(result.stdout) if result.exit_code == 0 else None
    if objects is None:
        return [unknown(label, "Container inspection failed or returned malformed JSON", checked=0, total=len(ids), complete=False) for label in labels]
    valid = []
    for item in objects:
        host = item.get("HostConfig")
        mounts = item.get("Mounts")
        if (item.get("Id") not in selected or not isinstance(host, dict) or
            type(host.get("Privileged")) is not bool or
            not isinstance(host.get("NetworkMode"), str) or not isinstance(host.get("PidMode"), str) or
            not (host.get("CapAdd") is None or isinstance(host.get("CapAdd"), list)) or
            not isinstance(mounts, list) or any(not isinstance(m, dict) or not isinstance(m.get("Source"), str) for m in mounts)):
            return [unknown(label, "Incomplete container inspection fields", checked=len(valid), total=len(ids), complete=False) for label in labels]
        valid.append(item)
    if len(valid) != len(selected) or {x["Id"] for x in valid} != set(selected):
        return [unknown(label, "Container set changed during inspection", checked=len(valid), total=len(ids), complete=False) for label in labels]
    coverage = {"checked": len(valid), "total": len(ids), "complete": len(valid) == len(ids)}
    dangerous = {
        "Privileged containers": sum(item["HostConfig"]["Privileged"] for item in valid),
        "Dangerous mounts": sum(any(m["Source"] in {"/", "/etc", "/root", "/var/run", "/run"} or m["Source"].endswith("/docker.sock") for m in item["Mounts"]) for item in valid),
        "Host network/PID": sum(item["HostConfig"]["NetworkMode"] == "host" or item["HostConfig"]["PidMode"] == "host" for item in valid),
        "Added capabilities": sum(bool(item["HostConfig"]["CapAdd"]) for item in valid),
    }
    findings = []
    for label, count in dangerous.items():
        severity = "critical" if label in {"Privileged containers", "Dangerous mounts"} else "warning"
        if count:
            findings.append(make_finding(severity, label, "FAIL" if severity == "critical" else "WARN",
                f"{count} of {len(valid)} inspected containers require review", "Review the service's required isolation before changing it", **coverage))
        elif not coverage["complete"]:
            findings.append(unknown(label, "Container inventory exceeded the bounded inspection limit", **coverage))
        else:
            findings.append(make_finding("pass", label, "PASS", f"No flagged settings in {len(valid)} inspected containers", **coverage))
    if not coverage["complete"]:
        findings.append(unknown("Docker container coverage", f"Inspected {len(valid)} of {len(ids)} containers", **coverage))
    return findings


def _compose_findings(ssh, server: str) -> list[dict]:
    result = run(ssh, server, _COMPOSE_DISCOVERY, privileged=True)
    if result.exit_code != 0:
        return [unknown("Compose sensitive fields")]
    paths = list(dict.fromkeys(line for line in result.stdout.splitlines() if line))
    if any(not path.startswith("/") or any(ord(char) < 32 for char in path) for path in paths):
        return [unknown("Compose sensitive fields", "Invalid file path in discovery results")]
    found = 0
    for path in paths[:MAX_COMPOSE_FILES]:
        command = ("if grep -qiE '(password|secret|token|api_key)[[:space:]]*[:=]' -- " + shlex.quote(path) +
                   '; then printf found; else rc=$?; [ "$rc" -eq 1 ] || exit "$rc"; printf absent; fi')
        result = run(ssh, server, command, privileged=True)
        if result.exit_code != 0 or result.stdout not in {"found", "absent"}:
            return [unknown("Compose sensitive fields", checked=min(len(paths), MAX_COMPOSE_FILES), total=len(paths), complete=False)]
        found += result.stdout == "found"
    if len(paths) > MAX_COMPOSE_FILES:
        return [unknown("Compose sensitive fields", "Discovery exceeded the bounded inspection limit", checked=MAX_COMPOSE_FILES, total=len(paths), complete=False)]
    return [make_finding("info", "Compose sensitive fields", "INFO",
        f"{found} of {len(paths)} files contain sensitive-field names; values were not collected and exposure was not verified",
        "Review interpolation, Docker secrets and file access separately", checked=len(paths), total=len(paths), complete=True)]


def _audit_docker_security(ssh, server: str) -> list[dict]:
    available = capability(ssh, server, "docker")
    if available is None:
        return [unknown("Docker installed")]
    if not available:
        if profile_for(ssh, server) == "docker_host":
            return [make_finding("warning", "Docker installed", "WARN", "Docker executable missing from a docker_host profile", "Verify the profile and intended Docker runtime before installing anything")]
        return [not_applicable("Docker installed", "Docker executable not found")]
    findings = [make_finding("info", "Docker installed", "INFO", "Docker executable available; daemon access is checked separately")]
    result = run(ssh, server, LISTENER_COMMAND)
    endpoints = listeners(result.stdout) if result.exit_code == 0 else None
    if endpoints is None:
        findings.append(unknown("Docker API exposure"))
    else:
        api = [item for item in endpoints if item["protocol"] == "tcp" and item["port"] in {2375, 2376}]
        external = [item for item in api if not item["loopback"]]
        if external:
            findings.append(unknown("Docker API exposure", "Docker API port bound outside loopback; TLS/authentication and firewall reachability are unverified", tls_verified=False, listeners=len(external)))
        else:
            findings.append(make_finding("info" if api else "pass", "Docker API exposure", "INFO" if api else "PASS",
                "Only loopback Docker API bindings observed" if api else "No TCP listener on conventional Docker API ports",
                "A port inventory does not verify Unix-socket access or alternate API ports", tls_verified=False))
    findings.extend(_container_findings(ssh, server))
    scanner = capability(ssh, server, "trivy")
    findings.append(unknown("Trivy availability") if scanner is None else make_finding("info", "Trivy availability", "INFO",
        "Trivy installed; no CVE scan was run" if scanner else "Trivy not installed; no CVE scan was run"))
    findings.extend(_compose_findings(ssh, server))
    return findings
