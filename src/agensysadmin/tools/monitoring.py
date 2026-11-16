from __future__ import annotations

import re

from agensysadmin.ssh_manager import SSHManager
from agensysadmin.validation import shell_quote, validate_service_name


def system_info_impl(ssh: SSHManager, server: str) -> dict:
    uname_result = ssh.execute(server, "uname -a")
    uptime_result = ssh.execute(server, "uptime -p")
    free_result = ssh.execute(server, "free -b")
    nproc_result = ssh.execute(server, "nproc")
    loadavg_result = ssh.execute(server, "cat /proc/loadavg")
    results = [uname_result, uptime_result, free_result, nproc_result, loadavg_result]
    failures = [result for result in results if result.exit_code != 0]
    if failures:
        return {
            "success": False,
            "complete": False,
            "error_type": _command_error_type(failures[0].exit_code),
        }

    try:
        uname = uname_result.stdout.strip()
        uptime = uptime_result.stdout.strip()
        free_output = free_result.stdout
        cpu_cores = int(nproc_result.stdout.strip())
        loadavg = loadavg_result.stdout.strip()
        memory = _parse_free(free_output)
        if not uname or not uptime or cpu_cores < 1 or len(loadavg.split()) < 3 or "mem" not in memory:
            raise ValueError("incomplete system information")
    except (IndexError, ValueError):
        return {"success": False, "complete": False, "error_type": "ParseError"}

    return {
        "success": True,
        "complete": True,
        "uname": uname,
        "uptime": uptime,
        "cpu_cores": cpu_cores,
        "load_average": " ".join(loadavg.split()[:3]),
        "memory": memory.get("mem", {}),
        "swap": memory.get("swap", {}),
    }


def _parse_free(output: str) -> dict:
    result = {}
    lines = output.strip().split("\n")
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        label = parts[0].lower().rstrip(":")
        if label == "mem":
            result["mem"] = {
                "total": int(parts[1]),
                "used": int(parts[2]),
                "free": int(parts[3]),
                "available": int(parts[6]) if len(parts) > 6 else None,
            }
        elif label == "swap":
            result["swap"] = {
                "total": int(parts[1]),
                "used": int(parts[2]),
                "free": int(parts[3]),
            }
    return result


def disk_usage_impl(ssh: SSHManager, server: str) -> dict:
    result = ssh.execute(server, "df -h --output=source,size,used,avail,pcent,target")
    if result.exit_code != 0:
        return {
            "success": False,
            "complete": False,
            "error_type": _command_error_type(result.exit_code),
            "filesystems": [],
        }
    output = result.stdout
    lines = output.strip().split("\n")
    filesystems = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            filesystems.append({
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "use_percent": parts[4],
                "mounted_on": parts[5],
            })
    return {"success": True, "complete": True, "filesystems": filesystems}


def check_services_impl(
    ssh: SSHManager, server: str, services: list[str] | None = None
) -> dict:
    if services:
        result_services = {}
        complete = True
        for svc in services:
            svc = validate_service_name(svc)
            output = ssh.execute(server, f"systemctl status --no-pager -- {shell_quote(svc)}")
            known_state = (
                output.exit_code in {0, 3} and "Active:" in output.stdout
            ) or (
                output.exit_code == 4 and (
                    "Loaded: not-found" in output.stdout
                    or "could not be found" in output.stdout.lower()
                )
            )
            if not known_state:
                complete = False
            active = "active (running)" in output.stdout
            result_services[svc] = {
                "active": active,
                "raw_output": output.stdout.strip(),
            }
        return {
            "success": complete,
            "complete": complete,
            "error_type": None if complete else "CommandFailed",
            "services": result_services,
        }
    else:
        output = ssh.execute(
            server, "systemctl list-units --type=service --state=running --no-pager"
        )
        if output.exit_code != 0:
            return {
                "success": False,
                "complete": False,
                "error_type": _command_error_type(output.exit_code),
                "raw_output": output.stdout.strip(),
            }
        return {"success": True, "complete": True, "raw_output": output.stdout.strip()}


def check_ports_impl(ssh: SSHManager, server: str) -> dict:
    result = ssh.execute(server, "ss -tlnp")
    if result.exit_code != 0:
        return {
            "success": False,
            "complete": False,
            "error_type": _command_error_type(result.exit_code),
            "ports": [],
        }
    output = result.stdout
    lines = output.strip().split("\n")
    ports = []
    for line in lines:
        if "LISTEN" not in line:
            continue
        parts = line.split()
        # Parse local address:port (ss columns: Netid State Recv-Q Send-Q LocalAddr:Port ...)
        local_addr = parts[4] if len(parts) > 4 else ""
        port_match = re.search(r":(\d+)$", local_addr)
        port = int(port_match.group(1)) if port_match else 0

        # Parse process name from users:(("name",pid=N,fd=N))
        process = ""
        process_match = re.search(r'\("([^"]+)"', line)
        if process_match:
            process = process_match.group(1)

        ports.append({"port": port, "address": local_addr, "process": process})
    return {"success": True, "complete": True, "ports": ports}


def _command_error_type(exit_code: int) -> str:
    return "CommandUnavailable" if exit_code == 127 else "CommandFailed"


def process_list_impl(
    ssh: SSHManager, server: str, sort_by: str = "cpu"
) -> dict:
    if sort_by not in {"cpu", "memory"}:
        raise ValueError("sort_by must be 'cpu' or 'memory'")
    # Use ps with custom output format: pid, user, %cpu, %mem, rss, command
    # Sort flag: k-%cpu (descending) or k-%mem (descending) — note: ps k sorts ascending,
    # so we use --sort=-%cpu for descending CPU order.
    sort_flag = "-%cpu" if sort_by == "cpu" else "-%mem"
    output = ssh.execute(
        server,
        f"ps -eo pid,user,%cpu,%mem,rss,comm --sort={sort_flag} | head -21",
    ).stdout
    lines = output.strip().split("\n")
    processes = []
    for line in lines[1:]:  # skip header
        parts = line.split(None, 5)
        if len(parts) >= 6:
            processes.append({
                "pid": int(parts[0]),
                "user": parts[1],
                "cpu_percent": float(parts[2]),
                "mem_percent": float(parts[3]),
                "rss_kb": int(parts[4]),
                "command": parts[5],
            })
    return {"processes": processes}
