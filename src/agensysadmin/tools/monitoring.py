from __future__ import annotations

import re

from agensysadmin.ssh_manager import SSHManager


def system_info_impl(ssh: SSHManager, server: str) -> dict:
    uname = ssh.execute(server, "uname -a").stdout.strip()
    uptime = ssh.execute(server, "uptime -p").stdout.strip()
    free_output = ssh.execute(server, "free -b").stdout
    cpu_cores = int(ssh.execute(server, "nproc").stdout.strip())
    loadavg = ssh.execute(server, "cat /proc/loadavg").stdout.strip()

    memory = _parse_free(free_output)

    return {
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
    output = ssh.execute(server, "df -h --output=source,size,used,avail,pcent,target").stdout
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
    return {"filesystems": filesystems}


def check_services_impl(
    ssh: SSHManager, server: str, services: list[str] | None = None
) -> dict:
    if services:
        result_services = {}
        for svc in services:
            output = ssh.execute(server, f"systemctl status {svc}")
            active = "active (running)" in output.stdout
            result_services[svc] = {
                "active": active,
                "raw_output": output.stdout.strip(),
            }
        return {"services": result_services}
    else:
        output = ssh.execute(
            server, "systemctl list-units --type=service --state=running --no-pager"
        )
        return {"raw_output": output.stdout.strip()}


def check_ports_impl(ssh: SSHManager, server: str) -> dict:
    output = ssh.execute(server, "ss -tlnp").stdout
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
    return {"ports": ports}


def process_list_impl(
    ssh: SSHManager, server: str, sort_by: str = "cpu"
) -> dict:
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
