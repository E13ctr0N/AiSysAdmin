from __future__ import annotations

PROFILES = frozenset({"generic", "vpn_node", "docker_host", "web", "database"})


def profile_for(ssh, server: str) -> str:
    """Return an operator-owned profile; unknown/mock values remain generic."""
    value = ssh.server_profile(server) if callable(getattr(ssh, "server_profile", None)) else "generic"
    return value if isinstance(value, str) and value in PROFILES else "generic"


def forwarding_expected(profile: str) -> str | None:
    return {"vpn_node": "1", "docker_host": "1", "web": "0", "database": "0"}.get(profile)
