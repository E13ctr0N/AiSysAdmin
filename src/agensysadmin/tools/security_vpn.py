from __future__ import annotations

from agensysadmin.profiles import profile_for
from agensysadmin.tools.security_common import make_finding, unknown, run, json_result, listeners

VPN_PACKAGES = {"openvpn", "wireguard", "wireguard-tools", "softether-vpnserver",
                "pptpd", "xl2tpd", "strongswan", "ocserv", "sing-box", "xray"}
VPN_PORTS = {1194, 1195, 51820, 500, 4500, 1701, 1723}
VPN_KINDS = {"wireguard", "tun", "tap", "gre", "gretap", "ipip", "vti", "vti6", "xfrm"}
LISTENER_COMMAND = "ss -H -lntu"
_CONFIG_COMMAND = r"""set -e
for d in /etc/wireguard /etc/openvpn /etc/xl2tpd; do
  if [ -d "$d" ]; then find "$d" -maxdepth 2 -type f -name '*.conf' -print; fi
done
if [ -f /etc/strongswan.conf ]; then printf '%s\n' /etc/strongswan.conf; fi"""


def _audit_vpn(ssh, server: str) -> list[dict]:
    profile = profile_for(ssh, server)
    authorised = profile == "vpn_node"
    findings = []

    result = run(ssh, server, "dpkg-query -W -f='${binary:Package}\t${db:Status-Abbrev}\n'")
    if result.exit_code != 0:
        findings.append(unknown("VPN packages installed"))
    else:
        installed = []
        malformed = False
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) != 2:
                malformed = True
                break
            name = fields[0].split(":", 1)[0]
            if fields[1].startswith("ii") and name in VPN_PACKAGES:
                installed.append(name)
        if malformed:
            findings.append(unknown("VPN packages installed"))
        else:
            findings.append(make_finding("info" if installed else "pass", "VPN packages installed",
                "INFO" if installed else "PASS", f"{len(installed)} known VPN package names found; package inventory is not service authorization",
                "Expected for the vpn_node profile" if authorised else "Compare detected software with the server's intended role", count=len(installed)))

    result = run(ssh, server, "ip -j -d link show")
    links = json_result(result, list)
    if links is None or any(not isinstance(link, dict) or not isinstance(link.get("ifname"), str) for link in links):
        findings.append(unknown("VPN network interfaces"))
    else:
        vpn_links = []
        for link in links:
            info = link.get("linkinfo", {})
            if not isinstance(info, dict):
                continue
            kind = info.get("info_kind", "")
            if kind in VPN_KINDS:
                vpn_links.append(link["ifname"])
        findings.append(make_finding("info" if vpn_links else "pass", "VPN network interfaces",
            "INFO" if vpn_links else "PASS", f"{len(vpn_links)} tunnel-kind interfaces, including custom interface names",
            "Expected tunnel inventory" if authorised else "Review tunnel interfaces against the intended role", count=len(vpn_links)))

    result = run(ssh, server, _CONFIG_COMMAND, privileged=True)
    if result.exit_code != 0:
        findings.append(unknown("VPN config files"))
    else:
        paths = [line for line in result.stdout.splitlines() if line]
        if any(not path.startswith("/") or any(ord(c) < 32 for c in path) for path in paths):
            findings.append(unknown("VPN config files"))
        else:
            findings.append(make_finding("info" if paths else "pass", "VPN config files",
                "INFO" if paths else "PASS", f"{len(paths)} config files in known VPN locations; contents were not collected",
                "Review file permissions and ownership separately", count=len(paths)))

    result = run(ssh, server, LISTENER_COMMAND)
    endpoints = listeners(result.stdout) if result.exit_code == 0 else None
    if endpoints is None:
        findings.append(unknown("VPN ports listening"))
    else:
        selected = [item for item in endpoints if item["port"] in VPN_PORTS]
        findings.append(make_finding("info" if selected else "pass", "VPN ports listening",
            "INFO" if selected else "PASS", f"{len(selected)} TCP/UDP IPv4/IPv6 listeners on known VPN ports; custom ports require role-specific review",
            "Expected for the vpn_node profile" if authorised else "Verify listener ownership; a port number alone does not identify a VPN", count=len(selected),
            protocols=sorted({item["protocol"] for item in selected})))
    return findings
