from __future__ import annotations

import ipaddress
import json
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .config import db_connect

SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 5}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    details: str
    confidence: str = "medium"


@dataclass
class ScanResult:
    created_at: str
    context: dict[str, Any]
    findings: list[Finding]

    @property
    def risk_score(self) -> int:
        return min(100, sum(SEVERITY_POINTS.get(f.severity, 0) for f in self.findings))


def run_command(command: list[str]) -> str:
    if not shutil.which(command[0]):
        return ""
    try:
        cp = subprocess.run(command, capture_output=True, text=True, check=False, timeout=3)
        return cp.stdout.strip()
    except Exception:
        return ""


def collect_network_context() -> dict[str, Any]:
    host = socket.gethostname()
    ip = ""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = ""

    context: dict[str, Any] = {
        "hostname": host,
        "platform": platform.platform(),
        "adapter": "unknown",
        "ip": ip,
        "gateway": "",
        "dns": [],
        "ssid": "",
        "bssid": "",
        "auth": "unknown",
        "encryption": "unknown",
    }

    system = platform.system().lower()
    if system == "linux":
        _fill_linux_context(context)
    elif system == "darwin":
        _fill_macos_context(context)
    elif system == "windows":
        _fill_windows_context(context)

    return context


def _fill_linux_context(ctx: dict[str, Any]) -> None:
    route = run_command(["ip", "route"])
    for line in route.splitlines():
        if line.startswith("default via"):
            parts = line.split()
            if len(parts) >= 5:
                ctx["gateway"] = parts[2]
                ctx["adapter"] = parts[4]

    resolv = run_command(["cat", "/etc/resolv.conf"])
    dns = []
    for line in resolv.splitlines():
        if line.strip().startswith("nameserver"):
            toks = line.split()
            if len(toks) >= 2:
                dns.append(toks[1])
    ctx["dns"] = dns

    wifi = run_command(["iwgetid", "-r"])
    if wifi:
        ctx["ssid"] = wifi


def _fill_macos_context(ctx: dict[str, Any]) -> None:
    route = run_command(["route", "-n", "get", "default"])
    for line in route.splitlines():
        if "gateway:" in line:
            ctx["gateway"] = line.split("gateway:")[-1].strip()
    dns = run_command(["scutil", "--dns"])
    servers = re.findall(r"nameserver\[[0-9]+\] : ([^\s]+)", dns)
    ctx["dns"] = servers


def _fill_windows_context(ctx: dict[str, Any]) -> None:
    out = run_command(["ipconfig", "/all"])
    gw = re.findall(r"Default Gateway[ .:]*([0-9a-fA-F:\.]+)", out)
    if gw:
        ctx["gateway"] = gw[0]
    dns = re.findall(r"DNS Servers[ .:]*([0-9\.]+)", out)
    ctx["dns"] = dns


def run_scan() -> ScanResult:
    context = collect_network_context()
    findings = run_rules(context)
    result = ScanResult(
        created_at=datetime.now(timezone.utc).isoformat(),
        context=context,
        findings=findings,
    )
    persist_scan(result)
    return result


def run_rules(context: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    auth = (context.get("auth") or "").lower()
    if auth in {"open", "none"}:
        findings.append(Finding("critical", "wifi", "Open Wi-Fi detected", "No link-layer auth detected.", "high"))
    elif auth == "wep":
        findings.append(Finding("high", "wifi", "WEP security detected", "WEP is obsolete and unsafe.", "high"))
    elif auth in {"wpa", "wpa2"}:
        findings.append(Finding("low", "wifi", "Legacy Wi-Fi mode", "Prefer WPA3 if available.", "medium"))

    dns = context.get("dns", [])
    if not dns:
        findings.append(Finding("medium", "dns", "No DNS resolvers detected", "Unable to validate resolver trust."))
    else:
        for server in dns:
            if _is_public_resolver(server):
                findings.append(Finding("low", "dns", "Public DNS in use", f"Resolver {server} is public; verify policy.", "low"))

    gw = context.get("gateway") or ""
    if not gw:
        findings.append(Finding("high", "gateway", "Gateway not detected", "Could indicate route manipulation or collection failure."))
    elif not _same_subnet(context.get("ip", ""), gw):
        findings.append(Finding("medium", "gateway", "Gateway/IP subnet mismatch", "Potential ARP/gateway drift signal."))

    findings.extend(_safe_gateway_probe(gw))
    findings.append(Finding("low", "stack", "Network stack age heuristic", "Unable to confirm latest driver/stack patch level locally.", "low"))
    return findings


def _is_public_resolver(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False


def _same_subnet(ip1: str, ip2: str) -> bool:
    try:
        a = ipaddress.ip_address(ip1)
        b = ipaddress.ip_address(ip2)
    except ValueError:
        return True
    if a.version != b.version:
        return False
    if a.version == 4:
        return ipaddress.ip_network(f"{ip1}/24", strict=False) == ipaddress.ip_network(f"{ip2}/24", strict=False)
    return True


def _safe_gateway_probe(gateway: str) -> list[Finding]:
    if not gateway:
        return []
    flagged: list[Finding] = []
    for port in (22, 23, 80, 443):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            if sock.connect_ex((gateway, port)) == 0:
                sev = "low" if port in (80, 443) else "medium"
                flagged.append(Finding(sev, "gateway", f"Gateway port {port} open", "Open management plane increases surface area.", "medium"))
        except Exception:
            pass
        finally:
            sock.close()
    return flagged


def persist_scan(result: ScanResult) -> int:
    conn = db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scans(created_at, risk_score, context_json) VALUES (?, ?, ?)",
            (result.created_at, result.risk_score, json.dumps(result.context)),
        )
        scan_id = int(cur.lastrowid)
        cur.executemany(
            "INSERT INTO findings(scan_id, severity, category, title, details, confidence) VALUES (?, ?, ?, ?, ?, ?)",
            [(scan_id, f.severity, f.category, f.title, f.details, f.confidence) for f in result.findings],
        )
        conn.commit()
        return scan_id
    finally:
        conn.close()


def recent_scans(limit: int = 20) -> list[dict[str, Any]]:
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT id, created_at, risk_score, context_json FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for row in rows:
            findings = conn.execute(
                "SELECT severity, category, title, details, confidence FROM findings WHERE scan_id = ?", (row["id"],)
            ).fetchall()
            out.append(
                {
                    "id": row["id"],
                    "created_at": row["created_at"],
                    "risk_score": row["risk_score"],
                    "context": json.loads(row["context_json"]),
                    "findings": [dict(f) for f in findings],
                }
            )
        return out
    finally:
        conn.close()
