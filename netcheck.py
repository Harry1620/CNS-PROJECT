#!/usr/bin/env python3
"""NetCheck CLI: local network posture checks with optional AI config."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import subprocess
import threading
import time
import webbrowser
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APP_DIR = Path.home() / ".netcheck"
CONFIG_PATH = APP_DIR / "config.json"
DB_PATH = APP_DIR / "netcheck.db"
LOG_PATH = APP_DIR / "logs"

DEFAULT_CONFIG = {
    "version": 1,
    "data_dir": str(APP_DIR),
    "bind_host": "127.0.0.1",
    "bind_port": 8765,
    "ai": {
        "provider": "none",
        "model": "",
        "base_url": "",
        "key_env": "",
        "send_full_context": False,
    },
    "watch": {"interval_seconds": 5},
}


@dataclass
class NetworkSnapshot:
    timestamp: str
    hostname: str
    interface: str
    ip: str
    gateway: str
    dns: list[str]
    ssid: str
    bssid: str
    wifi_auth: str


class NetCheckStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def init(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    findings_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_scan(self, snapshot: dict[str, Any], findings: list[dict[str, Any]], risk_score: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO scans(created_at, risk_score, snapshot_json, findings_json) VALUES(?, ?, ?, ?)",
                (
                    now_iso(),
                    risk_score,
                    json.dumps(snapshot),
                    json.dumps(findings),
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def latest_scan(self) -> dict[str, Any] | None:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "SELECT id, created_at, risk_score, snapshot_json, findings_json FROM scans ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "created_at": row[1],
            "risk_score": row[2],
            "snapshot": json.loads(row[3]),
            "findings": json.loads(row[4]),
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        return p.stdout.strip()
    except Exception:
        return ""


def detect_dns() -> list[str]:
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            vals = []
            for line in resolv.read_text(errors="ignore").splitlines():
                if line.strip().startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        vals.append(parts[1])
            return vals
    if system == "Windows":
        output = run_command(["ipconfig", "/all"])
        vals = []
        for line in output.splitlines():
            if "DNS Servers" in line:
                if ":" in line:
                    vals.append(line.split(":", 1)[1].strip())
        return [v for v in vals if v]
    return []


def detect_gateway() -> str:
    system = platform.system()
    if system == "Linux":
        out = run_command(["ip", "route"])
        for line in out.splitlines():
            if line.startswith("default via"):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    if system == "Darwin":
        out = run_command(["route", "-n", "get", "default"])
        for line in out.splitlines():
            if "gateway:" in line:
                return line.split("gateway:", 1)[1].strip()
    if system == "Windows":
        out = run_command(["ipconfig"])
        for line in out.splitlines():
            if "Default Gateway" in line and ":" in line:
                val = line.split(":", 1)[1].strip()
                if val:
                    return val
    return "unknown"


def detect_network_snapshot() -> NetworkSnapshot:
    hostname = platform.node() or "unknown"
    ip = run_command(["hostname", "-I"]).split()[0] if platform.system() != "Windows" else "unknown"
    if not ip:
        ip = "unknown"
    gateway = detect_gateway()
    dns = detect_dns()
    return NetworkSnapshot(
        timestamp=now_iso(),
        hostname=hostname,
        interface="active",
        ip=ip,
        gateway=gateway,
        dns=dns,
        ssid="unknown",
        bssid="unknown",
        wifi_auth="unknown",
    )


def severity_score(sev: str) -> int:
    return {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(sev, 0)


def deterministic_findings(snapshot: NetworkSnapshot) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if snapshot.gateway == "unknown":
        findings.append(
            {
                "id": "gateway-missing",
                "severity": "high",
                "title": "Gateway not detected",
                "detail": "Default gateway could not be detected; route checks are limited.",
                "confidence": "high",
            }
        )
    suspicious_dns = {"0.0.0.0", "127.0.0.1"}
    for d in snapshot.dns:
        if d in suspicious_dns:
            findings.append(
                {
                    "id": "dns-suspicious",
                    "severity": "high",
                    "title": "Potentially suspicious DNS resolver",
                    "detail": f"Resolver {d} may indicate interception or local tampering.",
                    "confidence": "medium",
                }
            )

    auth = snapshot.wifi_auth.lower()
    if auth in {"open", "wep"}:
        sev = "critical" if auth == "open" else "high"
        findings.append(
            {
                "id": "wifi-weak-auth",
                "severity": sev,
                "title": f"Weak Wi-Fi auth: {snapshot.wifi_auth}",
                "detail": "Use WPA2 or WPA3 where possible.",
                "confidence": "high",
            }
        )
    elif auth == "unknown":
        findings.append(
            {
                "id": "wifi-auth-unknown",
                "severity": "low",
                "title": "Wi-Fi auth unknown",
                "detail": "Could not inspect Wi-Fi auth details on this platform/session.",
                "confidence": "high",
            }
        )
    if not snapshot.dns:
        findings.append(
            {
                "id": "dns-missing",
                "severity": "medium",
                "title": "No DNS servers detected",
                "detail": "DNS configuration unavailable; name resolution risk cannot be assessed.",
                "confidence": "high",
            }
        )
    return findings


def compute_risk_score(findings: list[dict[str, Any]]) -> int:
    score = sum(severity_score(f["severity"]) for f in findings)
    return min(score, 100)


def ensure_config() -> dict[str, Any]:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_PATH.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    with CONFIG_PATH.open() as f:
        cfg = json.load(f)
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def cmd_init(_args: argparse.Namespace) -> int:
    cfg = ensure_config()
    NetCheckStore(DB_PATH).init()
    print(f"Initialized NetCheck at {cfg['data_dir']}")
    return 0


def do_scan() -> dict[str, Any]:
    cfg = ensure_config()
    store = NetCheckStore(DB_PATH)
    store.init()
    snap = detect_network_snapshot()
    findings = deterministic_findings(snap)
    risk_score = compute_risk_score(findings)
    scan_id = store.save_scan(asdict(snap), findings, risk_score)
    return {
        "scan_id": scan_id,
        "risk_score": risk_score,
        "snapshot": asdict(snap),
        "findings": findings,
        "ai_provider": cfg.get("ai", {}).get("provider", "none"),
    }


def cmd_scan(_args: argparse.Namespace) -> int:
    result = do_scan()
    print(json.dumps(result, indent=2))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    ensure_config()
    store = NetCheckStore(DB_PATH)
    store.init()
    latest = store.latest_scan()
    if not latest:
        print("No scans found. Run `netcheck scan` first.")
        return 1
    if args.json:
        print(json.dumps(latest, indent=2))
    else:
        print(f"Scan #{latest['id']} risk={latest['risk_score']}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    cfg = ensure_config()
    interval = int(args.interval or cfg.get("watch", {}).get("interval_seconds", 5))
    print(f"Watching network changes every {interval}s. Ctrl+C to stop.")
    prev_sig = None
    try:
        while True:
            snap = detect_network_snapshot()
            sig = (snap.ssid, snap.bssid, snap.gateway, tuple(snap.dns))
            if sig != prev_sig:
                result = do_scan()
                print(f"[{now_iso()}] change detected -> scan #{result['scan_id']} risk={result['risk_score']}")
                prev_sig = sig
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped watch.")
        return 0


def ai_env_ok(cfg: dict[str, Any]) -> tuple[bool, str]:
    ai = cfg.get("ai", {})
    provider = ai.get("provider", "none")
    if provider == "none":
        return True, "AI disabled by provider=none"
    if provider == "openai":
        return (bool(os.getenv("OPENAI_API_KEY")), "Missing OPENAI_API_KEY")
    if provider == "claude":
        return (bool(os.getenv("ANTHROPIC_API_KEY")), "Missing ANTHROPIC_API_KEY")
    if provider == "copilot":
        return (bool(os.getenv("GITHUB_TOKEN")), "Missing GITHUB_TOKEN")
    if provider == "opencode":
        key_env = ai.get("key_env") or "OPENCODE_API_KEY"
        return (bool(os.getenv(key_env)) and bool(ai.get("base_url")), f"Missing {key_env} or base_url")
    return False, f"Unknown provider: {provider}"


def cmd_ai(args: argparse.Namespace) -> int:
    cfg = ensure_config()
    ai = cfg.setdefault("ai", DEFAULT_CONFIG["ai"].copy())
    if args.ai_cmd == "setup":
        print("Supported providers: none, openai, claude, copilot, opencode")
        return 0
    if args.ai_cmd == "set":
        ai["provider"] = args.provider
        if args.model:
            ai["model"] = args.model
        if args.base_url:
            ai["base_url"] = args.base_url
        if args.key_env:
            ai["key_env"] = args.key_env
        save_config(cfg)
        print(f"AI provider set to {ai['provider']}")
        return 0
    if args.ai_cmd == "test":
        ok, msg = ai_env_ok(cfg)
        if ok:
            print("AI configuration check: OK")
            return 0
        print(f"AI configuration check: FAIL ({msg})")
        print("NetCheck continues with deterministic recommendations.")
        return 1
    return 1


def cmd_web(_args: argparse.Namespace) -> int:
    cfg = ensure_config()
    host = cfg.get("bind_host", "127.0.0.1")
    port = int(cfg.get("bind_port", 8765))
    store = NetCheckStore(DB_PATH)
    store.init()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, body: str, code: int = 200, ctype: str = "text/html") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def do_GET(self):
            if self.path == "/":
                self._send(DASHBOARD_HTML)
                return
            if self.path == "/api/state":
                latest = store.latest_scan() or {"message": "No scans yet"}
                self._send(json.dumps(latest), ctype="application/json")
                return
            if self.path == "/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                last_id = None
                try:
                    while True:
                        latest = store.latest_scan()
                        if latest and latest.get("id") != last_id:
                            payload = json.dumps(latest)
                            self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                            self.wfile.flush()
                            last_id = latest["id"]
                        time.sleep(1)
                except Exception:
                    return
                return
            self._send("Not found", code=404, ctype="text/plain")

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=lambda: webbrowser.open(f"http://{host}:{port}"), daemon=True).start()
    print(f"NetCheck dashboard at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset='utf-8'><title>NetCheck Dashboard</title>
<style>
body{font-family:ui-sans-serif,system-ui;margin:2rem;background:#0b1020;color:#e7ecff}
.card{background:#151d36;padding:1rem;border-radius:12px;margin-bottom:1rem}
.badge{display:inline-block;padding:.2rem .5rem;border-radius:8px;background:#223058}
pre{white-space:pre-wrap}
</style></head>
<body>
<h1>NetCheck</h1>
<div class='card'><h3>Overview</h3><div id='overview'>Loading...</div></div>
<div class='card'><h3>Active Network</h3><pre id='network'></pre></div>
<div class='card'><h3>Findings</h3><pre id='findings'></pre></div>
<script>
function render(data){
  if(!data || data.message){document.getElementById('overview').innerText='No scans yet';return;}
  document.getElementById('overview').innerHTML = `Risk: <span class='badge'>${data.risk_score}</span> | Scan #${data.id}`;
  document.getElementById('network').innerText = JSON.stringify(data.snapshot, null, 2);
  document.getElementById('findings').innerText = JSON.stringify(data.findings, null, 2);
}
fetch('/api/state').then(r=>r.json()).then(render);
const evt = new EventSource('/events');
evt.onmessage = (e)=>render(JSON.parse(e.data));
</script>
</body></html>"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netcheck")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("scan")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("watch")
    sp.add_argument("--interval", type=int)
    sp.set_defaults(func=cmd_watch)

    sp = sub.add_parser("web")
    sp.set_defaults(func=cmd_web)

    sp = sub.add_parser("report")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_report)

    ai = sub.add_parser("ai")
    aisub = ai.add_subparsers(dest="ai_cmd", required=True)

    sp = aisub.add_parser("setup")
    sp.set_defaults(func=cmd_ai)

    sp = aisub.add_parser("set")
    sp.add_argument("provider", choices=["none", "openai", "claude", "copilot", "opencode"])
    sp.add_argument("--model")
    sp.add_argument("--base-url")
    sp.add_argument("--key-env")
    sp.set_defaults(func=cmd_ai)

    sp = aisub.add_parser("test")
    sp.set_defaults(func=cmd_ai)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
