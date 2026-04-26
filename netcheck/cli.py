from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import sys
from datetime import datetime

from .config import CONFIG_PATH, DB_PATH, DATA_DIR, ensure_storage, load_config, save_config
from .scanner import recent_scans, run_scan
from .watcher import watch
from .web import run_server

VALID_PROVIDERS = {"none", "openai", "claude", "copilot", "opencode"}


def cmd_init(_: argparse.Namespace) -> int:
    paths = ensure_storage()
    print(f"Initialized NetCheck at {paths.data_dir}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    result = run_scan()
    if args.json:
        print(
            json.dumps(
                {
                    "created_at": result.created_at,
                    "risk_score": result.risk_score,
                    "context": result.context,
                    "findings": [f.__dict__ for f in result.findings],
                },
                indent=2,
            )
        )
        return 0

    _render_scan_ui(result)
    return 0


def _render_scan_ui(result) -> None:
    context = result.context
    print("◊  Scan complete")
    print("│")
    print("├─ Environment")
    print(f"│  Collected at: {result.created_at}")
    print(f"│  OS: {context.get('platform', 'unknown')}")
    print(f"│  Default interface: {context.get('adapter', 'unknown')}")
    print(f"│  Gateway: {context.get('gateway') or 'n/a'}")
    print(f"│  DNS: {', '.join(context.get('dns', [])) or 'n/a'}")
    print(f"│  Active Wi-Fi: {context.get('ssid') or 'n/a'} ({context.get('auth') or 'unknown'})")
    print("│")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in result.findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1

    print("├─ Scan summary")
    print(f"│  Risk score: {result.risk_score}/100")
    print(f"│  Findings: {len(result.findings)}")
    print(
        "│  "
        f"Critical {counts['critical']} | High {counts['high']} | Medium {counts['medium']} | "
        f"Low {counts['low']} | Info {counts['info']}"
    )
    print("│")

    if not result.findings:
        print("└─ No findings detected.")
        return

    print("└─ Findings")
    for f in result.findings:
        sev = f.severity.upper()
        print(f"   [{sev}] {f.title}")
        print(f"   Category: {f.category}")
        print(f"   Details: {f.details}")
        print(f"   Confidence: {f.confidence}")
        print("   ─")


def cmd_doctor(_: argparse.Namespace) -> int:
    ensure_storage()
    print("NetCheck doctor")
    print("│")
    print("├─ Diagnostics")
    print(f"│  Python: {platform.python_version()}")
    print(f"│  Platform: {platform.platform()}")
    print(f"│  Data dir: {DATA_DIR}")
    print(f"│  Config path: {CONFIG_PATH}")
    print(f"│  DB path: {DB_PATH}")
    print(f"│  Config exists: {CONFIG_PATH.exists()}")
    print(f"│  DB exists: {DB_PATH.exists()}")
    print(f"│  AI provider: {load_config()['ai']['provider']}")

    scan_count = 0
    findings_count = 0
    db_ok = False
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        scan_count = cur.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        findings_count = cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False

    print(f"│  DB readable: {db_ok}")
    print(f"│  Stored scans: {scan_count}")
    print(f"│  Stored findings: {findings_count}")
    print("│")

    latest = recent_scans(limit=1)
    if latest:
        s = latest[0]
        print("└─ Latest scan")
        print(f"   Time: {s['created_at']}")
        print(f"   Risk: {s['risk_score']}")
        print(f"   Findings: {len(s['findings'])}")
    else:
        print("└─ Latest scan: none")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    cfg = load_config()
    interval = args.interval or cfg["watch"]["interval_seconds"]
    print(f"Watching for network changes every {interval}s (Ctrl+C to stop)...")
    try:
        watch(interval)
    except KeyboardInterrupt:
        print("Stopped watch.")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    cfg = load_config()["web"]
    run_server(host=args.host or cfg["host"], port=args.port or cfg["port"], auto_open=not args.no_open)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    scans = recent_scans(limit=args.limit)
    if args.json:
        print(json.dumps(scans, indent=2))
    else:
        for s in scans:
            ts = datetime.fromisoformat(s["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{ts}  risk={s['risk_score']}  findings={len(s['findings'])}")
    return 0


def cmd_ai_setup(_: argparse.Namespace) -> int:
    cfg = load_config()
    if cfg["ai"]["provider"] == "none":
        print("AI is optional and currently disabled.")
    print("Use `netcheck ai set --provider ...` to configure a provider.")
    return 0


def cmd_ai_set(args: argparse.Namespace) -> int:
    if args.provider not in VALID_PROVIDERS:
        print(f"Invalid provider: {args.provider}", file=sys.stderr)
        return 2
    cfg = load_config()
    cfg["ai"].update(
        {
            "provider": args.provider,
            "model": args.model or "",
            "base_url": args.base_url or "",
            "api_key_env": args.api_key_env or "",
            "full_context": bool(args.full_context),
        }
    )
    save_config(cfg)
    print(f"AI provider set to {args.provider}")
    return 0


def cmd_ai_test(_: argparse.Namespace) -> int:
    cfg = load_config()["ai"]
    provider = cfg["provider"]
    if provider == "none":
        print("AI disabled. Deterministic recommendations will be used.")
        return 0

    env_name = cfg.get("api_key_env") or ("GITHUB_TOKEN" if provider == "copilot" else "OPENAI_API_KEY")
    if not os.getenv(env_name):
        print(f"AI provider '{provider}' configured but env var '{env_name}' is missing.")
        print("NetCheck will continue with deterministic rule-based recommendations.")
        return 0

    print(f"AI configuration looks ready for provider '{provider}' (token found in {env_name}).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netcheck")
    sub = p.add_subparsers(dest="command", required=True)

    sp_init = sub.add_parser("init")
    sp_init.set_defaults(func=cmd_init)

    sp_scan = sub.add_parser("scan")
    sp_scan.add_argument("--json", action="store_true")
    sp_scan.set_defaults(func=cmd_scan)

    sp_doctor = sub.add_parser("doctor")
    sp_doctor.set_defaults(func=cmd_doctor)

    sp_watch = sub.add_parser("watch")
    sp_watch.add_argument("--interval", type=int)
    sp_watch.set_defaults(func=cmd_watch)

    sp_web = sub.add_parser("web")
    sp_web.add_argument("--host")
    sp_web.add_argument("--port", type=int)
    sp_web.add_argument("--no-open", action="store_true")
    sp_web.set_defaults(func=cmd_web)

    sp_report = sub.add_parser("report")
    sp_report.add_argument("--json", action="store_true")
    sp_report.add_argument("--limit", type=int, default=20)
    sp_report.set_defaults(func=cmd_report)

    sp_ai = sub.add_parser("ai")
    ai_sub = sp_ai.add_subparsers(dest="ai_cmd", required=True)
    ai_setup = ai_sub.add_parser("setup")
    ai_setup.set_defaults(func=cmd_ai_setup)
    ai_set = ai_sub.add_parser("set")
    ai_set.add_argument("--provider", required=True)
    ai_set.add_argument("--model")
    ai_set.add_argument("--base-url")
    ai_set.add_argument("--api-key-env")
    ai_set.add_argument("--full-context", action="store_true")
    ai_set.set_defaults(func=cmd_ai_set)
    ai_test = ai_sub.add_parser("test")
    ai_test.set_defaults(func=cmd_ai_test)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
