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


class Ansi:
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"
    green = "\033[32m"
    yellow = "\033[33m"
    red = "\033[31m"
    magenta = "\033[35m"
    cyan = "\033[36m"


def use_color() -> bool:
    return sys.stdout.isatty() and not os.getenv("NO_COLOR")


def c(text: str, color: str) -> str:
    if not use_color():
        return text
    return f"{color}{text}{Ansi.reset}"


def severity_color(sev: str) -> str:
    sev = sev.lower()
    if sev == "critical":
        return Ansi.magenta
    if sev == "high":
        return Ansi.red
    if sev == "medium":
        return Ansi.yellow
    if sev == "low":
        return Ansi.cyan
    return Ansi.dim


def _section_title(title: str) -> None:
    marker = c("◊", Ansi.green)
    print(f"{marker}  {title} " + c("─" * 42, Ansi.dim))


def _boxed(lines: list[str], width: int = 64) -> None:
    print(c("┌" + "─" * (width - 2) + "┐", Ansi.dim))
    for line in lines:
        trimmed = line[: width - 4]
        print(c("│ ", Ansi.dim) + f"{trimmed:<{width - 4}}" + c(" │", Ansi.dim))
    print(c("└" + "─" * (width - 2) + "┘", Ansi.dim))


def _suggest_fix(category: str) -> str:
    suggestions = {
        "dns": "Use trusted DNS or DNS-over-HTTPS/TLS and verify resolver policy.",
        "gateway": "Restrict router admin access and disable remote WAN administration.",
        "wifi": "Prefer WPA3 where available and rotate Wi-Fi credentials.",
        "stack": "Check vendor updates for adapter drivers and OS network stack patches.",
    }
    return suggestions.get(category, "Review local network security policy and remediate configuration drift.")


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
    print(c("✓  Scan complete", Ansi.green + Ansi.bold))

    _section_title("Environment")
    env_lines = [
        f"Collected at: {result.created_at}",
        f"OS: {context.get('platform', 'unknown')}",
        f"Default interface: {context.get('adapter', 'unknown')}",
        f"Gateway: {context.get('gateway') or 'n/a'}",
        f"DNS: {', '.join(context.get('dns', [])) or 'n/a'}",
        f"Active Wi-Fi: {context.get('ssid') or 'n/a'} ({context.get('auth') or 'unknown'})",
    ]
    _boxed(env_lines)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in result.findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1

    _section_title("Scan summary")
    summary_lines = [
        f"Risk score: {result.risk_score}/100",
        f"Findings: {len(result.findings)}",
        (
            f"{c('Critical', Ansi.magenta)} {counts['critical']} | "
            f"{c('High', Ansi.red)} {counts['high']} | "
            f"{c('Medium', Ansi.yellow)} {counts['medium']} | "
            f"{c('Low', Ansi.cyan)} {counts['low']} | Info {counts['info']}"
        ),
    ]
    _boxed(summary_lines)

    if not result.findings:
        print(c("No findings detected.", Ansi.green))
        return

    print(c("─" * 70, Ansi.dim))
    for f in result.findings:
        sev = c(f"[{f.severity.upper()}]", severity_color(f.severity) + Ansi.bold)
        print(f"{sev} {c(f.title, Ansi.bold)}")
        print(f" Category: {f.category}")
        print(f" Evidence: {f.details}")
        print(f" Fix: {_suggest_fix(f.category)}")
        print()


def cmd_doctor(_: argparse.Namespace) -> int:
    ensure_storage()
    print(c("NetCheck doctor", Ansi.bold))
    _section_title("Diagnostics")

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

    diag_lines = [
        f"Python: {platform.python_version()}",
        f"Platform: {platform.platform()}",
        f"App dir: {DATA_DIR}",
        f"Config: {CONFIG_PATH}",
        f"DB: {DB_PATH}",
        f"DB readable: {db_ok}",
        f"Stored scans: {scan_count}",
        f"Stored findings: {findings_count}",
        f"AI provider: {load_config()['ai']['provider']}",
    ]
    _boxed(diag_lines)

    latest = recent_scans(limit=1)
    if latest:
        s = latest[0]
        print(c("Latest scan", Ansi.bold))
        print(f" Time: {s['created_at']}")
        print(f" Risk: {s['risk_score']}")
        print(f" Findings: {len(s['findings'])}")
    else:
        print("Latest scan: none")
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
