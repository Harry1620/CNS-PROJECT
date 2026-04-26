from __future__ import annotations

import argparse
import json
import os
import sys

from .config import ensure_storage, load_config, save_config
from .scanner import recent_scans, run_scan
from .watcher import watch
from .web import run_server

VALID_PROVIDERS = {"none", "openai", "claude", "copilot", "opencode"}


def cmd_init(_: argparse.Namespace) -> int:
    paths = ensure_storage()
    print(f"Initialized NetCheck at {paths.data_dir}")
    return 0


def cmd_scan(_: argparse.Namespace) -> int:
    result = run_scan()
    print(f"Scan complete: risk={result.risk_score} findings={len(result.findings)}")
    for f in result.findings:
        print(f"- [{f.severity}] {f.category}: {f.title} ({f.confidence})")
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
            print(f"{s['created_at']} risk={s['risk_score']} findings={len(s['findings'])}")
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
    sp_scan.set_defaults(func=cmd_scan)

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
