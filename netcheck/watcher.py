from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable

from .scanner import collect_network_context, run_scan


def context_signature(context: dict) -> str:
    payload = json.dumps(
        {
            "ssid": context.get("ssid", ""),
            "bssid": context.get("bssid", ""),
            "gateway": context.get("gateway", ""),
            "dns": context.get("dns", []),
            "ip": context.get("ip", ""),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def watch(interval_seconds: int, on_scan: Callable[[dict], None] | None = None) -> None:
    last_sig = ""
    while True:
        ctx = collect_network_context()
        sig = context_signature(ctx)
        if sig != last_sig:
            result = run_scan()
            if on_scan:
                on_scan({"created_at": result.created_at, "risk_score": result.risk_score, "context": result.context})
            print(f"[watch] network change detected -> scan risk={result.risk_score}")
            last_sig = sig
        time.sleep(max(1, interval_seconds))
