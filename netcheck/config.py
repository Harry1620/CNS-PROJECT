from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DATA_DIR = Path.home() / ".netcheck"
CONFIG_PATH = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "netcheck.db"
LOG_PATH = DATA_DIR / "logs"

DEFAULT_CONFIG: dict[str, Any] = {
    "ai": {
        "provider": "none",
        "model": "",
        "base_url": "",
        "api_key_env": "",
        "full_context": False,
    },
    "watch": {"interval_seconds": 5},
    "web": {"host": "127.0.0.1", "port": 8765, "auto_open": True},
}


@dataclass
class NetcheckPaths:
    data_dir: Path = DATA_DIR
    config_path: Path = CONFIG_PATH
    db_path: Path = DB_PATH


def ensure_storage() -> NetcheckPaths:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_PATH.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    init_db(DB_PATH)
    return NetcheckPaths()


def load_config() -> dict[str, Any]:
    ensure_storage()
    raw = CONFIG_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)
    return merge_defaults(DEFAULT_CONFIG, data)


def save_config(config: dict[str, Any]) -> None:
    ensure_storage()
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def merge_defaults(defaults: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    merged = dict(defaults)
    for key, value in target.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_defaults(merged[key], value)
        else:
            merged[key] = value
    return merged


def init_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                context_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                confidence TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def db_connect() -> sqlite3.Connection:
    ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
