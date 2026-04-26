# NetCheck

NetCheck is a cross-platform CLI for local network risk checks with optional AI guidance.

## Install

Global install via npm/pnpm:

- `npm install -g @netcheck/cli`
- `pnpm add -g @netcheck/cli`

Then run:

- `netcheck --help`

> Note: full scan execution requires Python 3 and this repository's Python package installed.

## Commands

- `netcheck init`
- `netcheck scan`
- `netcheck watch`
- `netcheck web`
- `netcheck report --json`
- `netcheck ai setup|set|test`

## Privacy defaults

- Data path: `~/.netcheck/`
- Web bind: `127.0.0.1`
- AI receives only sanitized summaries by default
# NetCheck (V1 scaffold)

Cross-platform local-first network risk CLI.

## Commands

- `./netcheck.py init`
- `./netcheck.py scan`
- `./netcheck.py watch --interval 5`
- `./netcheck.py web`
- `./netcheck.py report --json`
- `./netcheck.py ai setup|set|test`

## Data and privacy defaults

- Data directory: `~/.netcheck/`
- Config: `~/.netcheck/config.json`
- SQLite history: `~/.netcheck/netcheck.db`
- Logs directory: `~/.netcheck/logs`
- Web bind default: `127.0.0.1:8765`
- Scans work without AI and always return deterministic recommendations.
