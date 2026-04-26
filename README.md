# NetCheck

NetCheck is a cross-platform CLI for local network risk checks with optional AI guidance.

## Install

### Option A (recommended right now): install from this repository folder

```bash
npm install -g .
# or
pnpm add -g .
```

Then run:

```bash
netcheck --help
```

### Why you saw npm/pnpm 404

If you run `npm add -g @netcheck/cli` (or `pnpm add -g @netcheck/cli`) you get 404 because that scoped package is **not published** on npm registry yet.
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

## Requirements

- Python 3 must be installed for full scan execution.
- The launcher forwards commands to `python -m netcheck.cli`.

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
