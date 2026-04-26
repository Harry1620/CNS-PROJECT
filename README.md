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
