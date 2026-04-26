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
