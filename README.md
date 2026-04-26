# NetCheck

NetCheck is a cross-platform CLI for local network risk checks with optional AI guidance.

## Install (Windows/macOS/Linux)

## Option A: install directly from GitHub (no manual clone)

```bash
npm install -g git+https://github.com/Harry1620/CNS-PROJECT.git
# or
pnpm add -g git+https://github.com/Harry1620/CNS-PROJECT.git
```

Then verify:

```bash
netcheck --help
```

## Option B: local development link

```bash
# from the project folder
npm link
# or
pnpm link --global
```

This creates a global `netcheck` command symlink for local testing.

## Update command

```bash
netcheck update --manager npm --source git+https://github.com/<org>/<repo>.git
# or
netcheck update --manager pnpm --source git+https://github.com/<org>/<repo>.git
```

You can also set `NETCHECK_UPDATE_SOURCE` and run just:

```bash
netcheck update --manager npm
```

Add `--force` when your package manager asks to overwrite an existing global binary.

## Commands

- `netcheck init`
- `netcheck scan`
- `netcheck watch`
- `netcheck web`
- `netcheck report --json`
- `netcheck ai setup|set|test`
- `netcheck update`

## Requirements

- Python 3 must be installed for full scan execution.
- The Node launcher executes the bundled Python CLI script.

## Privacy defaults

- Data path: `~/.netcheck/`
- Web bind: `127.0.0.1`
- AI receives only sanitized summaries by default
