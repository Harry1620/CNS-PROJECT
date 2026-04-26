# NetCheck

NetCheck is a cross-platform CLI for local network risk checks with optional AI guidance.

## Install (pnpm only)

```bash
pnpm add -g git+https://github.com/<org>/<repo>.git
```

Then verify:

```bash
netcheck --help
```

## If Windows says `Unknown command: update`

You are likely running a different `netcheck` binary already present on your machine.

Fix it with:

```powershell
npm uninstall -g netcheck netcheck-cli
pnpm remove -g netcheck netcheck-cli
pnpm add -g git+https://github.com/<org>/<repo>.git
Get-Command netcheck
```

The final command should point to pnpm global bin path.

## Update command

```bash
netcheck update --source git+https://github.com/<org>/<repo>.git
```

or set the source once:

```bash
# Windows PowerShell
$env:NETCHECK_UPDATE_SOURCE='git+https://github.com/<org>/<repo>.git'
netcheck update
```

Add `--force` if pnpm asks to overwrite an existing binary.

## Commands

- `netcheck init`
- `netcheck scan`
- `netcheck watch`
- `netcheck web`
- `netcheck report --json`
- `netcheck doctor`
- `netcheck ai setup|set|test`
- `netcheck update`

## Requirements

- Python 3 must be installed for full scan execution.
- The Node launcher executes the bundled Python CLI script.

## Privacy defaults

- Data path: `~/.netcheck/`
- Web bind: `127.0.0.1`
- AI receives only sanitized summaries by default
