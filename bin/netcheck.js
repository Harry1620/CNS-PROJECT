#!/usr/bin/env node

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const HELP = `NetCheck CLI\n\nUsage:\n  netcheck <command> [options]\n\nCommands:\n  init             Create local config and defaults\n  scan             One-time vulnerability scan\n  watch            Monitor connection changes and rescan\n  web              Start local dashboard + open browser\n  report --json    Export findings\n  ai setup         Explain AI setup\n  ai set           Configure AI provider\n  ai test          Test AI configuration\n  update           Update global install with pnpm\n\nSupported AI providers:\n  none, openai, claude, copilot, opencode\n\nInstall (pnpm only, no manual clone):\n  pnpm add -g git+https://github.com/<org>/<repo>.git\n\nUpdate examples:\n  netcheck update --source git+https://github.com/<org>/<repo>.git\n  NETCHECK_UPDATE_SOURCE=git+https://github.com/<org>/<repo>.git netcheck update\n`;

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  process.stdout.write(HELP);
  process.exit(0);
}

if (args[0] === 'update') {
  const source = readArg(args, '--source') || process.env.NETCHECK_UPDATE_SOURCE || '';
  const force = args.includes('--force');
  if (!source) {
    process.stderr.write('Missing update source. Use --source <git/url/path> or set NETCHECK_UPDATE_SOURCE.\n');
    process.exit(2);
  }

  const check = spawnSync('pnpm', ['bin', '-g'], { encoding: 'utf8' });
  if (check.error) {
    process.stderr.write('pnpm is required for update. Install pnpm and ensure it is in PATH.\n');
    process.exit(1);
  }
  if (check.status !== 0) {
    process.stderr.write('pnpm global bin is not configured. Run `pnpm setup`, restart shell, then retry.\n');
    process.exit(check.status ?? 1);
  }

  const result = spawnSync('pnpm', ['add', '-g', source, ...(force ? ['--force'] : [])], { encoding: 'utf8' });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.status !== 0 && (result.stderr || '').includes('ERR_PNPM_NO_GLOBAL_BIN_DIR')) {
    process.stderr.write('pnpm global bin is not configured. Run `pnpm setup`, restart shell, then retry.\n');
  }
  process.exit(result.status ?? 1);
}

const pythonCandidates = ['python3', 'python'];
const packageRoot = path.resolve(__dirname, '..');
const bundledPkg = path.resolve(packageRoot, 'netcheck');
let lastError = null;

if (!fs.existsSync(bundledPkg)) {
  process.stderr.write(`Bundled NetCheck Python package was not found at ${bundledPkg}\n`);
  process.exit(1);
}

for (const py of pythonCandidates) {
  const probe = spawnSync(py, ['--version'], { stdio: 'ignore' });
  if (probe.status !== 0) continue;

  const child = spawnSync(py, ['-m', 'netcheck.cli', ...args], {
    stdio: 'inherit',
    env: {
      ...process.env,
      PYTHONPATH: process.env.PYTHONPATH
        ? `${packageRoot}${path.delimiter}${process.env.PYTHONPATH}`
        : packageRoot,
    },
  });
  if (child.error) {
    lastError = child.error;
    continue;
  }
  process.exit(child.status ?? 0);
}

process.stderr.write('NetCheck requires Python 3 installed in PATH.\n');
if (lastError) {
  process.stderr.write(String(lastError) + '\n');
}
process.exit(1);

function readArg(allArgs, key) {
  const i = allArgs.indexOf(key);
  if (i === -1 || i + 1 >= allArgs.length) return '';
  return allArgs[i + 1];
}
