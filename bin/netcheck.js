#!/usr/bin/env node

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const HELP = `NetCheck CLI\n\nUsage:\n  netcheck <command> [options]\n\nCommands:\n  init             Create local config and defaults\n  scan             One-time vulnerability scan\n  watch            Monitor connection changes and rescan\n  web              Start local dashboard + open browser\n  report --json    Export findings\n  ai setup         Explain AI setup\n  ai set           Configure AI provider\n  ai test          Test AI configuration\n  update           Update global install from source\n\nSupported AI providers:\n  none, openai, claude, copilot, opencode\n\nInstall from git (no manual clone):\n  npm install -g git+https://github.com/<org>/<repo>.git\n  pnpm add -g git+https://github.com/<org>/<repo>.git\n\nLocal dev linking:\n  npm link\n  pnpm link --global\n\nUpdate examples:\n  netcheck update --manager npm --source git+https://github.com/<org>/<repo>.git\n  netcheck update --manager pnpm --source git+https://github.com/<org>/<repo>.git\n`;

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  process.stdout.write(HELP);
  process.exit(0);
}

if (args[0] === 'update') {
  const manager = readArg(args, '--manager') || 'npm';
  const source = readArg(args, '--source') || process.env.NETCHECK_UPDATE_SOURCE || '';
  const force = args.includes('--force');
  if (!source) {
    process.stderr.write('Missing update source. Use --source <git/url/path> or set NETCHECK_UPDATE_SOURCE.\n');
    process.exit(2);
  }

  let command;
  if (manager === 'npm') {
    command = ['install', '-g', source, ...(force ? ['--force'] : [])];
  } else if (manager === 'pnpm') {
    command = ['add', '-g', source, ...(force ? ['--force'] : [])];
  } else {
    process.stderr.write("Unsupported manager. Use '--manager npm' or '--manager pnpm'.\n");
    process.exit(2);
  }

  const result = spawnSync(manager, command, { stdio: 'inherit' });
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
