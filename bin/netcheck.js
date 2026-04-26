#!/usr/bin/env node

const { spawnSync } = require('node:child_process');

const HELP = `NetCheck CLI\n\nUsage:\n  netcheck <command> [options]\n\nCommands:\n  init             Create local config and defaults\n  scan             One-time vulnerability scan\n  watch            Monitor connection changes and rescan\n  web              Start local dashboard + open browser\n  report --json    Export findings\n  ai setup         Explain AI setup\n  ai set           Configure AI provider\n  ai test          Test AI configuration\n\nSupported AI providers:\n  none, openai, claude, copilot, opencode\n\nInstall:\n  # from repo folder\n  npm install -g .\n  pnpm add -g .\n`;

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  process.stdout.write(HELP);
  process.exit(0);
}

const pythonCandidates = ['python3', 'python'];
let lastError = null;

for (const py of pythonCandidates) {
  const probe = spawnSync(py, ['--version'], { stdio: 'ignore' });
  if (probe.status !== 0) continue;

  const child = spawnSync(py, ['-m', 'netcheck.cli', ...args], { stdio: 'inherit' });
  if (child.error) {
    lastError = child.error;
    continue;
  }
  process.exit(child.status ?? 0);
}

process.stderr.write('NetCheck requires Python 3 installed and the netcheck Python package available.\n');
if (lastError) {
  process.stderr.write(String(lastError) + '\n');
}
process.exit(1);
