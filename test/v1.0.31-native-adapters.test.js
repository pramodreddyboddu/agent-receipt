import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, dirname, resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CURSOR_RULE_MDC } from '../dist/lib/cursor-rule.js';
import { GROK_HOOK_JSON, GROK_RULE_MD, GROK_WRAP_SCRIPT } from '../dist/lib/grok-rule.js';
import { getAdapter } from '../dist/lib/adapters/index.js';
import { hashToolEvents } from '../dist/lib/adapters/tool-calls.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const homes = [];

const AKIA = 'AKIAIOSFODNN7EXAMPLE';
const GH = `ghp_${'a'.repeat(36)}`;
const SK = `sk-ant-${'b'.repeat(24)}`;
const SECRET_URL = 'https://example.com/a';
const PW = 'hunter2SuperSecretPw';
const SQL = 'SqlPlantedSecret99';
const API = 'AbCdEf0123456789GhIjKlMnOpQrStUv';
const TOK = 'tok_LivePlantedSecretValue';
const BLOB = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/';
const XOX = `xoxb-${'1'.repeat(12)}`;
const HOST1 = 'db01.corp';
const HOST2 = 'prod-db.lan';
const PLANTED = [PW, SQL, API, TOK, BLOB, AKIA, GH, XOX, HOST1, HOST2];

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function envFor(home) {
  return {
    ...process.env,
    NO_COLOR: '1',
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    XDG_DATA_HOME: join(home, '.local', 'share'),
    CLAUDE_CONFIG_DIR: join(home, 'claude-config'),
    CODEX_HOME: join(home, 'codex-home'),
  };
}

function cliResult(cwd, args, home) {
  const result = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: envFor(home),
    maxBuffer: 8 * 1024 * 1024,
  });
  return { code: result.status ?? 1, out: result.stdout || '', err: result.stderr || '' };
}

function gitRepo() {
  const home = mkdtempSync(join(tmpdir(), 'ar1031-home-'));
  const dir = mkdtempSync(join(tmpdir(), 'ar1031-repo-'));
  homes.push(home);
  dirs.push(dir);
  mkdirSync(join(home, '.config'), { recursive: true });
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# repo\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  return { dir, home };
}

function plainDir() {
  const home = mkdtempSync(join(tmpdir(), 'ar1031-home-'));
  const dir = mkdtempSync(join(tmpdir(), 'ar1031-plain-'));
  homes.push(home);
  dirs.push(dir);
  mkdirSync(join(home, '.config'), { recursive: true });
  return { dir, home };
}

function sha256Text(text) {
  return createHash('sha256').update(text).digest('hex');
}

function fallbackBackup(dir, name) {
  return join(dir, '.agent-receipt', 'adapter-backups', name);
}

function receiptMdCount(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  if (!existsSync(out)) return 0;
  return readdirSync(out).filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md')).length;
}

function walkFiles(dir) {
  const out = [];
  const walk = (current) => {
    for (const name of readdirSync(current)) {
      if (name === '.git') continue;
      const filePath = join(current, name);
      const st = lstatSync(filePath);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(filePath);
      else out.push(filePath);
    }
  };
  if (existsSync(dir)) walk(dir);
  return out;
}

function assertNoPlanted(dir) {
  for (const file of walkFiles(dir)) {
    const buf = readFileSync(file);
    for (const secret of PLANTED) {
      assert.equal(buf.includes(Buffer.from(secret)), false, `${file} leaked ${secret.slice(0, 16)}`);
    }
  }
}

function pathShim(home) {
  const binDir = join(home, 'bin');
  mkdirSync(binDir, { recursive: true });
  const script = join(binDir, 'agent-receipt');
  writeFileSync(script, `#!/bin/sh\nexec ${process.execPath} ${JSON.stringify(bin)} "$@"\n`);
  chmodSync(script, 0o755);
  return binDir;
}

function runHook(dir, home, rel, pathDir) {
  return spawnSync('sh', [join(dir, rel)], {
    cwd: dir,
    encoding: 'utf8',
    env: {
      ...envFor(home),
      PATH: `${pathDir}:${process.env.PATH}`,
      HOOK_STDIN_WAIT_SEC: '0.05',
    },
    timeout: 20000,
  });
}

function backupDir(dir, name) {
  const printed = git(dir, ['rev-parse', '--git-path', `agent-receipt-adapter-backups/${name}`]);
  return isAbsolute(printed) ? printed : resolve(dir, printed);
}

function listRel(dir, rel = '') {
  const out = [];
  const abs = join(dir, rel);
  if (!existsSync(abs)) return out;
  for (const name of readdirSync(abs)) {
    if (rel === '' && name === '.git') continue;
    const child = rel ? `${rel}/${name}` : name;
    const st = lstatSync(join(dir, child));
    if (st.isSymbolicLink()) out.push(`${child}@`);
    else if (st.isDirectory()) out.push(...listRel(dir, child));
    else out.push(child);
  }
  return out.sort();
}

function hookCount(text) {
  return text.split('agent-receipt-wrap.sh').length - 1;
}

function assertRedacted(text, label) {
  assert.equal(text.includes(AKIA), false, `${label} kept an AWS key`);
  assert.equal(text.includes(GH), false, `${label} kept a GitHub token`);
  assert.equal(text.includes(SK), false, `${label} kept an API key`);
  assert.equal(text.includes(SECRET_URL), false, `${label} kept a URL`);
  assert.match(text, /AKIA\[REDACTED\]/, label);
  assert.match(text, /ghp_\[REDACTED\]/, label);
  assert.match(text, /sk-ant-\[REDACTED\]/, label);
  assert.match(text, /\[host\]/, label);
}

function jsonl(rows) {
  return `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
}

describe('v1.0.31 native adapters', () => {
  after(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    for (const home of homes) rmSync(home, { recursive: true, force: true });
    for (const name of ['.claude', '.codex', '.cursor', '.grok']) {
      assert.equal(existsSync(join(root, name)), false, `${name} appeared in the package repo`);
    }
    for (const home of homes) {
      for (const name of ['.claude', '.codex', '.cursor', '.grok']) {
        assert.equal(existsSync(join(home, name)), false, `${name} appeared under the temp HOME`);
      }
    }
  });

  it('documents adapters in help, and doctor keeps the row informational', () => {
    const { dir, home } = gitRepo();
    const help = cliResult(root, ['help', 'adapters'], home);
    assert.equal(help.code, 0, help.err);
    assert.match(help.out, /install/);
    assert.match(help.out, /uninstall/);
    assert.match(help.out, /--dry-run/);
    assert.match(help.out, /backup|snapshot|pre-install/i);
    const capture = cliResult(root, ['help', 'capture'], home);
    assert.match(capture.out, /--transcript/);
    assert.match(capture.out, /--adapter/);
    const wrap = cliResult(root, ['help', 'wrap'], home);
    assert.match(wrap.out, /--transcript/);
    const init = cliResult(root, ['help', 'init'], home);
    assert.match(init.out, /--claude/);
    assert.match(init.out, /--codex/);
    assert.match(init.out, /sessionEnd and stop hooks/);
    assert.match(init.out, /Codex SessionEnd and Stop hooks/);
    assert.match(init.out, /--grok/);
    assert.match(init.out, /\.grok\/rules/);
    assert.match(help.out, /--force/);
    assert.match(help.out, /would discard user changes/);
    assert.match(capture.out, /not covered by the receipt/);
    const report = cliResult(root, ['help', 'report'], home);
    assert.match(report.out, /Version 2 is this page/);
    assert.match(report.out, /Version 1 stays/);
    assert.match(report.out, /1\.0\.30 rejects a payload that includes `toolCalls`/);
    assert.match(report.out, /UNSIGNED \(1 receipt not checked\)/);
    assert.match(report.out, /re-sign an altered narrative/);
    assert.match(report.out, /prune timestamp is not a date/);
    const global = cliResult(root, ['help'], home);
    assert.match(global.out, /adapters\s+Native hooks/);
    const listed = cliResult(dir, ['adapters', '--json'], home);
    assert.equal(listed.code, 0, listed.err);
    const body = JSON.parse(listed.out);
    assert.equal(body.command, 'adapters');
    assert.equal(body.action, 'list');
    assert.equal(body.dryRun, false);
    assert.equal(body.adapters.length, 4);
    const alias = JSON.parse(cliResult(dir, ['adapters', 'status', 'claude', '--json'], home).out);
    assert.equal(alias.adapters.length, 1);
    assert.equal(alias.adapters[0].name, 'claude-code');
    assert.equal(alias.adapters[0].installed, false);
    const doctor = cliResult(dir, ['doctor', '--json'], home);
    assert.equal(doctor.code, 0, doctor.err + doctor.out);
    const checks = JSON.parse(doctor.out).checks;
    const row = checks.find((check) => check.id === 'adapters');
    assert.equal(row.status, 'info');
    const both = cliResult(dir, ['adapters', 'install', 'claude-code', '--stop', '--no-stop'], home);
    assert.equal(both.code, 1);
    assert.match(both.err, /Pass only one of --stop and --no-stop/);
    const unknown = cliResult(dir, ['adapters', 'install', 'nope'], home);
    assert.equal(unknown.code, 1);
    assert.match(unknown.err, /Unknown adapter/);
  });

  it('installs and uninstalls Claude Code without clobbering user settings', () => {
    const { dir, home } = gitRepo();
    const rel = '.claude/settings.json';
    const original = '{"permissions":{"allow":["Bash"]},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo keep-me","timeout":5}]}]}}\n';
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, rel), original);
    const before = listRel(dir);
    const preview = cliResult(dir, ['adapters', 'install', 'claude-code', '--dry-run'], home);
    assert.equal(preview.code, 0, preview.err);
    assert.match(preview.out, /dry-run/);
    assert.match(preview.out, /would write/);
    assert.match(preview.out, /no files written/);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);
    assert.deepEqual(listRel(dir), before);
    assert.equal(existsSync(backupDir(dir, 'claude-code')), false);

    const installed = cliResult(dir, ['adapters', 'install', 'claude-code', '--json'], home);
    assert.equal(installed.code, 0, installed.err);
    const first = JSON.parse(installed.out);
    assert.equal(first.action, 'install');
    assert.equal(first.dryRun, false);
    assert.ok(first.results[0].changed.length > 0);
    const settings = readFileSync(join(dir, rel), 'utf8');
    const doc = JSON.parse(settings);
    assert.deepEqual(doc.permissions.allow, ['Bash']);
    assert.match(JSON.stringify(doc.hooks.PreToolUse), /echo keep-me/);
    assert.ok(doc.hooks.SessionEnd);
    assert.ok(doc.hooks.Stop);
    assert.equal(hookCount(settings), 2);
    const backup = backupDir(dir, 'claude-code');
    const manifest = JSON.parse(readFileSync(join(backup, 'manifest.json'), 'utf8'));
    const entry = manifest.entries.find((item) => item.rel === rel);
    assert.equal(entry.existed, true);
    assert.equal(readFileSync(join(backup, 'files', entry.file), 'utf8'), original);
    assert.doesNotMatch(git(dir, ['status', '--porcelain']), /agent-receipt-adapter-backups/);

    const again = JSON.parse(cliResult(dir, ['adapters', 'install', 'claude-code', '--json'], home).out);
    assert.deepEqual(again.results[0].changed, []);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), settings);
    assert.equal(hookCount(readFileSync(join(dir, rel), 'utf8')), 2);
    assert.equal(readFileSync(join(backup, 'manifest.json'), 'utf8'), JSON.stringify(manifest, null, 2) + '\n');

    const dryOff = cliResult(dir, ['adapters', 'uninstall', 'claude-code', '--dry-run'], home);
    assert.match(dryOff.out, /would restore/);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), settings);
    const removed = cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home);
    assert.equal(removed.code, 0, removed.err);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);
    assert.equal(existsSync(backup), false);
    assert.equal(existsSync(join(dir, '.claude', 'rules', 'agent-receipt.md')), false);
    const twice = cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home);
    assert.equal(twice.code, 0, twice.err);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);

    const quiet = cliResult(dir, ['adapters', 'install', 'claude-code', '--no-stop', '--json'], home);
    assert.equal(quiet.code, 0, quiet.err);
    const stopped = JSON.parse(readFileSync(join(dir, rel), 'utf8'));
    assert.ok(stopped.hooks.SessionEnd);
    assert.equal(stopped.hooks.Stop, undefined);
    assert.match(JSON.stringify(stopped.hooks.PreToolUse), /echo keep-me/);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home).code, 0);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);
  });

  it('refuses a Claude settings symlink and invalid JSON', () => {
    const { dir, home } = gitRepo();
    const outside = join(home, 'outside-settings.json');
    writeFileSync(outside, '{"keep":true}\n');
    mkdirSync(join(dir, '.claude'), { recursive: true });
    symlinkSync(outside, join(dir, '.claude', 'settings.json'));
    const linked = cliResult(dir, ['adapters', 'install', 'claude-code'], home);
    assert.equal(linked.code, 1);
    assert.match(linked.err, /symlink/);
    assert.equal(readFileSync(outside, 'utf8'), '{"keep":true}\n');
    assert.equal(lstatSync(join(dir, '.claude', 'settings.json')).isSymbolicLink(), true);
    assert.equal(existsSync(join(dir, '.claude', 'rules')), false);
    assert.equal(existsSync(backupDir(dir, 'claude-code')), false);

    const { dir: badDir, home: badHome } = gitRepo();
    const bad = '{not json';
    mkdirSync(join(badDir, '.claude'), { recursive: true });
    writeFileSync(join(badDir, '.claude', 'settings.json'), bad);
    const refused = cliResult(badDir, ['adapters', 'install', 'claude-code'], badHome);
    assert.equal(refused.code, 1);
    assert.match(refused.err, /refusing to rewrite/);
    assert.equal(readFileSync(join(badDir, '.claude', 'settings.json'), 'utf8'), bad);
    assert.equal(existsSync(backupDir(badDir, 'claude-code')), false);
    assert.equal(existsSync(join(badDir, '.claude', 'rules')), false);
  });

  it('installs and uninstalls Cursor without clobbering user hooks', () => {
    const { dir, home } = gitRepo();
    const rel = '.cursor/hooks.json';
    const original = '{"version":1,"hooks":{"beforeShellExecution":[{"command":"echo keep-cursor"}]}}\n';
    mkdirSync(join(dir, '.cursor'), { recursive: true });
    writeFileSync(join(dir, rel), original);
    const preview = cliResult(dir, ['adapters', 'install', 'cursor', '--dry-run'], home);
    assert.equal(preview.code, 0, preview.err);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);
    assert.equal(existsSync(backupDir(dir, 'cursor')), false);
    assert.equal(cliResult(dir, ['adapters', 'install', 'cursor', '--json'], home).code, 0);
    const doc = JSON.parse(readFileSync(join(dir, rel), 'utf8'));
    assert.equal(doc.hooks.beforeShellExecution[0].command, 'echo keep-cursor');
    assert.ok(doc.hooks.sessionEnd);
    assert.ok(doc.hooks.stop);
    assert.equal(readFileSync(join(dir, '.cursor', 'rules', 'agent-receipt.mdc'), 'utf8'), CURSOR_RULE_MDC);
    const again = JSON.parse(cliResult(dir, ['adapters', 'install', 'cursor', '--json'], home).out);
    assert.deepEqual(again.results[0].changed, []);
    assert.equal(hookCount(readFileSync(join(dir, rel), 'utf8')), 2);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'cursor'], home).code, 0);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);
    assert.equal(existsSync(join(dir, '.cursor', 'rules', 'agent-receipt.mdc')), false);
    assert.equal(existsSync(backupDir(dir, 'cursor')), false);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'cursor'], home).code, 0);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);

    assert.equal(cliResult(dir, ['adapters', 'install', 'cursor', '--no-stop'], home).code, 0);
    const quiet = JSON.parse(readFileSync(join(dir, rel), 'utf8'));
    assert.ok(quiet.hooks.sessionEnd);
    assert.equal(quiet.hooks.stop, undefined);
    assert.equal(quiet.hooks.beforeShellExecution[0].command, 'echo keep-cursor');
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'cursor'], home).code, 0);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), original);

    const outside = join(home, 'outside-hooks.json');
    writeFileSync(outside, '{"keep":1}\n');
    rmSync(join(dir, rel));
    symlinkSync(outside, join(dir, rel));
    const linked = cliResult(dir, ['adapters', 'install', 'cursor'], home);
    assert.equal(linked.code, 1);
    assert.match(linked.err, /symlink/);
    assert.equal(readFileSync(outside, 'utf8'), '{"keep":1}\n');
    assert.equal(existsSync(join(dir, '.cursor', 'rules', 'agent-receipt.mdc')), false);
  });

  it('installs and uninstalls Codex without clobbering AGENTS.md', () => {
    const { dir, home } = gitRepo();
    const hooksRel = '.codex/hooks.json';
    const originalHooks = '{"features":{"hooks":true},"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo keep-codex"}]}]}}\n';
    const originalAgents = '# Project notes\n\nLeave this paragraph alone.\n';
    mkdirSync(join(dir, '.codex'), { recursive: true });
    writeFileSync(join(dir, hooksRel), originalHooks);
    writeFileSync(join(dir, 'AGENTS.md'), originalAgents);
    const preview = cliResult(dir, ['adapters', 'install', 'codex', '--dry-run'], home);
    assert.equal(preview.code, 0, preview.err);
    assert.equal(readFileSync(join(dir, hooksRel), 'utf8'), originalHooks);
    assert.equal(readFileSync(join(dir, 'AGENTS.md'), 'utf8'), originalAgents);
    assert.equal(existsSync(backupDir(dir, 'codex')), false);
    assert.equal(cliResult(dir, ['adapters', 'install', 'codex', '--json'], home).code, 0);
    const doc = JSON.parse(readFileSync(join(dir, hooksRel), 'utf8'));
    assert.equal(doc.features.hooks, true);
    assert.match(JSON.stringify(doc.hooks.SessionStart), /echo keep-codex/);
    assert.ok(doc.hooks.Stop);
    const agents = readFileSync(join(dir, 'AGENTS.md'), 'utf8');
    assert.match(agents, /Leave this paragraph alone/);
    assert.match(agents, /agent-receipt:codex:start/);
    assert.match(agents, /agent-receipt:codex:end/);
    const again = JSON.parse(cliResult(dir, ['adapters', 'install', 'codex', '--json'], home).out);
    assert.deepEqual(again.results[0].changed, []);
    assert.ok(doc.hooks.SessionEnd);
    assert.equal(hookCount(readFileSync(join(dir, hooksRel), 'utf8')), 2);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'codex'], home).code, 0);
    assert.equal(readFileSync(join(dir, hooksRel), 'utf8'), originalHooks);
    assert.equal(readFileSync(join(dir, 'AGENTS.md'), 'utf8'), originalAgents);
    assert.equal(existsSync(backupDir(dir, 'codex')), false);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'codex'], home).code, 0);
    assert.equal(readFileSync(join(dir, 'AGENTS.md'), 'utf8'), originalAgents);

    assert.equal(cliResult(dir, ['adapters', 'install', 'codex', '--no-stop'], home).code, 0);
    const kept = JSON.parse(readFileSync(join(dir, hooksRel), 'utf8'));
    assert.ok(kept.hooks.SessionEnd);
    assert.equal(kept.hooks.Stop, undefined);
    assert.equal(kept.features.hooks, true);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'codex'], home).code, 0);
    assert.equal(readFileSync(join(dir, hooksRel), 'utf8'), originalHooks);
    assert.equal(readFileSync(join(dir, 'AGENTS.md'), 'utf8'), originalAgents);
  });

  it('installs and uninstalls Grok, including a file that already matched the template', () => {
    const { dir, home } = gitRepo();
    mkdirSync(join(dir, '.grok', 'rules'), { recursive: true });
    mkdirSync(join(dir, '.grok', 'hooks'), { recursive: true });
    writeFileSync(join(dir, '.grok', 'rules', 'agent-receipt.md'), GROK_RULE_MD);
    writeFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), GROK_HOOK_JSON);
    writeFileSync(join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh'), GROK_WRAP_SCRIPT);
    assert.equal(cliResult(dir, ['adapters', 'install', 'grok', '--json'], home).code, 0);
    assert.equal(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), 'utf8'), GROK_HOOK_JSON);
    assert.equal(readFileSync(join(dir, '.grok', 'rules', 'agent-receipt.md'), 'utf8'), GROK_RULE_MD);
    assert.equal(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh'), 'utf8'), GROK_WRAP_SCRIPT);
    const seeded = backupDir(dir, 'grok');
    const manifest = JSON.parse(readFileSync(join(seeded, 'manifest.json'), 'utf8'));
    assert.equal(manifest.entries.every((entry) => entry.existed), true);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'grok'], home).code, 0);
    assert.equal(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), 'utf8'), GROK_HOOK_JSON);
    assert.equal(existsSync(seeded), false);

    rmSync(join(dir, '.grok'), { recursive: true, force: true });
    const preview = cliResult(dir, ['adapters', 'install', 'grok', '--dry-run'], home);
    assert.equal(preview.code, 0, preview.err);
    assert.equal(existsSync(join(dir, '.grok')), false);
    assert.equal(existsSync(backupDir(dir, 'grok')), false);
    assert.equal(cliResult(dir, ['adapters', 'install', 'grok'], home).code, 0);
    assert.equal(readFileSync(join(dir, '.grok', 'rules', 'agent-receipt.md'), 'utf8'), GROK_RULE_MD);
    assert.equal(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), 'utf8'), GROK_HOOK_JSON);
    assert.equal(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh'), 'utf8'), GROK_WRAP_SCRIPT);
    assert.doesNotMatch(git(dir, ['status', '--porcelain']), /agent-receipt-adapter-backups/);
    const fresh = readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), 'utf8');
    const again = JSON.parse(cliResult(dir, ['adapters', 'install', 'grok', '--json'], home).out);
    assert.deepEqual(again.results[0].changed, []);
    assert.equal(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), 'utf8'), fresh);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'grok'], home).code, 0);
    assert.equal(existsSync(join(dir, '.grok')), false);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'grok'], home).code, 0);

    const custom = '{"extra":true,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo keep-grok"}]}]}}\n';
    mkdirSync(join(dir, '.grok', 'hooks'), { recursive: true });
    writeFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), custom);
    assert.equal(cliResult(dir, ['adapters', 'install', 'grok', '--no-stop'], home).code, 0);
    const merged = JSON.parse(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), 'utf8'));
    assert.equal(merged.extra, true);
    assert.match(JSON.stringify(merged.hooks.PreToolUse), /echo keep-grok/);
    assert.ok(merged.hooks.SessionEnd);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'grok'], home).code, 0);
    assert.equal(readFileSync(join(dir, '.grok', 'hooks', 'agent-receipt.json'), 'utf8'), custom);
  });

  it('parses each adapter, redacts tool args, and keeps the receipt hash chain', () => {
    const { dir, home } = gitRepo();
    writeFileSync(join(dir, 'README.md'), '# repo\n\nReviewed paragraph.\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'readme']);
    cliResult(dir, ['init'], home);

    const claudeText = jsonl([
      {
        type: 'assistant',
        message: {
          content: [{
            type: 'tool_use',
            id: 'tu1',
            name: 'mcp__github__create_issue',
            input: { note: AKIA, gh: GH, sk: SK, url: SECRET_URL },
          }],
        },
      },
      { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'tu1', is_error: false }] } },
      {
        type: 'assistant',
        message: { content: [{ type: 'tool_use', id: 'tu2', name: 'Edit', input: { file_path: 'src/app.ts', old_string: 'a', new_string: 'b' } }] },
      },
      {
        type: 'assistant',
        message: { content: [{ type: 'tool_use', id: 'tu3', name: 'Bash', input: { command: 'cat only-in-shell.ts' } }] },
      },
      { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'list_issues', server: 'linear', arguments: { q: 'open' } } },
      { type: 'tool_result', tool_use_id: 7, is_error: false },
      {
        type: 'assistant',
        message: { content: [{ type: 'tool_use', id: 'tu4', name: 'CallMcpTool', input: { server: 'docs', toolName: 'search', arguments: { q: 'docs' } } }] },
      },
      { type: 'mcp_tool_call', id: 'm1', server: 'github', tool: 'close_issue', arguments: { n: 1 } },
    ]);
    const transcript = join(dir, 'transcript.jsonl');
    writeFileSync(transcript, claudeText);
    const parsed = getAdapter('claude-code').parseTranscript(transcript, dir);
    assert.equal(parsed.ok, true, parsed.reason);
    assert.ok(parsed.events.some((event) => event.tool === 'mcp:github/create_issue'));
    assert.ok(parsed.events.some((event) => event.tool === 'mcp:linear/list_issues' && event.exitStatus === 0));
    assert.ok(parsed.events.some((event) => event.tool === 'mcp:docs/search'));
    assert.ok(parsed.events.some((event) => event.tool === 'mcp:github/close_issue'));
    const edit = parsed.events.find((event) => event.tool === 'Edit');
    assert.deepEqual(edit.files, ['src/app.ts']);
    assert.deepEqual(edit.writes, ['src/app.ts']);
    const shell = parsed.events.find((event) => event.tool === 'Bash');
    assert.deepEqual(shell.files, []);
    assert.match(shell.command, /only-in-shell\.ts/);

    const cursorFile = join(dir, 'cursor.jsonl');
    writeFileSync(cursorFile, jsonl([{
      type: 'assistant',
      message: {
        content: [{
          type: 'tool_use',
          id: 'c1',
          name: 'CallMcpTool',
          input: { server: 'github', toolName: 'create_issue', arguments: JSON.stringify({ note: AKIA, title: 'from-cursor' }) },
        }],
      },
    }]));
    const cursorEvents = getAdapter('cursor').parseTranscript(cursorFile, dir);
    assert.equal(cursorEvents.ok, true, cursorEvents.reason);
    assert.equal(cursorEvents.events[0].tool, 'mcp:github/create_issue');
    assert.match(cursorEvents.events[0].argsSummary, /AKIA\[REDACTED\]/);
    assert.equal(cursorEvents.events[0].argsSummary.includes(AKIA), false);

    const codexFile = join(dir, 'codex.jsonl');
    writeFileSync(codexFile, jsonl([
      { type: 'mcp_tool_call', id: 'm2', server: 'docs', tool: 'search', arguments: { sk: SK } },
      { type: 'function_call', name: 'shell', call_id: 's1', arguments: JSON.stringify({ command: 'cat only-in-shell.ts' }) },
    ]));
    const codexEvents = getAdapter('codex').parseTranscript(codexFile, dir);
    assert.equal(codexEvents.ok, true, codexEvents.reason);
    assert.ok(codexEvents.events.some((event) => event.tool === 'mcp:docs/search' && event.argsSummary.includes('sk-ant-[REDACTED]')));
    const codexShell = codexEvents.events.find((event) => event.tool === 'shell');
    assert.deepEqual(codexShell.files, []);

    const grokFile = join(dir, 'grok.jsonl');
    writeFileSync(grokFile, jsonl([{ type: 'tool_use', id: 'g1', name: 'mcp__linear__list_issues', input: { gh: GH } }]));
    const grokEvents = getAdapter('grok').parseTranscript(grokFile, dir);
    assert.equal(grokEvents.ok, true, grokEvents.reason);
    assert.equal(grokEvents.events[0].tool, 'mcp:linear/list_issues');
    assert.match(grokEvents.events[0].argsSummary, /ghp_\[REDACTED\]/);
    const grokMd = join(dir, 'grok.md');
    writeFileSync(grokMd, 'tool: Bash\ncommand: cat only-in-shell.ts\n\ntool: Edit\nfile_path: src/app.ts\n');
    const grokMarkdown = getAdapter('grok').parseTranscript(grokMd, dir);
    assert.equal(grokMarkdown.ok, true, grokMarkdown.reason);
    assert.deepEqual(grokMarkdown.events.find((event) => event.tool === 'Bash').files, []);
    assert.deepEqual(grokMarkdown.events.find((event) => event.tool === 'Edit').files, ['src/app.ts']);

    const captured = cliResult(dir, [
      'capture', '--json', '--commits', '1', '--agent', 'claude-code', '--adapter', 'claude-code',
      '--transcript', transcript, '--message', 'tool calls',
    ], home);
    assert.equal(captured.code, 0, captured.err + captured.out);
    const gate = JSON.parse(captured.out);
    const markdown = readFileSync(gate.path, 'utf8');
    const companion = JSON.parse(readFileSync(gate.jsonPath, 'utf8'));
    assert.ok(markdown.indexOf('## Tool calls') < markdown.indexOf('## Diff summaries'));
    assert.match(markdown, /mcp:github\/create_issue/);
    assert.match(markdown, /src\/app\.ts/);
    assertRedacted(markdown, 'receipt');
    assertRedacted(JSON.stringify(companion.toolCalls), 'companion');
    assert.equal(companion.toolCalls.adapter, 'claude-code');
    assert.equal(companion.toolCalls.count, companion.toolCalls.events.length);
    assert.equal(companion.toolCalls.sha256, hashToolEvents(companion.toolCalls.events));
    assert.match(markdown, new RegExp(companion.toolCalls.sha256));
    const bash = companion.toolCalls.events.find((event) => event.tool === 'Bash');
    assert.deepEqual(bash.files, []);
    assert.match(bash.command, /only-in-shell\.ts/);
    const codes = companion.risks.map((risk) => risk.code);
    assert.ok(codes.includes('tool-call-unmentioned-diff'));
    assert.ok(codes.includes('tool-call-write-not-in-diff'));
    assert.equal(cliResult(dir, ['verify', gate.path], home).code, 0);
    assert.equal(cliResult(dir, ['audit', '--verify'], home).code, 0);

    const tampered = markdown.replace('mcp:github/create_issue', 'mcp:github/create_issue_tampered');
    writeFileSync(gate.path, tampered);
    assert.notEqual(cliResult(dir, ['verify', gate.path], home).code, 0);
    assert.equal(cliResult(dir, ['audit', '--verify'], home).code, 0);
    writeFileSync(gate.path, markdown);
    assert.equal(cliResult(dir, ['verify', gate.path], home).code, 0);

    for (const [name, file] of [['cursor', cursorFile], ['codex', codexFile], ['grok', grokFile]]) {
      const next = cliResult(dir, [
        'capture', '--json', '--commits', '1', '--agent', name, '--adapter', name, '--transcript', file, '--message', name,
      ], home);
      assert.equal(next.code, 0, next.err + next.out);
      const nextPath = JSON.parse(next.out).path;
      assert.match(readFileSync(nextPath, 'utf8'), /## Tool calls/);
      assert.equal(cliResult(dir, ['verify', nextPath], home).code, 0);
    }
    assert.equal(cliResult(dir, ['audit', '--verify'], home).code, 0);

    const empty = join(dir, 'empty.jsonl');
    writeFileSync(empty, jsonl([{ type: 'user', message: { content: [{ type: 'text', text: 'hi' }] } }]));
    const zero = cliResult(dir, [
      'capture', '--json', '--commits', '1', '--agent', 'claude-code', '--transcript', empty, '--message', 'no tools',
    ], home);
    assert.equal(zero.code, 0, zero.err);
    const zeroMd = readFileSync(JSON.parse(zero.out).path, 'utf8');
    assert.match(zeroMd, /\*\*Count\*\*: 0/);
    assert.equal(cliResult(dir, ['verify', JSON.parse(zero.out).path], home).code, 0);

    const missing = cliResult(dir, [
      'capture', '--commits', '1', '--agent', 'claude-code', '--transcript', join(dir, 'missing-transcript.jsonl'),
      '--message', 'missing-transcript-marker',
    ], home);
    assert.equal(missing.code, 0, missing.err);
    assert.match(missing.err, /transcript/);
    const receiptDir = join(dir, '.agent-receipt', 'receipts');
    const missingMd = readdirSync(receiptDir)
      .filter((name) => name.endsWith('.md'))
      .map((name) => readFileSync(join(receiptDir, name), 'utf8'))
      .find((text) => text.includes('missing-transcript-marker'));
    assert.ok(missingMd);
    assert.equal(missingMd.includes('## Tool calls'), false);

    const beforeUnknown = readdirSync(receiptDir).length;
    const nope = cliResult(dir, [
      'capture', '--json', '--commits', '1', '--adapter', 'nope', '--transcript', empty, '--message', 'bad adapter',
    ], home);
    assert.equal(nope.code, 1);
    assert.match(`${nope.err}\n${nope.out}`, /Unknown adapter/);
    assert.equal(readdirSync(receiptDir).length, beforeUnknown);

    writeFileSync(join(dir, 'other.txt'), 'dirty\n');
    const wrapped = cliResult(dir, [
      'wrap', '--agent', 'claude-code', '--transcript', empty, '--message', 'wrap-tools-marker',
    ], home);
    assert.equal(wrapped.code, 0, wrapped.err + wrapped.out);
    const wrapPath = wrapped.out.match(/path\s+(\S+\.md)/);
    assert.ok(wrapPath, wrapped.out);
    const wrapMd = readFileSync(wrapPath[1], 'utf8');
    assert.match(wrapMd, /wrap-tools-marker/);
    assert.match(wrapMd, /\*\*Count\*\*: 0/);
    assert.equal(cliResult(dir, ['audit', '--verify'], home).code, 0);
  });

  it('redacts planted secrets in every artifact for all four transcript shapes', () => {
    const { dir, home } = gitRepo();
    writeFileSync(join(dir, 'README.md'), '# repo\n\nReviewed paragraph.\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'readme']);
    assert.equal(cliResult(dir, ['init'], home).code, 0);
    const input = {
      password: PW,
      api_key: API,
      query: `select 1 where pw='${SQL}'`,
      note: TOK,
      blob: BLOB,
      endpoint: `${HOST1} ${HOST2}`,
    };
    const names = [`mcp__srv_${AKIA}__q`, `mcp__${GH}__list`, `mcp__slack__${XOX}`];
    const claudeRows = [{
      type: 'assistant',
      message: {
        content: names.map((name, index) => ({ type: 'tool_use', id: `c${index}`, name, input })),
      },
    }];
    const cursorRows = names.map((name, index) => ({
      role: 'assistant',
      composerId: 'comp-plant',
      type: 'tool_call',
      id: `k${index}`,
      name,
      input,
    }));
    const codexRows = names.map((name, index) => ({
      type: 'function_call',
      name,
      call_id: `f${index}`,
      arguments: JSON.stringify(input),
    }));
    const rpcRows = names.map((name, index) => ({
      jsonrpc: '2.0',
      id: index,
      method: 'tools/call',
      params: { name, arguments: input },
    }));
    const shapes = [
      ['claude-code', claudeRows, 'claude-code'],
      ['cursor', cursorRows, 'cursor'],
      ['codex', codexRows, 'codex'],
      ['json-rpc', rpcRows, null],
    ];
    const paths = [];
    for (const [label, rows, adapter] of shapes) {
      const transcript = join(home, `${label}.jsonl`);
      writeFileSync(transcript, jsonl(rows));
      const args = [
        'capture', '--json', '--commits', '1', '--redact', '--session', 's-plant',
        '--agent', 'claude-code', '--transcript', transcript, '--message', `planted ${label}`,
      ];
      if (adapter) args.push('--adapter', adapter);
      const captured = cliResult(dir, args, home);
      assert.equal(captured.code, 0, `${label}\n${captured.err}\n${captured.out}`);
      const gate = JSON.parse(captured.out);
      paths.push(gate.path);
      const markdown = readFileSync(gate.path, 'utf8');
      const companion = JSON.parse(readFileSync(gate.jsonPath, 'utf8'));
      assert.match(markdown, /## Tool calls/, label);
      assert.match(markdown, /AKIA\[REDACTED\]/, label);
      assert.match(markdown, /ghp_\[REDACTED\]/, label);
      assert.match(markdown, /tok_\[REDACTED\]/, label);
      assert.match(markdown, /pw='\[REDACTED\]/, label);
      assert.match(markdown, /\[host\]/, label);
      assert.equal(companion.toolCalls.adapter, label, label);
      const shared = cliResult(dir, ['share', gate.path, '--package', '--json'], home);
      assert.equal(shared.code, 0, `${label} share\n${shared.err}\n${shared.out}`);
    }
    const reported = cliResult(dir, ['report', '--session', 's-plant', '--out', join(dir, 'plant.report.html'), '--json'], home);
    assert.equal(reported.code, 0, reported.err + reported.out);
    const exported = cliResult(dir, ['session', 'export', 's-plant', '--json'], home);
    assert.equal(exported.code, 0, exported.err + exported.out);
    assert.ok(paths.length === 4);
    assertNoPlanted(dir);
  });

  it('sniffs the transcript before --agent and omits an empty toolCalls field', () => {
    const { dir, home } = gitRepo();
    writeFileSync(join(dir, 'README.md'), '# repo\n\nReviewed paragraph.\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'readme']);
    assert.equal(cliResult(dir, ['init'], home).code, 0);
    const cases = [
      ['codex', jsonl([{ type: 'function_call', name: 'shell', call_id: 's', arguments: JSON.stringify({ command: 'true' }) }]), 'codex'],
      ['cursor', jsonl([{ role: 'assistant', composerId: 'comp-1', type: 'tool_call', name: 'Read', input: { file_path: 'README.md' } }]), 'cursor'],
      ['json-rpc', jsonl([{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_issues', arguments: { q: 'open' } } }]), 'json-rpc'],
      ['claude-code', jsonl([{ type: 'assistant', message: { content: [{ type: 'tool_use', id: 'tu', name: 'Read', input: { file_path: 'README.md' } }] } }]), 'claude-code'],
    ];
    for (const [label, body, adapter] of cases) {
      const transcript = join(home, `${label}-sniff.jsonl`);
      writeFileSync(transcript, body);
      const captured = cliResult(dir, [
        'capture', '--json', '--commits', '1', '--agent', 'claude-code', '--transcript', transcript,
        '--message', `sniff ${label}`,
      ], home);
      assert.equal(captured.code, 0, `${label}\n${captured.err}\n${captured.out}`);
      const gate = JSON.parse(captured.out);
      const companion = JSON.parse(readFileSync(gate.jsonPath, 'utf8'));
      assert.equal(companion.toolCalls.adapter, adapter, label);
    }
    const bare = cliResult(dir, ['capture', '--json', '--commits', '1', '--agent', 'claude-code', '--message', 'no section'], home);
    assert.equal(bare.code, 0, bare.err + bare.out);
    const reported = cliResult(dir, ['report', JSON.parse(bare.out).path, '--out', join(dir, 'empty-tools.report.html'), '--json'], home);
    assert.equal(reported.code, 0, reported.err + reported.out);
    const html = readFileSync(JSON.parse(reported.out).htmlPath, 'utf8');
    const payload = JSON.parse(html.match(/<script type="application\/json" id="agent-receipt-report">([\s\S]*?)<\/script>/)[1]);
    assert.equal(Object.hasOwn(payload.receipts[0], 'toolCalls'), false);
    assert.match(html, /No tool-call section/);
  });

  it('strips Claude and Codex edits instead of restoring a stale snapshot', () => {
    const { dir, home } = gitRepo();
    const rel = '.claude/settings.json';
    const original = '{"permissions":{"allow":["Bash"]},"model":"x"}\n';
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, rel), original);
    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    const settingsPath = join(dir, rel);
    const doc = JSON.parse(readFileSync(settingsPath, 'utf8'));
    doc.model = 'opus';
    doc.permissions.allow.push('Edit');
    doc.hooks.PostToolUse = [{ hooks: [{ type: 'command', command: 'echo other-tool', timeout: 5 }] }];
    writeFileSync(settingsPath, `${JSON.stringify(doc, null, 2)}\n`);
    const edited = readFileSync(settingsPath, 'utf8');
    const dry = cliResult(dir, ['adapters', 'uninstall', 'claude-code', '--dry-run'], home);
    assert.equal(dry.code, 0, dry.err);
    assert.match(dry.out, /would discard user changes/);
    assert.match(dry.out, /would strip/);
    assert.equal(readFileSync(settingsPath, 'utf8'), edited);
    const forceDry = cliResult(dir, ['adapters', 'uninstall', 'claude-code', '--dry-run', '--force'], home);
    assert.match(forceDry.out, /would discard user changes/);
    assert.match(forceDry.out, /would restore/);
    assert.equal(readFileSync(settingsPath, 'utf8'), edited);
    const forced = cliResult(dir, ['adapters', 'uninstall', 'claude-code', '--force'], home);
    assert.equal(forced.code, 0, forced.err + forced.out);
    assert.match(forced.out, /restored/);
    assert.equal(readFileSync(settingsPath, 'utf8'), original);

    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    const again = JSON.parse(readFileSync(settingsPath, 'utf8'));
    again.model = 'opus';
    again.hooks.PostToolUse = [{ hooks: [{ type: 'command', command: 'echo other-tool', timeout: 5 }] }];
    writeFileSync(settingsPath, `${JSON.stringify(again, null, 2)}\n`);
    const preReinstall = readFileSync(settingsPath);
    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    const backup = backupDir(dir, 'claude-code');
    const manifest = JSON.parse(readFileSync(join(backup, 'manifest.json'), 'utf8'));
    const entry = manifest.entries.find((item) => item.rel === rel);
    assert.equal(entry.userModified, true);
    assert.equal(readFileSync(join(backup, 'files', entry.file)).equals(preReinstall), true);
    const stripped = cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home);
    assert.equal(stripped.code, 0, stripped.err + stripped.out);
    assert.match(stripped.out, /stripped/);
    assert.doesNotMatch(stripped.out, /restored \.claude\/settings\.json/);
    const kept = JSON.parse(readFileSync(settingsPath, 'utf8'));
    assert.equal(kept.model, 'opus');
    assert.match(JSON.stringify(kept.hooks.PostToolUse), /echo other-tool/);
    assert.equal(JSON.stringify(kept).includes('agent-receipt-wrap.sh'), false);

    const hooksRel = '.codex/hooks.json';
    const agentsRel = 'AGENTS.md';
    mkdirSync(join(dir, '.codex'), { recursive: true });
    writeFileSync(join(dir, hooksRel), '{"features":{"hooks":true},"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo keep-codex"}]}]}}\n');
    writeFileSync(join(dir, agentsRel), '# Notes\n\nKeep this paragraph.\n');
    assert.equal(cliResult(dir, ['adapters', 'install', 'codex'], home).code, 0);
    const hooksDoc = JSON.parse(readFileSync(join(dir, hooksRel), 'utf8'));
    hooksDoc.hooks.PreToolUse = [{ hooks: [{ type: 'command', command: 'echo other-codex' }] }];
    writeFileSync(join(dir, hooksRel), `${JSON.stringify(hooksDoc, null, 2)}\n`);
    writeFileSync(join(dir, agentsRel), `${readFileSync(join(dir, agentsRel), 'utf8')}\n## Later\n\nAlso keep this.\n`);
    const codexDry = cliResult(dir, ['adapters', 'uninstall', 'codex', '--dry-run'], home);
    assert.match(codexDry.out, /would discard user changes/);
    assert.match(codexDry.out, /would strip/);
    const codexOff = cliResult(dir, ['adapters', 'uninstall', 'codex'], home);
    assert.equal(codexOff.code, 0, codexOff.err + codexOff.out);
    assert.match(codexOff.out, /stripped/);
    const codexKept = JSON.parse(readFileSync(join(dir, hooksRel), 'utf8'));
    assert.match(JSON.stringify(codexKept.hooks.PreToolUse), /echo other-codex/);
    assert.match(JSON.stringify(codexKept.hooks.SessionStart), /echo keep-codex/);
    assert.equal(JSON.stringify(codexKept).includes('agent-receipt-wrap.sh'), false);
    const agents = readFileSync(join(dir, agentsRel), 'utf8');
    assert.match(agents, /Keep this paragraph/);
    assert.match(agents, /Also keep this/);
    assert.equal(agents.includes('agent-receipt:codex:start'), false);
  });

  it('keys a subdirectory install to the project root and strips when the snapshot is gone', () => {
    const { dir, home } = gitRepo();
    const rootRel = '.claude/settings.json';
    const rootOriginal = '{"permissions":{"allow":["Bash"]},"model":"root"}\n';
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, rootRel), rootOriginal);
    git(dir, ['add', rootRel]);
    git(dir, ['commit', '-m', 'root settings']);
    const sub = join(dir, 'sub');
    mkdirSync(sub, { recursive: true });
    assert.equal(cliResult(sub, ['adapters', 'install', 'claude-code'], home).code, 0);
    assert.equal(readFileSync(join(dir, rootRel), 'utf8'), rootOriginal);
    const manifest = JSON.parse(readFileSync(join(backupDir(dir, 'claude-code'), 'manifest.json'), 'utf8'));
    assert.ok(manifest.entries.some((entry) => entry.rel === 'sub/.claude/settings.json'));
    assert.equal(manifest.entries.some((entry) => entry.rel === rootRel), false);
    const removed = cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home);
    assert.equal(removed.code, 0, removed.err + removed.out);
    assert.equal(readFileSync(join(dir, rootRel), 'utf8'), rootOriginal);
    assert.equal(existsSync(join(sub, '.claude', 'settings.json')), false);

    writeFileSync(join(dir, rootRel), '{"permissions":{"allow":["Bash"]},"model":"kept"}\n');
    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    rmSync(backupDir(dir, 'claude-code'), { recursive: true, force: true });
    const bare = cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home);
    assert.equal(bare.code, 0, bare.err + bare.out);
    assert.match(bare.out, /stripped/);
    assert.doesNotMatch(bare.out, /restored/);
    const kept = JSON.parse(readFileSync(join(dir, rootRel), 'utf8'));
    assert.equal(kept.model, 'kept');
    assert.equal(JSON.stringify(kept).includes('agent-receipt-wrap.sh'), false);
  });

  it('rejects a corrupt backup, a traversal manifest, a symlinked backup dir, and an unignored fallback', () => {
    const corrupt = plainDir();
    assert.equal(cliResult(corrupt.dir, ['adapters', 'install', 'claude-code'], corrupt.home).code, 0);
    const corruptBackup = fallbackBackup(corrupt.dir, 'claude-code');
    const corruptManifest = join(corruptBackup, 'manifest.json');
    const installedSettings = readFileSync(join(corrupt.dir, '.claude', 'settings.json'), 'utf8');
    writeFileSync(corruptManifest, '{');
    const bad = cliResult(corrupt.dir, ['adapters', 'uninstall', 'claude-code'], corrupt.home);
    assert.equal(bad.code, 1);
    assert.match(bad.err, /adapter backup manifest is corrupt/);
    assert.equal(readFileSync(join(corrupt.dir, '.claude', 'settings.json'), 'utf8'), installedSettings);
    assert.equal(existsSync(corruptManifest), true);

    const missing = plainDir();
    mkdirSync(join(missing.dir, '.claude'), { recursive: true });
    writeFileSync(join(missing.dir, '.claude', 'settings.json'), '{"model":"keep"}\n');
    assert.equal(cliResult(missing.dir, ['adapters', 'install', 'claude-code'], missing.home).code, 0);
    const missingBackup = fallbackBackup(missing.dir, 'claude-code');
    const missingDoc = JSON.parse(readFileSync(join(missingBackup, 'manifest.json'), 'utf8'));
    const missingEntry = missingDoc.entries.find((entry) => entry.rel === '.claude/settings.json');
    rmSync(join(missingBackup, 'files', missingEntry.file));
    const gone = cliResult(missing.dir, ['adapters', 'uninstall', 'claude-code'], missing.home);
    assert.equal(gone.code, 1);
    assert.match(gone.err, /adapter backup blob is missing: \.claude\/settings\.json/);
    assert.match(readFileSync(join(missing.dir, '.claude', 'settings.json'), 'utf8'), /agent-receipt-wrap\.sh/);
    assert.equal(existsSync(join(missingBackup, 'manifest.json')), true);

    const attack = plainDir();
    assert.equal(cliResult(attack.dir, ['adapters', 'install', 'claude-code'], attack.home).code, 0);
    const attackBackup = fallbackBackup(attack.dir, 'claude-code');
    const notes = 'keep these notes\n';
    writeFileSync(join(attack.dir, 'notes.txt'), notes);
    writeFileSync(join(attack.dir, 'package.json'), '{"name":"keep"}\n');
    const attackDoc = JSON.parse(readFileSync(join(attackBackup, 'manifest.json'), 'utf8'));
    const settingsEntry = attackDoc.entries.find((entry) => entry.rel === '.claude/settings.json');
    const beforeSettings = readFileSync(join(attack.dir, '.claude', 'settings.json'), 'utf8');
    attackDoc.entries = [
      { rel: 'notes.txt', existed: false, sha256: null, postSha256: sha256Text(notes) },
      { rel: 'package.json', existed: true, file: '../../../etc/hostname', sha256: settingsEntry.sha256, postSha256: sha256Text('{"name":"keep"}\n') },
      { ...settingsEntry, file: '../../../etc/hostname' },
      { rel: '../outside.txt', existed: false, sha256: null },
    ];
    writeFileSync(join(attackBackup, 'manifest.json'), `${JSON.stringify(attackDoc, null, 2)}\n`);
    const attacked = cliResult(attack.dir, ['adapters', 'uninstall', 'claude-code'], attack.home);
    assert.equal(attacked.code, 1);
    assert.match(attacked.err, /adapter backup manifest is corrupt/);
    assert.equal(readFileSync(join(attack.dir, 'notes.txt'), 'utf8'), notes);
    assert.equal(readFileSync(join(attack.dir, 'package.json'), 'utf8'), '{"name":"keep"}\n');
    assert.equal(readFileSync(join(attack.dir, '.claude', 'settings.json'), 'utf8'), beforeSettings);
    assert.equal(existsSync(join(attackBackup, 'manifest.json')), true);

    const linked = plainDir();
    const outside = join(linked.home, 'outside-backup');
    mkdirSync(join(linked.dir, '.agent-receipt'), { recursive: true });
    mkdirSync(outside);
    symlinkSync(outside, join(linked.dir, '.agent-receipt', 'adapter-backups'));
    const refused = cliResult(linked.dir, ['adapters', 'install', 'claude-code'], linked.home);
    assert.equal(refused.code, 1);
    assert.match(refused.err, /refusing to follow a symlink in the adapter backup path/);
    assert.equal(existsSync(join(outside, 'claude-code', 'manifest.json')), false);
    assert.equal(existsSync(join(linked.dir, '.claude', 'settings.json')), false);

    const ignored = plainDir();
    const preview = cliResult(ignored.dir, ['adapters', 'install', 'claude-code', '--dry-run'], ignored.home);
    assert.equal(preview.code, 0, preview.err);
    assert.equal(existsSync(join(ignored.dir, '.gitignore')), false);
    assert.equal(existsSync(join(ignored.dir, '.claude')), false);
    assert.equal(cliResult(ignored.dir, ['adapters', 'install', 'claude-code'], ignored.home).code, 0);
    assert.equal(cliResult(ignored.dir, ['adapters', 'install', 'claude-code'], ignored.home).code, 0);
    const ignoreText = readFileSync(join(ignored.dir, '.gitignore'), 'utf8');
    assert.equal(ignoreText.split('.agent-receipt/adapter-backups/').length - 1, 1);
    git(ignored.dir, ['init']);
    git(ignored.dir, ['add', '-A']);
    assert.doesNotMatch(git(ignored.dir, ['status', '--porcelain']), /adapter-backups/);

    const linkIgnore = plainDir();
    const outsideIgnore = join(linkIgnore.home, 'gitignore');
    writeFileSync(outsideIgnore, 'keep\n');
    symlinkSync(outsideIgnore, join(linkIgnore.dir, '.gitignore'));
    const ignoreRefused = cliResult(linkIgnore.dir, ['adapters', 'install', 'claude-code'], linkIgnore.home);
    assert.equal(ignoreRefused.code, 1);
    assert.match(ignoreRefused.err, /refusing to follow a symlink: \.gitignore/);
    assert.equal(readFileSync(outsideIgnore, 'utf8'), 'keep\n');
  });

  it('preserves JSON indent, refuses a bad hooks shape, and leaves no snapshot on EACCES', () => {
    const { dir, home } = gitRepo();
    const rel = '.claude/settings.json';
    mkdirSync(join(dir, '.claude'), { recursive: true });
    const spaced = '{\n    "model": "opus",\n    "permissions": {"allow": ["Bash"]}\n}\n';
    writeFileSync(join(dir, rel), spaced);
    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    const written = readFileSync(join(dir, rel), 'utf8');
    assert.match(written, /^    "/m);
    assert.equal(JSON.parse(written).model, 'opus');
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home).code, 0);

    const tabbed = '{\n\t"model": "tabbed"\n}\n';
    writeFileSync(join(dir, rel), tabbed);
    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    assert.match(readFileSync(join(dir, rel), 'utf8'), /\n\t"/);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home).code, 0);

    const emptyHooks = '{"hooks":{"PreToolUse":[]}}\n';
    writeFileSync(join(dir, rel), emptyHooks);
    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    const emptyDoc = JSON.parse(readFileSync(join(dir, rel), 'utf8'));
    assert.deepEqual(emptyDoc.hooks.PreToolUse, []);
    assert.ok(emptyDoc.hooks.SessionEnd);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'claude-code'], home).code, 0);

    const arrayHooks = '{"hooks":[]}\n';
    writeFileSync(join(dir, rel), arrayHooks);
    const arrayRefused = cliResult(dir, ['adapters', 'install', 'claude-code'], home);
    assert.equal(arrayRefused.code, 1);
    assert.match(arrayRefused.err, /hooks must be a JSON object/);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), arrayHooks);
    assert.equal(existsSync(backupDir(dir, 'claude-code')), false);
    assert.equal(existsSync(join(dir, '.claude', 'rules')), false);

    const objectEvent = '{"hooks":{"SessionEnd":{"command":"echo"}}}\n';
    writeFileSync(join(dir, rel), objectEvent);
    const objectRefused = cliResult(dir, ['adapters', 'install', 'claude-code'], home);
    assert.equal(objectRefused.code, 1);
    assert.match(objectRefused.err, /hooks\.SessionEnd must be an array/);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), objectEvent);
    assert.equal(existsSync(backupDir(dir, 'claude-code')), false);

    const locked = '{"model":"locked"}\n';
    writeFileSync(join(dir, rel), locked);
    chmodSync(join(dir, rel), 0o444);
    const denied = cliResult(dir, ['adapters', 'install', 'claude-code'], home);
    assert.equal(denied.code, 1);
    assert.match(denied.err, /permission denied/);
    assert.equal(readFileSync(join(dir, rel), 'utf8'), locked);
    assert.equal(existsSync(backupDir(dir, 'claude-code')), false);
    assert.equal(existsSync(join(dir, '.claude', 'rules')), false);
    chmodSync(join(dir, rel), 0o644);
  });

  it('ignores its own out dir, discards hook stdout, and times out Cursor hooks', () => {
    const { dir, home } = gitRepo();
    assert.equal(cliResult(dir, ['init'], home).code, 0);
    assert.equal(cliResult(dir, ['adapters', 'install', 'claude-code'], home).code, 0);
    assert.equal(cliResult(dir, ['adapters', 'install', 'codex'], home).code, 0);
    assert.equal(cliResult(dir, ['adapters', 'install', 'cursor'], home).code, 0);
    const scripts = [
      '.claude/hooks/agent-receipt-wrap.sh',
      '.codex/hooks/agent-receipt-wrap.sh',
      '.cursor/hooks/agent-receipt-wrap.sh',
    ];
    for (const rel of scripts) {
      const text = readFileSync(join(dir, rel), 'utf8');
      assert.match(text, /git status --porcelain/);
      assert.match(text, />\/dev\/null 2>&1/);
      assert.match(text, /timeout 120/);
      assert.match(text, /git rev-parse --show-toplevel/);
    }
    const cursorDoc = JSON.parse(readFileSync(join(dir, '.cursor', 'hooks.json'), 'utf8'));
    assert.equal(cursorDoc.hooks.sessionEnd[0].timeout, 120);
    assert.equal(cursorDoc.hooks.stop[0].timeout, 120);
    assert.match(cursorDoc.hooks.sessionEnd[0].command, /git rev-parse --show-toplevel/);
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-m', 'hooks']);
    const pathDir = pathShim(home);
    mkdirSync(join(dir, '.agent-receipt', 'receipts'), { recursive: true });
    writeFileSync(join(dir, '.agent-receipt', 'receipts', 'plant.md'), 'untracked receipt\n');
    writeFileSync(join(dir, '.agent-receipt', 'index.json'), '{}\n');
    writeFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), '');
    const before = receiptMdCount(dir);
    for (const rel of scripts) {
      const ran = runHook(dir, home, rel, pathDir);
      assert.equal(ran.status, 0, `${rel}\n${ran.stderr}`);
    }
    assert.equal(receiptMdCount(dir), before);
    writeFileSync(join(dir, 'user-dirty.txt'), 'dirty\n');
    const wrapped = runHook(dir, home, scripts[0], pathDir);
    assert.equal(wrapped.status, 0, wrapped.stderr);
    assert.equal(receiptMdCount(dir), before + 1);
    git(dir, ['add', 'user-dirty.txt']);
    git(dir, ['commit', '-m', 'user file']);
    for (const rel of scripts) {
      const ran = runHook(dir, home, rel, pathDir);
      assert.equal(ran.status, 0, `${rel}\n${ran.stderr}`);
    }
    assert.equal(receiptMdCount(dir), before + 1);
  });
});
