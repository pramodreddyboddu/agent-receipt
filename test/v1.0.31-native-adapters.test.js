import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
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
    assert.match(init.out, /--grok/);
    assert.match(init.out, /\.grok\/rules/);
    const report = cliResult(root, ['help', 'report'], home);
    assert.match(report.out, /Version 2 is this page/);
    assert.match(report.out, /Version 1 stays/);
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
    assert.equal(hookCount(readFileSync(join(dir, hooksRel), 'utf8')), 1);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'codex'], home).code, 0);
    assert.equal(readFileSync(join(dir, hooksRel), 'utf8'), originalHooks);
    assert.equal(readFileSync(join(dir, 'AGENTS.md'), 'utf8'), originalAgents);
    assert.equal(existsSync(backupDir(dir, 'codex')), false);
    assert.equal(cliResult(dir, ['adapters', 'uninstall', 'codex'], home).code, 0);
    assert.equal(readFileSync(join(dir, 'AGENTS.md'), 'utf8'), originalAgents);

    assert.equal(cliResult(dir, ['adapters', 'install', 'codex', '--no-stop'], home).code, 0);
    const kept = JSON.parse(readFileSync(join(dir, hooksRel), 'utf8'));
    assert.ok(kept.hooks.Stop);
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
            input: { token: AKIA, gh: GH, sk: SK, url: SECRET_URL },
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
          input: { server: 'github', toolName: 'create_issue', arguments: JSON.stringify({ token: AKIA, title: 'from-cursor' }) },
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
});
