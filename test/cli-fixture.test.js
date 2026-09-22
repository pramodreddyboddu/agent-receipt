import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args) {
  return execFileSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
  });
}

describe('cli fixture', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# fixture\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    writeFileSync(join(dir, 'README.md'), '# fixture\n\nupdated\n');
    writeFileSync(join(dir, 'app.js'), 'console.log(1)\n');
    git(dir, ['add', '.']);
    git(dir, ['commit', '-m', 'update']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('help exits 0 and lists core commands', () => {
    const out = cli(dir, ['help']);
    assert.match(out, /agent-receipt/);
    assert.match(out, /capture/);
    assert.match(out, /last/);
    assert.match(out, /install-hooks/);
    assert.match(out, /doctor/);
    assert.match(out, /compare/);
    assert.match(out, /history/);
    assert.match(out, /watch/);
  });

  it('version is 1.0.8', () => {
    const out = cli(dir, ['version']);
    assert.match(out, /1\.0\.8/);
  });

  it('init writes config', () => {
    const out = cli(dir, ['init']);
    assert.match(out, /Initialized/);
    assert.ok(existsSync(join(dir, '.agent-receipt.yml')));
    assert.ok(existsSync(join(dir, '.agent-receipt', 'SETUP.md')));
  });

  it('capture + verify roundtrip with summary', () => {
    const out = cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'test-bot',
      '--message',
      'fixture run',
      '--json',
      '--out',
      'receipt.md',
    ]);
    const gate = JSON.parse(out);
    assert.equal(gate.ok, true);
    assert.equal(gate.command, 'capture');
    assert.equal(gate.exitCode, 0);
    assert.equal(gate.verified, null);
    assert.equal(gate.path, join(dir, 'receipt.md'));
    assert.equal(gate.jsonPath, join(dir, 'receipt.json'));
    assert.ok(existsSync(join(dir, 'receipt.md')));
    assert.ok(existsSync(join(dir, 'receipt.json')));
    const md = readFileSync(join(dir, 'receipt.md'), 'utf8');
    assert.match(md, /Agent Receipt/);
    assert.match(md, /## Summary/);
    assert.match(md, /## What to review/);
    assert.match(md, /TL;DR/);
    assert.match(md, /test-bot/);
    assert.match(md, /fixture run/);
    assert.match(md, /1\.0\.8/);
    assert.match(md, /agent-receipt-sha256/);
    const json = JSON.parse(readFileSync(join(dir, 'receipt.json'), 'utf8'));
    assert.ok(json.summary);
    assert.equal(typeof json.summary.files, 'number');
    const v = cli(dir, ['verify', 'receipt.md']);
    assert.match(v, /OK/);
  });

  it('show prints receipt', () => {
    const out = cli(dir, ['show', 'receipt.md']);
    assert.match(out, /Agent Receipt/);
  });

  it('last reports newest receipt under outDir', () => {
    // seed default outDir receipt
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'last-bot',
      '--message',
      'for last',
    ]);
    const out = cli(dir, ['last']);
    assert.match(out, /latest:/);
    assert.match(out, /\.agent-receipt\/receipts\/receipt-/);
    const pathOnly = cli(dir, ['last', '--path']).trim();
    assert.ok(pathOnly.endsWith('.md'));
    assert.ok(existsSync(pathOnly));
  });

  it('install-hooks installs and uninstall-hooks removes post-commit hook', () => {
    const out = cli(dir, ['install-hooks']);
    assert.match(out, /post-commit hook (created|updated)/);
    const gitDir = git(dir, ['rev-parse', '--git-dir']);
    const hookPath = join(dir, gitDir, 'hooks', 'post-commit');
    assert.ok(existsSync(hookPath));
    const hook = readFileSync(hookPath, 'utf8');
    assert.match(hook, /agent-receipt/);
    assert.match(hook, /capture/);

    const out2 = cli(dir, ['uninstall-hooks']);
    assert.match(out2, /removed/i);
  });

  it('fails cleanly outside a git repo', () => {
    const bare = mkdtempSync(join(tmpdir(), 'agent-receipt-bare-'));
    try {
      let failed = false;
      try {
        cli(bare, ['capture', '--message', 'nope']);
      } catch (err) {
        failed = true;
        assert.match(String(err.stderr || err.message || err), /Not a git repository/i);
      }
      assert.equal(failed, true);
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });

  it('honors --session and --cwd', () => {
    const out = cli(tmpdir(), [
      'capture',
      '--cwd',
      dir,
      '--commits',
      '1',
      '--agent',
      'cursor',
      '--session',
      'sess-99',
      '--out',
      'session-receipt.md',
    ]);
    assert.match(out, /Wrote receipt/);
    const md = readFileSync(join(dir, 'session-receipt.md'), 'utf8');
    assert.match(md, /sess-99/);
    assert.match(md, /cursor/);
    assert.match(md, /## Summary/);
  });

  it('unknown command exits non-zero', () => {
    let failed = false;
    try {
      cli(dir, ['not-a-command']);
    } catch (err) {
      failed = true;
      assert.match(String(err.stderr || err.message || err), /Unknown command/i);
    }
    assert.equal(failed, true);
  });
});
