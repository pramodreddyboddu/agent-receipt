import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { clampInterval } from '../dist/commands/watch.js';
import { CURSOR_RULE_MDC } from '../dist/lib/cursor-rule.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args, extra = {}) {
  return execFileSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    ...extra,
  });
}

function cliStatus(cwd, args) {
  try {
    const out = cli(cwd, args);
    return { ok: true, code: 0, out, err: '' };
  } catch (err) {
    return {
      ok: false,
      code: err.status ?? 1,
      out: String(err.stdout || ''),
      err: String(err.stderr || err.message || err),
    };
  }
}

describe('clampInterval', () => {
  it('defaults, clamps min 1 and max 3600', () => {
    assert.equal(clampInterval(undefined), 5);
    assert.equal(clampInterval(0), 1);
    assert.equal(clampInterval(1), 1);
    assert.equal(clampInterval(99999), 3600);
    assert.equal(clampInterval(10), 10);
  });
});

describe('history + fail-on + init --cursor', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-hw-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# hw fixture\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('init --cursor writes the alwaysApply rule', () => {
    const out = cli(dir, ['init', '--cursor']);
    assert.match(out, /cursor:/);
    const rule = join(dir, '.cursor', 'rules', 'agent-receipt.mdc');
    assert.ok(existsSync(rule));
    const body = readFileSync(rule, 'utf8');
    assert.match(body, /alwaysApply: true/);
    assert.match(body, /agent-receipt capture --agent cursor/);
    assert.match(body, /watch --once/);
    assert.equal(body, CURSOR_RULE_MDC);
  });

  it('history lists receipts with time, agent, summary', () => {
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'hist-bot',
      '--message',
      'first session',
    ]);
    writeFileSync(join(dir, 'README.md'), '# hw fixture\n\nedit\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'edit readme']);
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'hist-bot',
      '--message',
      'second session',
    ]);

    const out = cli(dir, ['history']);
    assert.match(out, /Recent receipts/);
    assert.match(out, /TIME/);
    assert.match(out, /AGENT/);
    assert.match(out, /hist-bot/);
    assert.match(out, /first session|second session/);
    assert.match(out, /newest:/);

    const ls = cli(dir, ['ls', '--limit', '1']);
    assert.match(ls, /Recent receipts \(1 of /);
  });

  it('capture --fail-on high exits 2 when .env is committed', () => {
    writeFileSync(join(dir, '.env'), 'SECRET=1\n');
    git(dir, ['add', '.env']);
    git(dir, ['commit', '-m', 'add env']);
    const r = cliStatus(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'ci',
      '--message',
      'env leak',
      '--fail-on',
      'high',
      '--out',
      'env-receipt.md',
    ]);
    assert.equal(r.code, 2);
    assert.match(r.out + r.err, /fail-on high/);
    assert.match(r.out, /Wrote receipt/);
    assert.ok(existsSync(join(dir, 'env-receipt.md')));
    const md = readFileSync(join(dir, 'env-receipt.md'), 'utf8');
    assert.match(md, /> \*\*TL;DR\*\*/);
    assert.match(md, /## What to review/);
    assert.match(md, /env-file/);
  });

  it('bare --fail-on means high', () => {
    const r = cliStatus(dir, [
      'capture',
      '--commits',
      '1',
      '--fail-on',
      '--out',
      'env-receipt-bare.md',
    ]);
    assert.equal(r.code, 2);
    assert.match(r.out + r.err, /fail-on high/);
  });

  it('capture --fail-on high exits 0 on a clean text change', () => {
    writeFileSync(join(dir, 'notes.txt'), 'hello\n');
    git(dir, ['add', 'notes.txt']);
    git(dir, ['commit', '-m', 'notes']);
    const r = cliStatus(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'ci',
      '--message',
      'clean',
      '--fail-on',
      'high',
      '--out',
      'clean-receipt.md',
    ]);
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, /Wrote receipt/);
  });
});

describe('watch --once', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-watch-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# watch fixture\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('captures after detecting a new commit, then exits', async () => {
    const child = spawn(
      process.execPath,
      [bin, 'watch', '--once', '--interval', '1', '--agent', 'watch-bot', '--message', 'from-watch'],
      {
        cwd: dir,
        env: { ...process.env, NO_COLOR: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });

    const started = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('watch did not start: ' + stdout + stderr)), 8000);
      const check = () => {
        if (/baseline:/.test(stdout)) {
          clearTimeout(t);
          resolve(true);
        }
      };
      child.stdout.on('data', check);
      check();
    });
    assert.equal(started, true);

    writeFileSync(join(dir, 'watched.txt'), 'hello from watch\n');
    git(dir, ['add', 'watched.txt']);
    git(dir, ['commit', '-m', 'watch trigger']);

    const code = await new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('watch --once did not exit: ' + stdout + stderr));
      }, 15000);
      child.on('close', (c) => {
        clearTimeout(t);
        resolve(c);
      });
    });

    assert.equal(code, 0, stdout + stderr);
    assert.match(stdout, /Wrote receipt/);
    assert.match(stdout, /watch-bot|from-watch|capturing/);
    const receipts = readdirSync(join(dir, '.agent-receipt', 'receipts')).filter((f) =>
      f.endsWith('.md'),
    );
    assert.ok(receipts.length >= 1);
    const md = readFileSync(join(dir, '.agent-receipt', 'receipts', receipts[0]), 'utf8');
    assert.match(md, /watched\.txt|from-watch|watch-bot/);
  });
});
