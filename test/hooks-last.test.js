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
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  MARKER_BEGIN,
  MARKER_END,
  resolveCliInvocation,
  resolvePackageBinPath,
  postCommitBody,
} from '../dist/commands/hooks.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args, env = {}) {
  return execFileSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...env },
  });
}

describe('hooks + last', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-hooks-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# hooks fixture\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('install-hooks writes post-commit with markers', () => {
    const out = cli(dir, ['install-hooks']);
    assert.match(out, /post-commit hook created/);
    const hook = join(dir, '.git', 'hooks', 'post-commit');
    assert.ok(existsSync(hook));
    const body = readFileSync(hook, 'utf8');
    assert.ok(body.includes(MARKER_BEGIN));
    assert.ok(body.includes(MARKER_END));
    assert.match(body, /agent-receipt/);
  });

  it('install-hooks --pre-push adds pre-push', () => {
    const out = cli(dir, ['install-hooks', '--pre-push']);
    assert.match(out, /pre-push hook/);
    const hook = join(dir, '.git', 'hooks', 'pre-push');
    assert.ok(existsSync(hook));
    assert.ok(readFileSync(hook, 'utf8').includes(MARKER_BEGIN));
  });

  it('preserves existing hook content on reinstall', () => {
    const hook = join(dir, '.git', 'hooks', 'post-commit');
    const custom = '#!/bin/sh\necho custom-before\n';
    writeFileSync(hook, custom + '\n' + MARKER_BEGIN + '\nold\n' + MARKER_END + '\n', {
      mode: 0o755,
    });
    cli(dir, ['install-hooks']);
    const body = readFileSync(hook, 'utf8');
    assert.match(body, /custom-before/);
    assert.ok(body.includes(MARKER_BEGIN));
    assert.ok(!body.includes('old\n'));
  });

  it('uninstall-hooks removes managed sections', () => {
    const out = cli(dir, ['uninstall-hooks']);
    assert.match(out, /removed/i);
    const post = join(dir, '.git', 'hooks', 'post-commit');
    if (existsSync(post)) {
      assert.ok(!readFileSync(post, 'utf8').includes(MARKER_BEGIN));
    }
    const pre = join(dir, '.git', 'hooks', 'pre-push');
    if (existsSync(pre)) {
      assert.ok(!readFileSync(pre, 'utf8').includes(MARKER_BEGIN));
    }
  });

  it('last shows newest receipt', () => {
    cli(dir, ['init']);
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'test',
      '--message',
      'for-last',
    ]);
    const receipts = readdirSync(join(dir, '.agent-receipt', 'receipts')).filter((f) =>
      f.endsWith('.md'),
    );
    assert.ok(receipts.length >= 1);
    const out = cli(dir, ['last']);
    assert.match(out, /Agent Receipt/);
    assert.match(out, /for-last/);
    assert.match(out, /latest:/);
  });


  it('install-hooks embeds absolute bin path (not only npx)', () => {
    // Fresh install into a clean hooks dir state
    const hook = join(dir, '.git', 'hooks', 'post-commit');
    if (existsSync(hook)) {
      // force rewrite via uninstall + install
      cli(dir, ['uninstall-hooks']);
    }
    const out = cli(dir, ['install-hooks']);
    assert.match(out, /post-commit hook/);
    const body = readFileSync(hook, 'utf8');
    assert.ok(body.includes(MARKER_BEGIN));
    // Must embed real path to agent-receipt.js OR AGENT_RECEIPT_BIN fallback logic
    assert.match(body, /agent-receipt\.js/);
    assert.match(body, /AGENT_RECEIPT_BIN/);
    assert.match(body, /agent_receipt_run/);
    // Should not be npx-only: either absolute path present, or env-first with embedded path
    const hasAbsBin = /['"]\/[^'"]*agent-receipt\.js['"]/.test(body);
    const hasEnvFallback = body.includes('AGENT_RECEIPT_BIN');
    assert.ok(hasAbsBin || hasEnvFallback, 'hook must embed abs path or env fallback');
    assert.ok(
      hasAbsBin,
      'expected embedded absolute path to bin/agent-receipt.js for local dogfood',
    );
    // npx may appear as last resort but must not be the only invocation
    if (body.includes('npx --yes agent-receipt')) {
      assert.ok(hasAbsBin, 'npx present only as fallback alongside embedded bin');
    }
  });

  it('resolveCliInvocation prefers AGENT_RECEIPT_BIN then package bin', () => {
    const prev = process.env.AGENT_RECEIPT_BIN;
    try {
      process.env.AGENT_RECEIPT_BIN = '/tmp/custom-agent-receipt.js';
      const viaEnv = resolveCliInvocation();
      assert.equal(viaEnv.kind, 'env');
      assert.match(viaEnv.primary, /custom-agent-receipt\.js/);

      delete process.env.AGENT_RECEIPT_BIN;
      const viaBin = resolveCliInvocation();
      assert.equal(viaBin.kind, 'bin');
      assert.ok(viaBin.binPath && viaBin.binPath.includes('agent-receipt.js'));
      assert.match(viaBin.primary, /agent-receipt\.js/);
      assert.ok(!viaBin.primary.includes('npx'));

      const pkgBin = resolvePackageBinPath();
      assert.ok(pkgBin && pkgBin.endsWith('agent-receipt.js'));

      const body = postCommitBody();
      assert.match(body, /agent_receipt_run/);
      assert.ok(body.includes(pkgBin));
    } finally {
      if (prev === undefined) delete process.env.AGENT_RECEIPT_BIN;
      else process.env.AGENT_RECEIPT_BIN = prev;
    }
  });

  it('install-hooks fails outside git repo', () => {
    const bare = mkdtempSync(join(tmpdir(), 'agent-receipt-hooks-bare-'));
    try {
      let failed = false;
      try {
        cli(bare, ['install-hooks']);
      } catch (err) {
        failed = true;
        assert.match(String(err.stderr || err.message || err), /Not a git repository/i);
      }
      assert.equal(failed, true);
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });
});
