import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  chmodSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  GROK_RULE_MD,
  GROK_HOOK_JSON,
  GROK_WRAP_SCRIPT,
} from '../dist/lib/grok-rule.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args) {
  return execFileSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

describe('init --grok', { concurrency: false }, () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-grok-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# grok fixture\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('writes the Grok rule, SessionEnd hook, and wrap script', () => {
    const out = cli(dir, ['init', '--grok']);
    assert.match(out, /grok:/);
    assert.match(out, /hook:/);
    assert.match(out, /wrap --agent grok --redact/);
    assert.match(out, /grok --trust/);

    const rule = join(dir, '.grok', 'rules', 'agent-receipt.md');
    const hook = join(dir, '.grok', 'hooks', 'agent-receipt.json');
    const script = join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh');
    assert.equal(readFileSync(rule, 'utf8'), GROK_RULE_MD);
    assert.equal(readFileSync(hook, 'utf8'), GROK_HOOK_JSON);
    assert.equal(readFileSync(script, 'utf8'), GROK_WRAP_SCRIPT);

    const hookJson = JSON.parse(readFileSync(hook, 'utf8'));
    const cmd = hookJson.hooks.SessionEnd[0].hooks[0];
    assert.equal(cmd.type, 'command');
    assert.equal(cmd.command, 'sh .grok/hooks/agent-receipt-wrap.sh');
    assert.equal(cmd.timeout, 120);
    assert.match(GROK_RULE_MD, /wrap --agent grok --redact/);
    assert.match(GROK_RULE_MD, /--uncommitted/);
    assert.match(GROK_WRAP_SCRIPT, /--redact/);
    assert.match(GROK_WRAP_SCRIPT, /--uncommitted/);
    assert.match(GROK_WRAP_SCRIPT, /git status --porcelain/);
  });

  it('does not write .grok files without --grok', () => {
    const bare = mkdtempSync(join(tmpdir(), 'agent-receipt-grok-bare-'));
    try {
      git(bare, ['init']);
      git(bare, ['config', 'user.email', 'test@example.com']);
      git(bare, ['config', 'user.name', 'Test']);
      writeFileSync(join(bare, 'README.md'), '# bare\n');
      git(bare, ['add', 'README.md']);
      git(bare, ['commit', '-m', 'initial']);
      const out = cli(bare, ['init']);
      assert.match(out, /init --grok/);
      assert.equal(existsSync(join(bare, '.grok')), false);
      assert.ok(existsSync(join(bare, '.agent-receipt.yml')));
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });

  it('help init documents --grok', () => {
    const out = cli(dir, ['help', 'init']);
    assert.match(out, /--grok/);
    assert.match(out, /\.grok\/rules/);
    assert.match(out, /--cursor/);
  });

  it('examples/.grok matches the files init writes', () => {
    assert.equal(
      readFileSync(join(root, 'examples/.grok/rules/agent-receipt.md'), 'utf8'),
      GROK_RULE_MD,
    );
    assert.equal(
      readFileSync(join(root, 'examples/.grok/hooks/agent-receipt.json'), 'utf8'),
      GROK_HOOK_JSON,
    );
    assert.equal(
      readFileSync(join(root, 'examples/.grok/hooks/agent-receipt-wrap.sh'), 'utf8'),
      GROK_WRAP_SCRIPT,
    );
  });

  it('SessionEnd script skips a clean tree and wraps a dirty one with --redact', () => {
    const script = join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh');
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-m', 'init grok']);
    const argsFile = join(dir, 'wrap-args.txt');
    // Keep the fake binary outside the repo so it does not dirty the tree.
    const fakeBin = mkdtempSync(join(tmpdir(), 'agent-receipt-fakebin-'));
    writeFileSync(
      join(fakeBin, 'agent-receipt'),
      '#!/bin/sh\nprintf "%s\\n" "$@" > "$WRAP_ARGS"\nexit 0\n',
    );
    chmodSync(join(fakeBin, 'agent-receipt'), 0o755);
    const env = {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      WRAP_ARGS: argsFile,
      GROK_WORKSPACE_ROOT: dir,
    };

    execFileSync('sh', [script], { cwd: dir, env, encoding: 'utf8' });
    assert.equal(existsSync(argsFile), false);

    writeFileSync(join(dir, 'dirty.txt'), 'uncommitted\n');
    execFileSync('sh', [script], { cwd: dir, env, encoding: 'utf8' });
    const args = readFileSync(argsFile, 'utf8').trim().split('\n');
    rmSync(fakeBin, { recursive: true, force: true });
    assert.deepEqual(args, [
      'wrap',
      '--agent',
      'grok',
      '--redact',
      '--uncommitted',
      '--message',
      'grok session (uncommitted)',
    ]);
  });

  it('SessionEnd script is non-blocking when agent-receipt is missing', () => {
    const script = join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh');
    writeFileSync(join(dir, 'still-dirty.txt'), 'x\n');
    const result = spawnSync('sh', [script], {
      cwd: dir,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: '/usr/bin:/bin',
        GROK_WORKSPACE_ROOT: dir,
      },
    });
    assert.equal(result.status, 0);
    assert.match(result.stderr, /not on PATH/);
  });
});
