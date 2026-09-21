import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  chmodSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
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
    assert.match(GROK_WRAP_SCRIPT, /drain_hook_stdin/);
    assert.match(GROK_WRAP_SCRIPT, /must not block waiting for EOF/);
    assert.doesNotMatch(GROK_WRAP_SCRIPT, /cat >\/dev\/null/);
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

  function runOpenStdin(script, env, payload) {
    return new Promise((resolve, reject) => {
      const child = spawn('/bin/sh', [script], {
        cwd: dir,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const started = Date.now();
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => {
        stdout += d;
      });
      child.stderr.on('data', (d) => {
        stderr += d;
      });
      if (payload) child.stdin.write(payload);
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`SessionEnd hook hung with stdin left open (${Date.now() - started}ms)`));
      }, 3000);
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        try {
          child.stdin.destroy();
        } catch {
          /* already closed */
        }
        resolve({ code, stdout, stderr, elapsed: Date.now() - started });
      });
    });
  }

  it('SessionEnd script does not hang when stdin stays open without EOF', async () => {
    cli(dir, ['init', '--grok']);
    const script = join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh');
    const env = {
      ...process.env,
      PATH: '/usr/bin:/bin',
      GROK_WORKSPACE_ROOT: dir,
      HOOK_STDIN_WAIT_SEC: '0.3',
    };

    const empty = await runOpenStdin(script, env);
    assert.equal(empty.code, 0);
    // Bounded wait (timeout + dd), not an instant skip and not an EOF hang.
    assert.ok(empty.elapsed >= 180, `expected a bounded wait, got ${empty.elapsed}ms`);
    assert.ok(empty.elapsed < 2500, `drain took too long: ${empty.elapsed}ms`);

    const primed = await runOpenStdin(script, env, '{"event":"SessionEnd"}\n');
    assert.equal(primed.code, 0);
    assert.ok(primed.elapsed < 1000, `payload+open stdin took ${primed.elapsed}ms`);
  });

  it('SessionEnd drain uses node when timeout is not on PATH', async () => {
    cli(dir, ['init', '--grok']);
    const script = join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh');
    const binDir = mkdtempSync(join(tmpdir(), 'agent-receipt-notimeout-'));
    const link = (cmd) => {
      const src = execFileSync('sh', ['-c', `command -v ${cmd}`], { encoding: 'utf8' }).trim();
      symlinkSync(src, join(binDir, cmd));
    };
    link('node');
    link('git');
    const env = {
      ...process.env,
      PATH: binDir,
      GROK_WORKSPACE_ROOT: dir,
      HOOK_STDIN_WAIT_SEC: '0.3',
    };
    const result = await runOpenStdin(script, env);
    assert.equal(result.code, 0);
    assert.ok(result.elapsed >= 180, `node drain returned too fast (${result.elapsed}ms)`);
    assert.ok(result.elapsed < 2500, `node drain took ${result.elapsed}ms`);
    rmSync(binDir, { recursive: true, force: true });
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
