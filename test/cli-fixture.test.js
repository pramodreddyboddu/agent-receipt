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

  it('help exits 0', () => {
    const out = cli(dir, ['help']);
    assert.match(out, /agent-receipt/);
    assert.match(out, /capture/);
  });

  it('init writes config', () => {
    const out = cli(dir, ['init']);
    assert.match(out, /Initialized/);
    assert.ok(existsSync(join(dir, '.agent-receipt.yml')));
    assert.ok(existsSync(join(dir, '.agent-receipt', 'SETUP.md')));
  });

  it('capture + verify roundtrip', () => {
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
    assert.match(out, /Wrote receipt/);
    assert.ok(existsSync(join(dir, 'receipt.md')));
    assert.ok(existsSync(join(dir, 'receipt.json')));
    const md = readFileSync(join(dir, 'receipt.md'), 'utf8');
    assert.match(md, /Agent Receipt/);
    assert.match(md, /test-bot/);
    assert.match(md, /fixture run/);
    assert.match(md, /agent-receipt-sha256/);
    const v = cli(dir, ['verify', 'receipt.md']);
    assert.match(v, /OK/);
  });

  it('show prints receipt', () => {
    const out = cli(dir, ['show', 'receipt.md']);
    assert.match(out, /Agent Receipt/);
  });
});
