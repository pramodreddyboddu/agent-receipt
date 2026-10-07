/**
 * v1.0.39 bare 0x host labels.
 * WHATWG treats a last label of exactly 0x as hex zero (an IPv4 form).
 * The CLI child uses port 0, a hard timeout, and is killed in finally.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { hostHeaderAllowed, normalizeAllowedHost } from '../dist/lib/viewer-host.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const dirs = [];
const children = [];

function fresh(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

after(() => {
  for (const child of children) {
    if (child.exitCode === null && !child.signalCode) {
      try {
        child.kill('SIGKILL');
      } catch {
        // Already gone.
      }
    }
  }
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe('v1.0.39 bare 0x host labels', { concurrency: 1 }, () => {
  it('rejects a bare 0x label and keeps non-numeric neighbors', () => {
    for (const value of ['foo.0x', '0x', 'FOO.0X', 'foo.0x:8080']) {
      assert.throws(() => normalizeAllowedHost(value), /non-canonical/i, value);
    }
    assert.equal(normalizeAllowedHost('0x7f.example').normalized, '0x7f.example');
    assert.equal(normalizeAllowedHost('foo.0xg').normalized, 'foo.0xg');
    assert.equal(normalizeAllowedHost('foo.0x-a').normalized, 'foo.0x-a');

    assert.equal(hostHeaderAllowed('foo.0x:4173', 'foo.0x', 4173, []), false);
    assert.equal(hostHeaderAllowed('FOO.0X:8080', '0.0.0.0', 8080, []), false);
    assert.equal(hostHeaderAllowed('0x:4173', '0x', 4173, []), false);
    const neighbor = normalizeAllowedHost('foo.0xg');
    assert.equal(hostHeaderAllowed('foo.0xg:4173', '0.0.0.0', 4173, [neighbor]), true);
    assert.equal(hostHeaderAllowed('foo.0x-a:4173', '0.0.0.0', 4173, [normalizeAllowedHost('foo.0x-a')]), true);
    assert.equal(hostHeaderAllowed('0x7f.example:4173', '0.0.0.0', 4173, [normalizeAllowedHost('0x7f.example')]), true);
  });

  it('view --allowed-host foo.0x exits non-zero and does not listen', async () => {
    const cwd = fresh('agent-receipt-1039-hex-');
    const child = spawn(
      process.execPath,
      [bin, 'view', '--allowed-host', 'foo.0x', '--allow-remote', '--host', '0.0.0.0', '--port', '0'],
      {
        cwd,
        env: { ...process.env, NO_COLOR: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    children.push(child);
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
    });
    let result;
    try {
      result = await new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve(value);
        };
        const timer = setTimeout(() => {
          try {
            child.kill('SIGKILL');
          } catch {
            // Already gone.
          }
          finish({ timedOut: true, code: null, signal: 'SIGKILL', out, err });
        }, 4000);
        child.once('close', (code, signal) => {
          finish({ timedOut: false, code, signal, out, err });
        });
        child.once('error', (error) => {
          finish({ timedOut: false, code: 1, signal: null, out, err: `${err}${error.message}` });
        });
      });
      assert.equal(result.timedOut, false);
      assert.notEqual(result.code, 0);
      assert.equal(result.code, 1);
      assert.equal(result.signal, null);
      assert.match(result.err, /non-canonical/i);
      assert.equal(/https?:\/\//.test(result.out), false);
      assert.equal(result.out.trim(), '');
      assert.equal(/binds|Serving|Allowed hosts/.test(result.err), false);
    } finally {
      if (child.exitCode === null && !child.signalCode) {
        try {
          child.kill('SIGKILL');
        } catch {
          // Already gone.
        }
      }
    }
  });
});
