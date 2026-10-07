/**
 * v1.0.38 viewer --allowed-host.
 * Live binds use port 0. Children are killed in finally and after.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from '../dist/lib/args.js';
import {
  hostHeaderAllowed,
  normalizeAllowedHost,
  normalizeAllowedHosts,
} from '../dist/lib/viewer-host.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const LINK_ENV = [
  'AGENT_RECEIPT_SESSION',
  'AGENT_RECEIPT_PARENT',
  'AGENT_RECEIPT_AGENT',
  'AGENT_RECEIPT_HOST',
];

const dirs = [];
const children = [];

function baseEnv(extra = {}) {
  const env = { ...process.env, NO_COLOR: '1', ...extra };
  for (const key of LINK_ENV) {
    if (!Object.prototype.hasOwnProperty.call(extra, key)) delete env[key];
  }
  return env;
}

function fresh(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

function stopChild(child) {
  return new Promise((resolve) => {
    if (!child || child.exitCode !== null || child.signalCode) {
      resolve({ code: child ? child.exitCode : null, signal: child ? child.signalCode : null, forced: false });
      return;
    }
    let forced = false;
    const finish = (code, signal) => {
      clearTimeout(termTimer);
      clearTimeout(killTimer);
      resolve({ code, signal, forced });
    };
    const killTimer = setTimeout(() => {
      forced = true;
      try {
        child.kill('SIGKILL');
      } catch {
        finish(null, 'SIGKILL');
      }
    }, 3000);
    const termTimer = setTimeout(() => {
      forced = true;
      try {
        child.kill('SIGKILL');
      } catch {
        finish(null, 'SIGKILL');
      }
    }, 2000);
    child.once('exit', finish);
    try {
      child.kill('SIGTERM');
    } catch {
      finish(null, 'SIGTERM');
    }
  });
}

function startViewer(cwd, args) {
  const child = spawn(process.execPath, [bin, 'view', '--port', '0', '--json', ...args], {
    cwd,
    env: baseEnv(),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let out = '';
  let err = '';
  child.stdout.on('data', (chunk) => {
    out += chunk;
  });
  child.stderr.on('data', (chunk) => {
    err += chunk;
  });
  const started = { child, stderr: () => err, stdout: () => out };
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error(`viewer did not print JSON within 8s\n${out}\n${err}`));
    }, 8000);
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const onExit = (code, signal) => {
      fail(new Error(`viewer exited early code=${code} signal=${signal}\n${out}\n${err}`));
    };
    child.once('exit', onExit);
    child.once('error', fail);
    const poll = () => {
      const nl = out.indexOf('\n');
      if (nl < 0 || settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener('exit', onExit);
      try {
        started.info = JSON.parse(out.slice(0, nl));
        resolve(started);
      } catch (error) {
        fail(error);
      }
    };
    child.stdout.on('data', poll);
  });
}

function runUntilExit(cwd, args, timeoutMs) {
  const child = spawn(process.execPath, [bin, ...args], {
    cwd,
    env: baseEnv(),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let out = '';
  let err = '';
  child.stdout.on('data', (chunk) => {
    out += chunk;
  });
  child.stderr.on('data', (chunk) => {
    err += chunk;
  });
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // Already gone.
      }
      resolve({ timedOut: true, code: null, signal: 'SIGKILL', out, err });
    }, timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ timedOut: false, code, signal, out, err });
    });
    child.once('error', (error) => {
      clearTimeout(timer);
      resolve({ timedOut: false, code: 1, signal: null, out, err: `${err}${error.message}` });
    });
  });
}

function httpCall(port, path, { host, hostname = '127.0.0.1', headers = {}, timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    const reqHeaders = { ...headers };
    if (host !== undefined) reqHeaders.Host = host;
    const req = http.request(
      {
        hostname,
        port,
        path,
        method: 'GET',
        headers: reqHeaders,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    const timer = setTimeout(() => {
      req.destroy(new Error(`timeout GET ${path}`));
    }, timeoutMs);
    req.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    req.on('close', () => clearTimeout(timer));
    req.end();
  });
}

function waitFor(fn, timeoutMs) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (fn()) {
        resolve();
        return;
      }
      if (Date.now() - start > timeoutMs) {
        reject(new Error('timed out'));
        return;
      }
      setTimeout(tick, 20);
    };
    tick();
  });
}

function otherPort(port) {
  return port === 65535 ? port - 1 : port + 1;
}

describe('v1.0.38 viewer allowed host', { concurrency: 1 }, () => {
  after(async () => {
    await Promise.all(children.map((child) => stopChild(child)));
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  it('accepts an allowed Host on a remote bind and rejects the others', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1038-lan-');
    const started = await startViewer(dir, ['--host', '0.0.0.0', '--allow-remote', '--allowed-host', 'lan.test']);
    try {
      await waitFor(() => /Allowed hosts: lan\.test/.test(started.stderr()), 2000);
      assert.match(started.stderr(), /warning: --allow-remote binds 0\.0\.0\.0/);
      assert.match(started.stderr(), /The viewer is meant for 127\.0\.0\.1/);
      const info = started.info;
      assert.equal(info.url, `http://0.0.0.0:${info.port}/`);
      assert.deepEqual(info.allowedHosts, ['lan.test']);
      assert.equal(typeof info.receiptCount, 'number');
      assert.equal(info.pid, started.child.pid);

      const allowed = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `lan.test:${info.port}`,
      });
      assert.equal(allowed.status, 200);
      assert.ok(Array.isArray(JSON.parse(allowed.body).receipts));

      const folded = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `LAN.TEST:${info.port}`,
      });
      assert.equal(folded.status, 200);

      const bound = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `0.0.0.0:${info.port}`,
      });
      assert.equal(bound.status, 200);

      const evil = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `evil.test:${info.port}`,
      });
      assert.equal(evil.status, 403);
      assert.equal(evil.body, '{"error":"forbidden"}\n');

      const wrongPort = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `lan.test:${otherPort(info.port)}`,
      });
      assert.equal(wrongPort.status, 403);
      assert.equal(wrongPort.body, '{"error":"forbidden"}\n');

      const bare = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: 'lan.test',
      });
      assert.equal(bare.status, 403);
    } finally {
      await stopChild(started.child);
    }
  });

  it('matches an explicit port and an IPv4 literal', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1038-ipv4-');
    const started = await startViewer(dir, [
      '--host',
      '0.0.0.0',
      '--allow-remote',
      '--allowed-host',
      'lan.test:9',
      '--allowed-host',
      '192.0.2.10',
    ]);
    try {
      const info = started.info;
      assert.notEqual(info.port, 9);
      assert.deepEqual(info.allowedHosts, ['lan.test:9', '192.0.2.10']);
      await waitFor(() => /Allowed hosts: lan\.test:9, 192\.0\.2\.10/.test(started.stderr()), 2000);

      const explicit = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: 'lan.test:9',
      });
      assert.equal(explicit.status, 200);
      const explicitWrong = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `lan.test:${info.port}`,
      });
      assert.equal(explicitWrong.status, 403);

      const ipv4 = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `192.0.2.10:${info.port}`,
      });
      assert.equal(ipv4.status, 200);
      const ipv4Wrong = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: '192.0.2.10:9',
      });
      assert.equal(ipv4Wrong.status, 403);
      const ipv4Bare = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: '192.0.2.10',
      });
      assert.equal(ipv4Bare.status, 403);
    } finally {
      await stopChild(started.child);
    }
  });

  it('normalizes bracketed and bare IPv6 to the same entry', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1038-ipv6-');
    const started = await startViewer(dir, [
      '--host',
      '0.0.0.0',
      '--allow-remote',
      '--allowed-host',
      '[fd00::1]',
      '--allowed-host',
      'fd00::1',
      '--allowed-host',
      'FD00::1',
    ]);
    try {
      const info = started.info;
      assert.deepEqual(info.allowedHosts, ['[fd00::1]']);
      const ok = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `[fd00::1]:${info.port}`,
      });
      assert.equal(ok.status, 200);
      const folded = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `[FD00::1]:${info.port}`,
      });
      assert.equal(folded.status, 200);
      const other = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `[fd00::2]:${info.port}`,
      });
      assert.equal(other.status, 403);
      assert.equal(other.body, '{"error":"forbidden"}\n');
    } finally {
      await stopChild(started.child);
    }
  });

  it('rejects wildcards, schemes, lists, paths, userinfo, and empty values before listen', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1038-bad-');
    const cases = [
      ['*', /wildcard/i],
      ['*.test', /wildcard/i],
      ['http://x', /scheme/i],
      ['a,b', /comma-separated/],
      ['x/y', /path/i],
      ['user@x', /userinfo/i],
    ];
    for (const [value, pattern] of cases) {
      const result = await runUntilExit(
        dir,
        ['view', '--host', '0.0.0.0', '--allow-remote', '--allowed-host', value, '--port', '0', '--json'],
        4000,
      );
      assert.equal(result.timedOut, false, value);
      assert.notEqual(result.code, 0, value);
      assert.equal(result.signal, null, value);
      const body = JSON.parse(result.out);
      assert.equal(body.ok, false, value);
      assert.equal(body.command, 'view');
      assert.match(body.error, pattern, `${value}: ${body.error}`);
      assert.equal(body.url, undefined, value);
      assert.equal(result.out.includes('"allowedHosts"'), false, value);
    }

    const bare = await runUntilExit(dir, ['view', '--allowed-host', '--port', '0', '--json'], 4000);
    assert.equal(bare.timedOut, false);
    assert.notEqual(bare.code, 0);
    assert.match(JSON.parse(bare.out).error, /requires a hostname/i);

    const empty = await runUntilExit(dir, ['view', '--allowed-host=', '--port', '0', '--json'], 4000);
    assert.equal(empty.timedOut, false);
    assert.notEqual(empty.code, 0);
    assert.match(JSON.parse(empty.out).error, /requires a hostname/i);
    assert.equal(/https?:\/\//.test(empty.out), false);
  });

  it('requires --allow-remote except for loopback names', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1038-loop-');
    const remote = await runUntilExit(dir, ['view', '--allowed-host', 'lan.test', '--port', '0', '--json'], 4000);
    assert.equal(remote.timedOut, false);
    assert.notEqual(remote.code, 0);
    assert.equal(remote.signal, null);
    const body = JSON.parse(remote.out);
    assert.equal(body.ok, false);
    assert.match(body.error, /--allow-remote/);
    assert.match(body.error, /lan\.test/);
    assert.equal(body.url, undefined);

    const started = await startViewer(dir, ['--allowed-host', 'localhost']);
    try {
      const info = started.info;
      assert.deepEqual(info.allowedHosts, ['localhost']);
      assert.equal(info.url, `http://127.0.0.1:${info.port}/`);
      assert.equal(/--allow-remote binds/.test(started.stderr()), false);
      const loop = await httpCall(info.port, '/api/receipts', { host: `localhost:${info.port}` });
      assert.equal(loop.status, 200);
      const bound = await httpCall(info.port, '/api/receipts', { host: `127.0.0.1:${info.port}` });
      assert.equal(bound.status, 200);
      const evil = await httpCall(info.port, '/api/receipts', { host: `evil.test:${info.port}` });
      assert.equal(evil.status, 403);
    } finally {
      await stopChild(started.child);
    }
  });

  it('rejects --allowed-host with --static', { timeout: 10000 }, async () => {
    const dir = fresh('agent-receipt-1038-static-');
    const out = join(dir, 'viewer-dist');
    const result = await runUntilExit(
      dir,
      ['view', '--static', out, '--allowed-host', 'lan.test', '--json'],
      4000,
    );
    assert.equal(result.timedOut, false);
    assert.notEqual(result.code, 0);
    assert.equal(result.signal, null);
    const body = JSON.parse(result.out);
    assert.equal(body.ok, false);
    assert.match(body.error, /--static/);
    assert.match(body.error, /--allowed-host/);
    assert.equal(existsSync(out), false);
  });

  it('does not trust X-Forwarded-Host', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1038-forwarded-');
    const started = await startViewer(dir, [
      '--host',
      '0.0.0.0',
      '--allow-remote',
      '--allowed-host',
      'lan.test',
    ]);
    try {
      const info = started.info;
      const forged = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `evil.test:${info.port}`,
        headers: {
          'X-Forwarded-Host': `lan.test:${info.port}`,
          Forwarded: 'host=lan.test',
          'X-Forwarded-Server': 'lan.test',
        },
      });
      assert.equal(forged.status, 403);
      assert.equal(forged.body, '{"error":"forbidden"}\n');
      const real = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `lan.test:${info.port}`,
        headers: { 'X-Forwarded-Host': `evil.test:${info.port}` },
      });
      assert.equal(real.status, 200);
    } finally {
      await stopChild(started.child);
    }
  });

  it('puts allowedHosts on the JSON line, empty by default', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1038-json-');
    const started = await startViewer(dir, []);
    try {
      assert.deepEqual(started.info.allowedHosts, []);
      assert.equal(started.info.url, `http://127.0.0.1:${started.info.port}/`);
      const line = started.stdout().slice(0, started.stdout().indexOf('\n'));
      assert.equal(Object.prototype.hasOwnProperty.call(JSON.parse(line), 'allowedHosts'), true);
    } finally {
      await stopChild(started.child);
    }
  });
});

describe('v1.0.38 allowed-host normalizer', () => {
  it('normalizes case and IPv6 brackets', () => {
    const bracket = normalizeAllowedHost('[fd00::1]');
    const bare = normalizeAllowedHost('fd00::1');
    const upper = normalizeAllowedHost('FD00::1');
    assert.equal(bracket.normalized, '[fd00::1]');
    assert.equal(bare.normalized, bracket.normalized);
    assert.equal(upper.normalized, bracket.normalized);
    assert.equal(bracket.port, undefined);
    assert.equal(bracket.loopback, false);
    assert.deepEqual(
      normalizeAllowedHosts(['[fd00::1]', 'fd00::1', 'FD00::1']).map((entry) => entry.normalized),
      ['[fd00::1]'],
    );

    const named = normalizeAllowedHost('Lan.Test');
    assert.equal(named.normalized, 'lan.test');
    assert.equal(named.host, 'lan.test');
    const withPort = normalizeAllowedHost('[fd00::1]:9');
    assert.equal(withPort.normalized, '[fd00::1]:9');
    assert.equal(withPort.port, 9);
    const ipv4 = normalizeAllowedHost('192.0.2.10');
    assert.equal(ipv4.normalized, '192.0.2.10');
    assert.equal(ipv4.port, undefined);

    const loop = normalizeAllowedHost('LocalHost');
    assert.equal(loop.normalized, 'localhost');
    assert.equal(loop.loopback, true);
    assert.equal(normalizeAllowedHost('127.0.0.1:4173').loopback, true);
    assert.equal(normalizeAllowedHost('[::1]').loopback, true);
    assert.equal(normalizeAllowedHost('[::1]').normalized, '[::1]');
  });

  it('rejects values that are not one exact host', () => {
    const cases = [
      ['*', /wildcard/i],
      ['*.test', /wildcard/i],
      ['*.x', /wildcard/i],
      ['http://x', /scheme/i],
      ['a,b', /comma-separated/],
      ['x/y', /path/i],
      ['user@x', /userinfo/i],
      ['', /requires a hostname/i],
      ['lan.test ', /whitespace/i],
      [' lan.test', /whitespace/i],
    ];
    for (const [value, pattern] of cases) {
      assert.throws(() => normalizeAllowedHost(value), pattern, value);
    }
    assert.throws(() => normalizeAllowedHosts(['lan.test', 'a,b']), /comma-separated/);
  });

  it('matches the bound host and the allowlist only', () => {
    const allowed = normalizeAllowedHosts(['lan.test', '192.0.2.10', 'lan.test:9', '[fd00::1]']);
    assert.equal(hostHeaderAllowed('0.0.0.0:4173', '0.0.0.0', 4173, allowed), true);
    assert.equal(hostHeaderAllowed('lan.test:4173', '0.0.0.0', 4173, allowed), true);
    assert.equal(hostHeaderAllowed('LAN.TEST:4173', '0.0.0.0', 4173, allowed), true);
    assert.equal(hostHeaderAllowed('192.0.2.10:4173', '0.0.0.0', 4173, allowed), true);
    assert.equal(hostHeaderAllowed('lan.test:9', '0.0.0.0', 4173, allowed), true);
    assert.equal(hostHeaderAllowed('[fd00::1]:4173', '0.0.0.0', 4173, allowed), true);
    assert.equal(hostHeaderAllowed('[FD00::1]:4173', '0.0.0.0', 4173, allowed), true);
    assert.equal(hostHeaderAllowed('lan.test:4174', '0.0.0.0', 4173, allowed), false);
    assert.equal(hostHeaderAllowed('lan.test', '0.0.0.0', 4173, allowed), false);
    assert.equal(hostHeaderAllowed('evil.test:4173', '0.0.0.0', 4173, allowed), false);
    assert.equal(hostHeaderAllowed('lan.test:4173 ', '0.0.0.0', 4173, allowed), false);
    assert.equal(hostHeaderAllowed(undefined, '0.0.0.0', 4173, allowed), false);
    assert.equal(hostHeaderAllowed('[::1]:4173', '::1', 4173, []), true);
    assert.equal(hostHeaderAllowed('::1:4173', '::1', 4173, []), false);
    assert.equal(hostHeaderAllowed('localhost:4173', '127.0.0.1', 4173, []), false);
    const loop = normalizeAllowedHosts(['localhost']);
    assert.equal(hostHeaderAllowed('localhost:4173', '127.0.0.1', 4173, loop), true);
    assert.equal(hostHeaderAllowed('127.0.0.1:4173', '127.0.0.1', 4173, loop), true);
  });

  it('keeps a comma inside one flag and joins repeats', () => {
    const repeated = parseArgs([
      'node',
      'bin',
      'view',
      '--allowed-host',
      '[fd00::1]',
      '--allowed-host',
      'fd00::1',
    ]);
    assert.equal(repeated.flags['allowed-host'], '[fd00::1]\u001ffd00::1');
    const parts = String(repeated.flags['allowed-host']).split('\u001f');
    assert.deepEqual(
      normalizeAllowedHosts(parts).map((entry) => entry.normalized),
      ['[fd00::1]'],
    );
    const listed = parseArgs(['node', 'bin', 'view', '--allowed-host', 'a,b']);
    assert.equal(listed.flags['allowed-host'], 'a,b');
    assert.throws(() => normalizeAllowedHost(String(listed.flags['allowed-host'])), /comma-separated/);
  });
});
