/**
 * v1.0.39 viewer hardening.
 * Live --allow-remote binds use port 0 and always kill the child.
 * The CSP checks parse the served page and the static bundle.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

function httpCall(port, path, { host, hostname = '127.0.0.1', timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (host !== undefined) headers.Host = host;
    const req = http.request(
      {
        hostname,
        port,
        path,
        method: 'GET',
        headers,
        family: hostname.includes(':') ? 6 : undefined,
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

function canListen(host) {
  return new Promise((resolve) => {
    const server = net.createServer();
    const timer = setTimeout(() => {
      server.close();
      resolve(false);
    }, 2000);
    server.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
    server.listen(0, host, () => {
      clearTimeout(timer);
      server.close(() => resolve(true));
    });
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

function sha256(text) {
  return createHash('sha256').update(text).digest('base64');
}

function directive(csp, name) {
  for (const part of csp.split(';')) {
    const trimmed = part.trim();
    if (trimmed === name || trimmed.startsWith(`${name} `)) return trimmed;
  }
  return '';
}

function assertPolicyTight(csp) {
  assert.equal(csp.includes("'unsafe-inline'"), false, csp);
  assert.equal(csp.includes("'unsafe-eval'"), false, csp);
  assert.equal(/https?:\/\//.test(csp), false, csp);
  assert.equal(/(?:^|[;\s])\*(?=$|[;\s])/.test(csp), false, csp);
}

function assertInlineCovered(html, policies) {
  assert.ok(policies.length > 0);
  for (const policy of policies) assertPolicyTight(policy);
  const blocks = [
    ...[...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].map((match) => ({
      kind: 'script-src',
      attrs: match[1],
      body: match[2],
    })),
    ...[...html.matchAll(/<style\b([^>]*)>([\s\S]*?)<\/style>/gi)].map((match) => ({
      kind: 'style-src',
      attrs: match[1],
      body: match[2],
    })),
  ];
  assert.ok(blocks.some((block) => block.kind === 'script-src'));
  assert.ok(blocks.some((block) => block.kind === 'style-src'));
  for (const block of blocks) {
    assert.equal(/\ssrc\s*=/i.test(block.attrs), false, block.attrs);
    const hash = `'sha256-${sha256(block.body)}'`;
    const nonceMatch = /(?:^|\s)nonce\s*=\s*"([^"]*)"/i.exec(block.attrs);
    const nonce = nonceMatch ? `'nonce-${nonceMatch[1]}'` : '';
    for (const policy of policies) {
      const src = directive(policy, block.kind) || directive(policy, 'default-src');
      const covered = src.includes(hash) || (nonce !== '' && src.includes(nonce));
      assert.equal(covered, true, `${block.kind} ${hash} missing from ${policy}`);
    }
  }
}

function assertNoInlineHandlers(html) {
  for (const match of html.matchAll(/<[^>]*>/g)) {
    const tag = match[0];
    assert.equal(/\son[a-z][\w:-]*\s*=/i.test(tag), false, tag);
    assert.equal(/\sstyle\s*=/i.test(tag), false, tag);
  }
}

function assertResourceUrl(value, pageUrl) {
  const url = value.trim();
  if (url === '' || url.startsWith('#')) return;
  if (url.startsWith('data:')) return;
  if (url.startsWith('//')) assert.fail(`protocol-relative resource ${url}`);
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
    const parsed = new URL(url);
    if (!pageUrl) assert.fail(`absolute resource in offline bundle: ${url}`);
    assert.equal(parsed.origin, new URL(pageUrl).origin, url);
    return;
  }
}

function assertResourceUrls(html, pageUrl) {
  const attr = /\s(?:href|src|action|formaction|poster|cite|background|srcset|data)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
  for (const match of html.matchAll(attr)) {
    const value = match[1] ?? match[2] ?? match[3] ?? '';
    const name = /(?:href|src|action|formaction|poster|cite|background|srcset|data)/i.exec(match[0]);
    if (name && name[0].toLowerCase() === 'srcset') {
      for (const part of value.split(',')) {
        const candidate = part.trim().split(/\s+/)[0] || '';
        if (candidate) assertResourceUrl(candidate, pageUrl);
      }
    } else {
      assertResourceUrl(value, pageUrl);
    }
  }
  for (const match of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
    assert.equal(/@import/i.test(match[1]), false);
    for (const urlMatch of match[1].matchAll(/url\s*\(\s*(['"]?)([^'")]+)\1\s*\)/gi)) {
      assertResourceUrl(urlMatch[2], pageUrl);
    }
  }
}

function metaPolicy(html) {
  const match = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/);
  assert.ok(match, 'meta CSP missing');
  return match[1];
}

describe('v1.0.39 viewer hardening', { concurrency: 1 }, () => {
  after(async () => {
    await Promise.all(children.map((child) => stopChild(child)));
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  it('binds 0.0.0.0 with --allow-remote and still checks Host', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1037-remote-');
    const started = await startViewer(dir, ['--host', '0.0.0.0', '--allow-remote']);
    try {
      await waitFor(() => /warning: --allow-remote binds 0\.0\.0\.0/.test(started.stderr()), 2000);
      assert.match(started.stderr(), /The viewer is meant for 127\.0\.0\.1/);
      assert.equal(/warning:/.test(started.stdout()), false);
      const info = started.info;
      assert.equal(info.url, `http://0.0.0.0:${info.port}/`);
      assert.equal(info.port > 0, true);
      assert.equal(typeof info.receiptCount, 'number');
      assert.equal(info.pid, started.child.pid);
      assert.equal(started.stdout().includes('"url"'), true);

      const listed = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `0.0.0.0:${info.port}`,
      });
      assert.equal(listed.status, 200);
      assert.match(listed.headers['content-type'], /application\/json/);
      const body = JSON.parse(listed.body);
      assert.ok(Array.isArray(body.receipts));

      const forged = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: 'evil.example',
      });
      assert.equal(forged.status, 403);
      assert.equal(forged.body, '{"error":"forbidden"}\n');
      const forgedPort = await httpCall(info.port, '/api/receipts', {
        hostname: '127.0.0.1',
        host: `evil.example:${info.port}`,
      });
      assert.equal(forgedPort.status, 403);
      assert.equal(forgedPort.body, '{"error":"forbidden"}\n');
    } finally {
      const stopped = await stopChild(started.child);
      assert.equal(stopped.forced, false);
      assert.equal(stopped.signal, null);
      assert.equal(stopped.code, 0);
    }
  });

  it('refuses 0.0.0.0 without --allow-remote and does not listen', { timeout: 10000 }, async () => {
    const dir = fresh('agent-receipt-1037-refuse-');
    const result = await runUntilExit(dir, ['view', '--host', '0.0.0.0', '--port', '0'], 4000);
    assert.equal(result.timedOut, false);
    assert.notEqual(result.code, 0);
    assert.equal(result.signal, null);
    assert.match(result.err, /Refusing to bind 0\.0\.0\.0/);
    assert.match(result.err, /--allow-remote/);
    assert.equal(result.out.includes('"url"'), false);
    assert.equal(/https?:\/\//.test(result.out), false);
  });

  it('treats localhost as loopback', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1037-localhost-');
    const started = await startViewer(dir, ['--host', 'localhost']);
    try {
      const info = started.info;
      assert.equal(info.url, `http://localhost:${info.port}/`);
      assert.equal(/--allow-remote binds/.test(started.stderr()), false);
      const listed = await httpCall(info.port, '/api/receipts', {
        hostname: 'localhost',
        host: `localhost:${info.port}`,
      });
      assert.equal(listed.status, 200);
      assert.ok(Array.isArray(JSON.parse(listed.body).receipts));
    } finally {
      await stopChild(started.child);
    }
  });

  it('treats ::1 as loopback when IPv6 exists', { timeout: 20000 }, async (t) => {
    if (!(await canListen('::1'))) {
      t.skip('this host has no IPv6 loopback');
      return;
    }
    const dir = fresh('agent-receipt-1037-ipv6-');
    let started;
    try {
      started = await startViewer(dir, ['--host', '::1']);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (/EADDRNOTAVAIL|EAFNOSUPPORT|ENETUNREACH|EHOSTUNREACH/i.test(message)) {
        t.skip('this host has no IPv6 loopback');
        return;
      }
      throw error;
    }
    try {
      const info = started.info;
      assert.equal(info.url, `http://[::1]:${info.port}/`);
      assert.equal(/--allow-remote binds/.test(started.stderr()), false);
      const listed = await httpCall(info.port, '/api/receipts', {
        hostname: '::1',
        host: `[::1]:${info.port}`,
      });
      assert.equal(listed.status, 200);
      assert.ok(Array.isArray(JSON.parse(listed.body).receipts));
    } finally {
      await stopChild(started.child);
    }
  });

  it('covers inline script and style in the served page and the static bundle', { timeout: 20000 }, async () => {
    const dir = fresh('agent-receipt-1037-csp-');
    const started = await startViewer(dir, ['--host', '127.0.0.1']);
    try {
      const info = started.info;
      const index = await httpCall(info.port, '/', { host: `127.0.0.1:${info.port}` });
      assert.equal(index.status, 200);
      const header = index.headers['content-security-policy'] || '';
      const meta = metaPolicy(index.body);
      assert.match(header, /frame-ancestors 'none'/);
      assert.equal(meta.includes('frame-ancestors'), false);
      assert.match(header, /connect-src 'self'/);
      assert.match(meta, /connect-src 'self'/);
      assert.match(header, /img-src data:/);
      assert.match(meta, /img-src data:/);
      assert.match(header, /base-uri 'none'/);
      assert.match(header, /form-action 'none'/);
      const headerRest = header
        .split(';')
        .map((part) => part.trim())
        .filter((part) => part && !part.startsWith('frame-ancestors'))
        .join('; ');
      assert.equal(headerRest, meta);
      assertInlineCovered(index.body, [meta, header]);
      assertNoInlineHandlers(index.body);
      assertResourceUrls(index.body, info.url);
      assert.match(index.body, /<link rel="icon" href="data:,">/);

      const api = await httpCall(info.port, '/api/receipts');
      assert.equal(api.status, 200);
      const apiCsp = api.headers['content-security-policy'] || '';
      assert.match(apiCsp, /script-src 'none'/);
      assert.match(apiCsp, /img-src 'none'/);
      assert.equal(apiCsp.includes('data:'), false);
      assertPolicyTight(apiCsp);
    } finally {
      await stopChild(started.child);
    }

    const out = join(dir, 'viewer-dist');
    const written = spawnSync(process.execPath, [bin, 'view', '--static', out, '--json'], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 15000,
      env: baseEnv(),
    });
    assert.equal(written.status, 0, `${written.stdout || ''}${written.stderr || ''}${written.error || ''}`);
    const html = readFileSync(join(out, 'index.html'), 'utf8');
    const staticMeta = metaPolicy(html);
    assert.match(staticMeta, /connect-src 'none'/);
    assert.equal(staticMeta.includes('frame-ancestors'), false);
    assert.match(staticMeta, /img-src data:/);
    assert.match(staticMeta, /base-uri 'none'/);
    assert.match(staticMeta, /form-action 'none'/);
    assertInlineCovered(html, [staticMeta]);
    assertNoInlineHandlers(html);
    assertResourceUrls(html, null);
    assert.match(html, /<link rel="icon" href="data:,">/);
    assert.equal(html.includes('http://'), false);
    assert.equal(html.includes('https://'), false);
  });
});
