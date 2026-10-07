import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const SECRET = 'AKIAIOSFODNN7EXAMPLE';
const REDACTED = 'AKIA[REDACTED]';
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

function git(cwd, args) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'CI',
      GIT_AUTHOR_EMAIL: 'ci@example.com',
      GIT_COMMITTER_NAME: 'CI',
      GIT_COMMITTER_EMAIL: 'ci@example.com',
    },
  });
}

function fresh(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

function repo(prefix = 'agent-receipt-1036-') {
  const dir = fresh(prefix);
  git(dir, ['init']);
  git(dir, ['config', 'user.email', 'ci@example.com']);
  git(dir, ['config', 'user.name', 'CI']);
  writeFileSync(join(dir, 'README.md'), '# viewer\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'init']);
  return dir;
}

function commitFile(dir, name, body, message) {
  writeFileSync(join(dir, name), body);
  git(dir, ['add', name]);
  git(dir, ['commit', '-m', message]);
}

function cli(cwd, args, extraEnv) {
  const result = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 30000,
    env: baseEnv(extraEnv),
  });
  return {
    code: result.status === null ? 1 : result.status,
    out: result.stdout || '',
    err: result.stderr || '',
    signal: result.signal,
  };
}

function jsonOf(result) {
  return JSON.parse(result.out);
}

function field(markdown, label) {
  const prefix = `- **${label}**:`;
  for (const line of markdown.split('\n')) {
    if (!line.startsWith(prefix)) continue;
    const value = line.slice(prefix.length).trim().replace(/^`|`$/g, '');
    return value || null;
  }
  return null;
}

function stopChild(child) {
  return new Promise((resolve) => {
    if (!child || child.exitCode !== null || child.signalCode) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // The process is already gone.
      }
      resolve();
    }, 5000);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    try {
      child.kill('SIGTERM');
    } catch {
      clearTimeout(timer);
      resolve();
    }
  });
}

function startViewer(cwd, args = [], extraEnv) {
  const child = spawn(
    process.execPath,
    [bin, 'view', '--host', '127.0.0.1', '--port', '0', '--json', ...args],
    {
      cwd,
      env: baseEnv(extraEnv),
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  children.push(child);
  return new Promise((resolve, reject) => {
    let out = '';
    let err = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`viewer did not print JSON\n${out}\n${err}`));
    }, 20000);
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
    child.stderr.on('data', (chunk) => {
      err += chunk;
    });
    child.stdout.on('data', (chunk) => {
      out += chunk;
      const nl = out.indexOf('\n');
      if (nl < 0 || settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener('exit', onExit);
      try {
        resolve({ child, info: JSON.parse(out.slice(0, nl)), stderr: () => err });
      } catch (error) {
        reject(error);
      }
    });
    child.once('error', fail);
  });
}

async function withViewer(cwd, args, fn, extraEnv) {
  const started = await startViewer(cwd, args, extraEnv);
  try {
    await fn(started);
  } finally {
    await stopChild(started.child);
  }
}

function httpCall(port, path, { method = 'GET', host } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (host !== undefined) headers.Host = host;
    const req = http.request(
      { hostname: '127.0.0.1', port, path, method, headers },
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
    req.setTimeout(5000, () => req.destroy(new Error(`timeout ${method} ${path}`)));
    req.on('error', reject);
    req.end();
  });
}

function assertSecurity(headers, { connectSelf }) {
  const csp = headers['content-security-policy'] || '';
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  if (connectSelf) {
    assert.match(csp, /script-src 'sha256-[A-Za-z0-9+/=]+'/);
    assert.match(csp, /style-src 'sha256-[A-Za-z0-9+/=]+'/);
    assert.match(csp, /connect-src 'self'/);
  } else {
    assert.match(csp, /script-src 'none'/);
    assert.match(csp, /style-src 'none'/);
  }
  assert.equal(headers['x-content-type-options'], 'nosniff');
  assert.equal(headers['referrer-policy'], 'no-referrer');
  assert.equal(headers['x-frame-options'], 'DENY');
  assert.equal(headers['cache-control'], 'no-store');
}

function assertNoHttpAssets(text) {
  assert.equal(/<script\s+src/i.test(text), false);
  const links = text.match(/<link\b[^>]*>/gi) || [];
  for (const link of links) {
    assert.equal(link, '<link rel="icon" href="data:,">');
  }
  assert.equal(/@import/i.test(text), false);
  assert.equal(/url\s*\(/i.test(text), false);
  assert.equal(/https?:\/\//i.test(text), false);
}

function toolReceipt(command) {
  return `# Receipt

## Session

- **Version**: 1.0.39
- **Agent**: ci

## Tool calls

- **Adapter**: shell
- \`shell\` \u2014 exit 0 \u2014 \`${command}\`
`;
}

function actionScript() {
  const text = readFileSync(join(root, 'action.yml'), 'utf8');
  const lines = text.split('\n');
  const start = lines.findIndex((line) => line === '      run: |');
  assert.ok(start >= 0, 'action.yml run block missing');
  const body = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('        ')) body.push(line.slice(8));
    else if (line.trim() === '') body.push('');
    else break;
  }
  return body.join('\n');
}

function linkedRepo() {
  const dir = repo('agent-receipt-1036-link-');
  commitFile(dir, 'package-lock.json', '{}\n', 'lock');
  const transcript = join(dir, 'session.jsonl');
  writeFileSync(
    transcript,
    `${JSON.stringify({
      type: 'assistant',
      message: {
        content: [{ type: 'tool_use', id: 'tu1', name: 'Bash', input: { command: 'git status' } }],
      },
    })}\n${JSON.stringify({
      type: 'user',
      message: { content: [{ type: 'tool_result', tool_use_id: 'tu1', is_error: false }] },
    })}\n`,
  );
  const parentRun = cli(dir, [
    'capture',
    '--json',
    '--commits',
    '1',
    '--session',
    'viewer-sess',
    '--agent',
    'parent',
    '--host',
    'laptop',
    '--message',
    `parent ${SECRET}`,
    '--policy-pack',
    'builtin:supply-chain',
    '--adapter',
    'claude-code',
    '--transcript',
    transcript,
  ]);
  assert.equal(parentRun.code, 2, parentRun.out + parentRun.err);
  const parentBody = jsonOf(parentRun);
  assert.equal(parentBody.policyDenied, true);
  assert.ok(parentBody.policyPackHits.some((hit) => hit.rule === 'lockfiles' && hit.action === 'deny'));
  const parentMd = readFileSync(parentBody.path, 'utf8');
  assert.match(parentMd, new RegExp(SECRET));
  const parentId = field(parentMd, 'Id');
  assert.match(parentId, /^r-[0-9a-f]{16}$/);

  commitFile(dir, 'child.txt', 'child\n', 'child');
  const childRun = cli(dir, [
    'capture',
    '--json',
    '--commits',
    '1',
    '--session',
    'viewer-sess',
    '--parent',
    parentId,
    '--agent',
    'child',
    '--host',
    'runner',
    '--message',
    'child note',
  ]);
  assert.equal(childRun.code, 0, childRun.out + childRun.err);
  const childBody = jsonOf(childRun);
  assert.equal(childBody.exitCode, 0);
  assert.equal('policyPacks' in childBody, false);
  const childMd = readFileSync(childBody.path, 'utf8');
  const childId = field(childMd, 'Id');
  assert.match(childId, /^r-[0-9a-f]{16}$/);
  assert.equal(field(childMd, 'Parent'), parentId);
  return { dir, parentId, childId, childPath: childBody.path };
}

describe('v1.0.39 local viewer', { concurrency: 1 }, () => {
  after(async () => {
    await Promise.all(children.map((child) => stopChild(child)));
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  it('serves the index, receipt detail, and session tree', async () => {
    const { dir, parentId, childId } = linkedRepo();
    const openerDir = join(dir, 'open-bin');
    const opened = join(dir, 'opened-url');
    mkdirSync(openerDir);
    writeFileSync(
      join(openerDir, 'xdg-open'),
      `#!/bin/sh\nprintf '%s\\n' "$1" > ${JSON.stringify(opened)}\n`,
    );
    chmodSync(join(openerDir, 'xdg-open'), 0o755);

    await withViewer(
      dir,
      ['--open'],
      async ({ child, info }) => {
        assert.equal(typeof info.port, 'number');
        assert.ok(info.port > 0);
        assert.equal(info.url, `http://127.0.0.1:${info.port}/`);
        assert.equal(info.receiptCount, 2);
        assert.equal(info.pid, child.pid);
        const started = Date.now();
        while (!existsSync(opened)) {
          if (Date.now() - started > 2000) throw new Error('xdg-open was not called');
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        assert.equal(readFileSync(opened, 'utf8').trim(), info.url);

        const index = await httpCall(info.port, '/');
        assert.equal(index.status, 200);
        assert.match(index.headers['content-type'], /text\/html/);
        assertSecurity(index.headers, { connectSelf: true });
        assert.match(index.body, /<meta http-equiv="Content-Security-Policy"/);
        assert.match(index.body, /default-src 'none'/);
        assert.match(index.body, /id="q"/);
        assert.match(index.body, /id="agent"/);
        assert.match(index.body, /id="risk"/);
        assert.match(index.body, /id="signed"/);
        assert.match(index.body, /id="failed"/);
        assert.match(index.body, /id="viewer-data"/);
        assert.match(index.body, /<style>/);
        assert.match(index.body, /<script>/);
        assert.equal(index.body.includes('innerHTML'), false);
        assert.equal(index.body.includes('eval('), false);
        assertNoHttpAssets(index.body);
        assert.equal(index.body.includes(SECRET), false);

        const listed = await httpCall(info.port, '/api/receipts');
        assert.equal(listed.status, 200);
        assert.match(listed.headers['content-type'], /application\/json/);
        assertSecurity(listed.headers, { connectSelf: false });
        assert.equal(listed.body.includes(SECRET), false);
        assert.match(listed.body, /AKIA\[REDACTED\]/);
        const list = JSON.parse(listed.body);
        assert.equal(list.receipts.length, 2);
        const parent = list.receipts.find((row) => row.id === parentId);
        const childRow = list.receipts.find((row) => row.id === childId);
        assert.ok(parent);
        assert.ok(childRow);
        assert.equal('commands' in parent, false);
        assert.equal(parent.agent, 'parent');
        assert.equal(parent.host, 'laptop');
        assert.equal(parent.adapter, 'claude-code');
        assert.equal(parent.signed, false);
        assert.equal(parent.verify.status, 'OK');
        assert.equal(parent.verify.reason, '');
        assert.equal(parent.exitCode, 0);
        assert.equal(parent.failed, true);
        assert.equal(parent.session, 'viewer-sess');
        assert.ok(parent.policyHits.some((hit) => hit.rule === 'lockfiles' && hit.action === 'deny'));
        assert.match(parent.message, /AKIA\[REDACTED\]/);
        assert.equal(childRow.agent, 'child');
        assert.equal(childRow.host, 'runner');
        assert.equal(childRow.parent, parentId);
        assert.equal(childRow.verify.status, 'OK');
        assert.equal(childRow.failed, false);
        assert.equal(childRow.exitCode, 0);
        assert.deepEqual(childRow.policyHits, []);

        const detail = await httpCall(info.port, `/api/receipts/${parentId}`);
        assert.equal(detail.status, 200);
        assert.equal(detail.body.includes(SECRET), false);
        const full = JSON.parse(detail.body).receipt;
        assert.equal(full.id, parentId);
        assert.ok(full.commands.some((line) => line.includes('lock')));
        assert.ok(full.files.some((file) => file.path === 'package-lock.json'));
        assert.ok(full.toolCalls.some((call) => call.tool === 'Bash' && call.command === 'git status' && call.exit === 0));
        assert.equal(full.gate.failed, true);
        assert.equal(full.gate.exitCode, 0);
        assert.equal(full.gate.failedOn, true);
        assert.equal(full.signature.present, false);
        assert.equal(full.keyless.present, false);
        assert.equal(full.attestation.present, false);
        assert.equal(full.hashChain.chainOk, true);
        assert.equal(full.hashChain.matched, true);
        assert.equal(typeof full.hashChain.position, 'number');
        assert.ok(full.hashChain.position >= 1);
        assert.match(full.sha256, /^[0-9a-f]{64}$/);

        const byHash = await httpCall(info.port, `/api/receipts/${full.sha256}`);
        assert.equal(byHash.status, 200);
        assert.equal(JSON.parse(byHash.body).receipt.id, parentId);

        const verify = await httpCall(info.port, `/api/verify/${parentId}`);
        assert.equal(verify.status, 200);
        const verdict = JSON.parse(verify.body);
        assert.equal(verdict.id, parentId);
        assert.equal(verdict.status, 'OK');
        assert.equal(verdict.ok, true);
        assert.equal(verdict.reason, '');
        assert.equal(verdict.exitCode, 0);
        assert.equal(verdict.sha256, full.sha256);

        const sessions = await httpCall(info.port, '/api/sessions');
        assert.equal(sessions.status, 200);
        const tree = JSON.parse(sessions.body);
        assert.equal(tree.sessions.length, 1);
        assert.equal(tree.sessions[0].id, 'viewer-sess');
        assert.deepEqual(tree.sessions[0].hosts, ['laptop', 'runner']);
        assert.equal(tree.sessions[0].roots.length, 1);
        assert.equal(tree.sessions[0].roots[0].id, parentId);
        assert.equal(tree.sessions[0].roots[0].host, 'laptop');
        assert.equal(tree.sessions[0].roots[0].children.length, 1);
        assert.equal(tree.sessions[0].roots[0].children[0].id, childId);
        assert.equal(tree.sessions[0].roots[0].children[0].host, 'runner');
        assert.equal(tree.sessions[0].roots[0].children[0].parent, parentId);

        const queried = await httpCall(info.port, '/api/receipts?unused=1');
        assert.equal(queried.status, 200);
        assert.equal(JSON.parse(queried.body).receipts.length, 2);

        const missing = await httpCall(info.port, '/api/receipts/not-a-real-id');
        assert.equal(missing.status, 404);
        assert.equal(missing.body, '{"error":"not found"}\n');
        const unknown = await httpCall(info.port, '/no-such-page');
        assert.equal(unknown.status, 404);
        assert.equal(unknown.body, '{"error":"not found"}\n');

        for (const path of [
          '/api/receipts/../../etc/passwd',
          '/api/receipts/%2e%2e/%2e%2e/secret',
          '/api/receipts/%252e%252e',
          '/api/receipts//etc/passwd',
          '/api/receipts/%2Fetc%2Fpasswd',
          '/api/receipts/..\\secret',
        ]) {
          const blocked = await httpCall(info.port, path);
          assert.equal(blocked.status, 403, path);
          assert.equal(blocked.body, '{"error":"forbidden"}\n');
          assert.equal(blocked.body.includes('passwd'), false);
          assert.equal(blocked.body.includes('secret'), false);
          assert.equal(blocked.body.includes('..'), false);
        }

        for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
          const rejected = await httpCall(info.port, '/api/receipts', { method });
          assert.equal(rejected.status, 405, method);
          assert.equal(rejected.headers.allow, 'GET');
          assert.equal(rejected.body, '{"error":"method not allowed"}\n');
        }
        const head = await httpCall(info.port, '/api/receipts', { method: 'HEAD' });
        assert.equal(head.status, 405);
        assert.equal(head.headers.allow, 'GET');

        const badHost = await httpCall(info.port, '/api/receipts', { host: 'evil.example' });
        assert.equal(badHost.status, 403);
        assert.equal(badHost.body, '{"error":"forbidden"}\n');
        const bareHost = await httpCall(info.port, '/', { host: '127.0.0.1' });
        assert.equal(bareHost.status, 403);
        const wrongPort = await httpCall(info.port, '/', { host: `127.0.0.1:${info.port + 1}` });
        assert.equal(wrongPort.status, 403);
        const postBadHost = await httpCall(info.port, '/api/receipts', {
          method: 'POST',
          host: 'evil.example',
        });
        assert.equal(postBadHost.status, 403);

        const served = [index.body, listed.body, detail.body, verify.body, sessions.body].join('\n');
        assert.equal(served.includes(SECRET), false);
        assert.match(served, /AKIA\[REDACTED\]/);
      },
      { PATH: `${openerDir}:${process.env.PATH}` },
    );

    const outA = join(dir, 'static-a');
    const outB = join(dir, 'static-b');
    const first = cli(dir, ['view', '--static', outA, '--json']);
    const second = cli(dir, ['view', '--static', outB, '--json']);
    assert.equal(first.code, 0, first.out + first.err);
    assert.equal(second.code, 0, second.out + second.err);
    const staticBody = jsonOf(first);
    assert.equal(staticBody.command, 'view');
    assert.equal(staticBody.ok, true);
    assert.equal(staticBody.static, true);
    assert.equal(staticBody.out, outA);
    assert.equal(staticBody.receiptCount, 2);
    assert.deepEqual(readdirSync(outA).sort(), ['data.json', 'index.html']);
    const htmlA = readFileSync(join(outA, 'index.html'), 'utf8');
    const jsonA = readFileSync(join(outA, 'data.json'), 'utf8');
    const htmlB = readFileSync(join(outB, 'index.html'), 'utf8');
    const jsonB = readFileSync(join(outB, 'data.json'), 'utf8');
    assert.equal(htmlA, htmlB);
    assert.equal(jsonA, jsonB);
    assertNoHttpAssets(htmlA);
    assertNoHttpAssets(jsonA);
    assert.match(htmlA, /id="viewer-data"/);
    assert.match(htmlA, /connect-src 'none'/);
    assert.equal(htmlA.includes('innerHTML'), false);
    assert.equal(htmlA.includes('eval('), false);
    const snapshot = JSON.parse(jsonA);
    assert.equal(snapshot.receipts.length, 2);
    assert.equal(snapshot.sessions[0].id, 'viewer-sess');
    assert.equal(htmlA.includes(SECRET), false);
    assert.equal(jsonA.includes(SECRET), false);
    assert.match(htmlA, /AKIA\[REDACTED\]/);
    assert.match(jsonA, /AKIA\[REDACTED\]/);
    assert.match(htmlA, /<pre id="viewer-data" hidden>/);
  });

  it('refuses a non-loopback host and rejects view misuse', async () => {
    const dir = repo('agent-receipt-1036-usage-');
    const remote = cli(dir, ['view', '--host', '0.0.0.0', '--port', '0', '--json']);
    assert.equal(remote.code, 1, remote.out + remote.err);
    assert.equal(remote.signal, null);
    const remoteBody = jsonOf(remote);
    assert.equal(remoteBody.ok, false);
    assert.equal(remoteBody.command, 'view');
    assert.match(remoteBody.error, /Refusing to bind 0\.0\.0\.0/);
    assert.match(remoteBody.error, /--allow-remote/);

    const human = cli(dir, ['view', '--host', '192.0.2.1', '--port', '9']);
    assert.equal(human.code, 1);
    assert.match(human.err, /Refusing to bind 192\.0\.2\.1/);
    assert.match(human.err, /--allow-remote/);

    const noRedact = cli(dir, ['view', '--no-redact', '--json']);
    assert.equal(noRedact.code, 1);
    assert.match(jsonOf(noRedact).error, /view always redacts/);
    const humanRedact = cli(dir, ['view', '--no-redact']);
    assert.equal(humanRedact.code, 1);
    assert.match(humanRedact.err, /view always redacts\. There is no --no-redact\./);

    const positional = cli(dir, ['view', 'receipt.md']);
    assert.equal(positional.code, 1);
    assert.match(positional.err, /view does not take a receipt path/);
    const unknown = cli(dir, ['view', '--nope']);
    assert.equal(unknown.code, 1);
    assert.match(unknown.err, /Unknown flag: --nope/);
    const bareStatic = cli(dir, ['view', '--static']);
    assert.equal(bareStatic.code, 1);
    assert.match(bareStatic.err, /view --static requires an output directory/);
    const listenStatic = cli(dir, ['view', '--static', join(dir, 'bundle'), '--port', '0', '--json']);
    assert.equal(listenStatic.code, 1);
    assert.match(jsonOf(listenStatic).error, /view --static does not listen/);

    const emptyOut = join(dir, 'empty-static');
    const empty = cli(dir, ['view', '--static', emptyOut, '--json']);
    assert.equal(empty.code, 0, empty.out + empty.err);
    assert.equal(jsonOf(empty).receiptCount, 0);
    const emptyHtml = readFileSync(join(emptyOut, 'index.html'), 'utf8');
    assertNoHttpAssets(emptyHtml);
    assert.match(emptyHtml, /<pre id="viewer-data" hidden>/);
    assert.match(emptyHtml, /&quot;receipts&quot;: \[\]/);
    assert.deepEqual(JSON.parse(readFileSync(join(emptyOut, 'data.json'), 'utf8')), {
      receipts: [],
      sessions: [],
    });

    await withViewer(dir, [], async ({ info }) => {
      assert.equal(info.receiptCount, 0);
      assert.equal(info.url, `http://127.0.0.1:${info.port}/`);
      assert.equal(typeof info.pid, 'number');
      const page = await httpCall(info.port, '/index.html');
      assert.equal(page.status, 200);
      assert.equal(page.body.includes(SECRET), false);
      const none = await httpCall(info.port, '/api/receipts');
      assert.deepEqual(JSON.parse(none.body), { receipts: [] });
    });
  });

  it('shows a tampered receipt as FAILED', async () => {
    const dir = repo('agent-receipt-1036-tamper-');
    const captured = cli(dir, ['capture', '--json', '--message', 'clean-body-token']);
    assert.equal(captured.code, 0, captured.out + captured.err);
    const path = jsonOf(captured).path;
    const original = readFileSync(path, 'utf8');
    const marker = '<!-- agent-receipt-sha256:';
    const at = original.indexOf(marker);
    assert.ok(at > 0);
    const tampered = original.slice(0, at).replace('clean-body-token', 'tampered-body-token') + original.slice(at);
    writeFileSync(path, tampered);
    const verified = cli(dir, ['verify', path]);
    assert.equal(verified.code, 2);

    const out = join(dir, 'tamper-static');
    const written = cli(dir, ['view', '--static', out, '--json']);
    assert.equal(written.code, 0, written.out + written.err);
    const snapshot = JSON.parse(readFileSync(join(out, 'data.json'), 'utf8'));
    assert.equal(snapshot.receipts.length, 1);
    assert.equal(snapshot.receipts[0].verify.status, 'FAILED');
    assert.equal(snapshot.receipts[0].exitCode, 2);
    assert.equal(snapshot.receipts[0].failed, true);
    assert.equal(JSON.stringify(snapshot).includes('"status":"OK"'), false);

    await withViewer(dir, [], async ({ info }) => {
      assert.equal(info.receiptCount, 1);
      const listed = await httpCall(info.port, '/api/receipts');
      const sessions = await httpCall(info.port, '/api/sessions');
      const id = JSON.parse(listed.body).receipts[0].id;
      const detail = await httpCall(info.port, `/api/receipts/${id}`);
      const verdict = await httpCall(info.port, `/api/verify/${id}`);
      for (const body of [listed.body, detail.body, sessions.body, verdict.body]) {
        assert.equal(JSON.stringify(JSON.parse(body)).includes('"status":"OK"'), false);
      }
      assert.match(verdict.body, /"status": "FAILED"/);
      const body = JSON.parse(verdict.body);
      assert.equal(body.status, 'FAILED');
      assert.equal(body.ok, false);
      assert.equal(body.exitCode, 2);
      assert.notEqual(body.reason, 'OK');
      assert.match(body.reason, /hash|match|integrity|tamper/i);
    });
  });

  it('honors --require-sig and --trusted-key', () => {
    const dir = repo('agent-receipt-1036-sig-');
    const captured = cli(dir, ['capture', '--json', '--session', 'sig-sess', '--message', 'unsigned']);
    assert.equal(captured.code, 0, captured.out + captured.err);
    const unsignedOut = join(dir, 'unsigned-static');
    const unsigned = cli(dir, ['view', '--static', unsignedOut, '--require-sig', '--json']);
    assert.equal(unsigned.code, 0, unsigned.out + unsigned.err);
    const unsignedSnap = JSON.parse(readFileSync(join(unsignedOut, 'data.json'), 'utf8'));
    assert.equal(unsignedSnap.receipts.length, 1);
    assert.equal(unsignedSnap.receipts[0].verify.status, 'FAILED');
    assert.equal(unsignedSnap.receipts[0].signed, false);
    assert.match(unsignedSnap.receipts[0].verify.reason, /signature required: signature absent/);
    assert.equal(JSON.stringify(unsignedSnap).includes('"status":"OK"'), false);

    const made = jsonOf(cli(dir, ['keygen', '--json']));
    assert.equal(made.ok, true);
    assert.equal(made.fingerprint.length, 64);
    commitFile(dir, 'signed.txt', 'signed\n', 'signed');
    const signedRun = cli(dir, [
      'capture',
      '--json',
      '--sign',
      '--commits',
      '1',
      '--session',
      'sig-sess',
      '--message',
      'signed',
    ]);
    assert.equal(signedRun.code, 0, signedRun.out + signedRun.err);
    const signedPath = jsonOf(signedRun).path;
    const signedId = field(readFileSync(signedPath, 'utf8'), 'Id');

    const okOut = join(dir, 'signed-static');
    const ok = cli(dir, ['view', '--static', okOut, '--require-sig', '--receipts', dirname(signedPath), '--json']);
    assert.equal(ok.code, 0, ok.out + ok.err);
    const okSnap = JSON.parse(readFileSync(join(okOut, 'data.json'), 'utf8'));
    const signedRow = okSnap.receipts.find((row) => row.id === signedId);
    assert.ok(signedRow);
    assert.equal(signedRow.verify.status, 'OK');
    assert.equal(signedRow.signed, true);
    assert.equal(signedRow.signature.ok, true);
    assert.equal(signedRow.signature.fingerprint, made.fingerprint);

    const wrong = 'ab'.repeat(32);
    assert.notEqual(wrong, made.fingerprint);
    const badOut = join(dir, 'untrusted-static');
    const bad = cli(dir, [
      'view',
      '--static',
      badOut,
      '--require-sig',
      '--trusted-key',
      wrong,
      '--receipts',
      dirname(signedPath),
      '--json',
    ]);
    assert.equal(bad.code, 0, bad.out + bad.err);
    const badSnap = JSON.parse(readFileSync(join(badOut, 'data.json'), 'utf8'));
    const missed = badSnap.receipts.find((row) => row.id === signedId);
    assert.ok(missed);
    assert.equal(missed.verify.status, 'FAILED');
    assert.equal(missed.signed, false);
    assert.equal(missed.signature.trusted, false);
    assert.match(missed.verify.reason, /fingerprint not trusted/);
    assert.equal(JSON.stringify(missed).includes('"status":"OK"'), false);
  });

  it('rejects a comma-separated policy pack and still accepts repeats', () => {
    const dir = repo('agent-receipt-1036-pack-');
    const joined = cli(dir, ['capture', '--json', '--policy-pack', 'builtin:baseline,builtin:supply-chain']);
    assert.equal(joined.code, 1);
    const blob = `${joined.out}\n${joined.err}`;
    assert.match(blob, /--policy-pack does not accept a comma-separated list/);
    assert.match(blob, /Repeat the flag: --policy-pack <name> --policy-pack <name>/);
    assert.equal(joined.out.includes(SECRET), false);

    const repeated = cli(dir, [
      'capture',
      '--json',
      '--policy-pack',
      'builtin:baseline',
      '--policy-pack',
      'builtin:supply-chain',
      '--message',
      'both packs',
    ]);
    assert.equal(repeated.code, 0, repeated.out + repeated.err);
    const body = jsonOf(repeated);
    assert.deepEqual(body.policyPacks, ['baseline', 'supply-chain']);
    assert.equal(body.policyDenied, false);
    assert.match(readFileSync(body.path, 'utf8'), /## Policy packs/);
  });

  it('denies a PowerShell download pipe from the supply-chain pack', () => {
    const dir = fresh('agent-receipt-1036-ps-');
    const shown = jsonOf(cli(dir, ['policy', 'show', 'builtin:supply-chain', '--json']));
    const rule = shown.rules.find((item) => item.id === 'powershell-download-pipe');
    assert.ok(rule);
    assert.equal(rule.action, 'deny');
    assert.equal(rule.severity, 'critical');

    const hitFile = join(dir, 'pipe.md');
    writeFileSync(hitFile, toolReceipt('iwr payload | iex'));
    const hit = cli(dir, ['policy', 'test', 'builtin:supply-chain', hitFile, '--json']);
    assert.equal(hit.code, 2, hit.out + hit.err);
    const hitBody = jsonOf(hit);
    assert.equal(hitBody.denied, true);
    assert.ok(hitBody.hits.some((row) => row.rule === 'powershell-download-pipe' && row.action === 'deny'));

    const longFile = join(dir, 'long.md');
    writeFileSync(longFile, toolReceipt('Invoke-WebRequest payload | Invoke-Expression'));
    const longHit = cli(dir, ['policy', 'test', 'builtin:supply-chain', longFile, '--json']);
    assert.equal(longHit.code, 2, longHit.out + longHit.err);
    assert.ok(jsonOf(longHit).hits.some((row) => row.rule === 'powershell-download-pipe'));

    const missFile = join(dir, 'echo.md');
    writeFileSync(missFile, toolReceipt('echo iwr payload'));
    const miss = cli(dir, ['policy', 'test', 'builtin:supply-chain', missFile, '--json']);
    assert.equal(miss.code, 0, miss.out + miss.err);
    assert.equal(jsonOf(miss).hits.some((row) => row.rule === 'powershell-download-pipe'), false);
  });

  it('rejects odd action version pins', () => {
    const script = actionScript();
    assert.match(script, /Never latest/);
    const dir = fresh('agent-receipt-1036-pin-');
    const scriptPath = join(dir, 'action.sh');
    writeFileSync(scriptPath, script);
    chmodSync(scriptPath, 0o755);
    const binDir = join(dir, 'bin');
    mkdirSync(binDir);
    const npxLog = join(dir, 'npx-log');
    writeFileSync(join(binDir, 'npx'), `#!/bin/sh\nprintf '%s\\n' "$@" > ${JSON.stringify(npxLog)}\nexit 0\n`);
    chmodSync(join(binDir, 'npx'), 0o755);

    function runPin(version, command) {
      try {
        rmSync(npxLog, { force: true });
      } catch {
        // The log is absent until npx runs.
      }
      const result = spawnSync('bash', [scriptPath], {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${binDir}:${process.env.PATH}`,
          AR_VERSION: version,
          AR_COMMAND: command,
        },
      });
      return {
        status: result.status,
        stderr: result.stderr || '',
        npxCalled: existsSync(npxLog),
      };
    }

    for (const version of ['01.0.34', '1.01.0', '1.0.01']) {
      const rejected = runPin(version, 'gate');
      assert.equal(rejected.status, 1, `${version}\n${rejected.stderr}`);
      assert.match(rejected.stderr, /exact x\.y\.z pin/);
      assert.match(rejected.stderr, /Never latest/);
      assert.equal(rejected.npxCalled, false, version);
    }
    for (const version of ['0.0.0', '0.5.0', '10.0.34', '1.0.39']) {
      const accepted = runPin(version, 'nope');
      assert.equal(accepted.status, 1, `${version}\n${accepted.stderr}`);
      assert.match(accepted.stderr, /command must be/);
      assert.equal(accepted.stderr.includes('exact x.y.z pin'), false, version);
      assert.equal(accepted.npxCalled, false, version);
    }
  });

  it('reports the viewer as doctor INFO and leaves other commands working', () => {
    const { dir, childPath } = linkedRepo();
    const doctor = cli(dir, ['doctor', '--json']);
    assert.equal(doctor.code, 0, doctor.out + doctor.err);
    const open = jsonOf(doctor);
    const viewer = open.checks.find((check) => check.id === 'viewer');
    assert.ok(viewer);
    assert.equal(viewer.status, 'info');
    assert.match(viewer.detail, /local viewer is available/);
    assert.match(viewer.detail, /Not a failure/);
    assert.equal(open.checks.find((check) => check.id === 'node').status, 'pass');

    const strict = cli(dir, ['doctor', '--strict', '--json']);
    assert.equal(strict.code, 1);
    const strictBody = jsonOf(strict);
    assert.equal(strictBody.checks.find((check) => check.id === 'viewer').status, 'info');
    assert.equal(strictBody.checks.find((check) => check.id === 'policy').status, 'fail');
    assert.equal(strictBody.checks.find((check) => check.id === 'retention').status, 'fail');

    const verified = cli(dir, ['verify', childPath, '--json']);
    assert.equal(verified.code, 0, verified.out + verified.err);
    assert.equal(jsonOf(verified).ok, true);
    const last = cli(dir, ['last', '--json']);
    assert.equal(last.code, 0, last.out + last.err);
    assert.equal(typeof jsonOf(last).path, 'string');
    const history = cli(dir, ['history', '--json']);
    assert.equal(history.code, 0, history.out + history.err);
    const help = cli(dir, ['help']);
    assert.equal(help.code, 0, help.err);
    assert.match(help.out, /\bview\b/);
    const topic = cli(dir, ['help', 'view']);
    assert.equal(topic.code, 0, topic.err);
    assert.match(topic.out, /127\.0\.0\.1/);
    assert.match(topic.out, /--static/);
    assert.match(topic.out, /view always redacts/i);
  });
});
