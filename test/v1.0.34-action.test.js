import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  mkdirSync,
  chmodSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const AWS = 'AKIAIOSFODNN7EXAMPLE';
const GHP = 'ghp_' + 'b'.repeat(36);
const TOKEN = 'ghs_' + 'C'.repeat(36);

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args, env = {}) {
  const r = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 15000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      GITHUB_TOKEN: '',
      GITHUB_REPOSITORY: '',
      GITHUB_EVENT_PATH: '',
      GITHUB_API_URL: '',
      GITHUB_STEP_SUMMARY: '',
      ...env,
    },
  });
  return {
    code: r.status === null ? 1 : r.status,
    out: r.stdout || '',
    err: r.stderr || '',
    signal: r.signal,
  };
}

// Async spawn keeps the event loop free so an in-process mock API can answer.
function cliAsync(cwd, args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...args], {
      cwd,
      env: {
        ...process.env,
        NO_COLOR: '1',
        GITHUB_TOKEN: '',
        GITHUB_REPOSITORY: '',
        GITHUB_EVENT_PATH: '',
        GITHUB_API_URL: '',
        GITHUB_STEP_SUMMARY: '',
        ...env,
      },
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill('SIGTERM'), 15000);
    child.stdout.on('data', (chunk) => {
      out += chunk;
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, out, err, signal });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({ code: 1, out, err: `${err}${error.message}`, signal: null });
    });
    child.stdin.end();
  });
}

function parseYaml(src) {
  const lines = src.split('\n');
  const rootMap = {};
  const stack = [{ indent: -1, type: 'map', value: rootMap }];

  function unquote(value) {
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      return value.slice(1, -1);
    }
    return value;
  }

  function peek(start) {
    for (let i = start; i < lines.length; i++) {
      const raw = lines[i];
      if (!raw.trim() || /^\s*#/.test(raw)) continue;
      return { indent: raw.match(/^ */)[0].length, text: raw.trim() };
    }
    return null;
  }

  function takeBlock(start) {
    const buf = [];
    let i = start;
    let base = null;
    for (; i < lines.length; i++) {
      const raw = lines[i];
      if (!raw.trim()) {
        buf.push('');
        continue;
      }
      if (/^\s*#/.test(raw) && base === null) break;
      const indent = raw.match(/^ */)[0].length;
      if (base === null) base = indent;
      if (indent < base) break;
      buf.push(raw.slice(base));
    }
    while (buf.length && buf[buf.length - 1] === '') buf.pop();
    return { text: buf.join('\n'), next: i };
  }

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const indent = raw.match(/^ */)[0].length;
    const trimmed = raw.slice(indent);
    while (stack.length > 1 && indent < stack[stack.length - 1].indent) stack.pop();
    const top = stack[stack.length - 1];

    if (trimmed.startsWith('- ')) {
      if (top.type !== 'seq') throw new Error(`list item outside a sequence: ${raw}`);
      const rest = trimmed.slice(2).trim();
      const colon = rest.indexOf(':');
      const obj = {};
      top.value.push(obj);
      if (colon === -1) {
        top.value[top.value.length - 1] = unquote(rest);
        continue;
      }
      const key = rest.slice(0, colon).trim();
      const val = rest.slice(colon + 1).trim();
      if (val === '|' || val === '|-' || val === '>' || val === '>-') {
        const block = takeBlock(i + 1);
        obj[key] = val.startsWith('>') ? block.text.replace(/\s+/g, ' ').trim() : block.text;
        i = block.next - 1;
      } else if (val === '') {
        const next = peek(i + 1);
        if (next && next.text.startsWith('- ')) {
          const arr = [];
          obj[key] = arr;
          stack.push({ indent, type: 'map', value: obj });
          stack.push({ indent: next.indent, type: 'seq', value: arr });
        } else {
          const child = {};
          obj[key] = child;
          stack.push({ indent, type: 'map', value: obj });
          if (next) stack.push({ indent: next.indent, type: 'map', value: child });
        }
      } else {
        obj[key] = unquote(val);
      }
      stack.push({ indent, type: 'map', value: obj });
      continue;
    }

    const colon = trimmed.indexOf(':');
    if (colon === -1) throw new Error(`bad yaml line: ${raw}`);
    if (top.type !== 'map') throw new Error(`key outside a map: ${raw}`);
    const key = trimmed.slice(0, colon).trim();
    const val = trimmed.slice(colon + 1).trim();
    if (val === '|' || val === '|-' || val === '>' || val === '>-') {
      const block = takeBlock(i + 1);
      top.value[key] = val.startsWith('>') ? block.text.replace(/\s+/g, ' ').trim() : block.text;
      i = block.next - 1;
      continue;
    }
    if (val === '') {
      const next = peek(i + 1);
      if (next && next.text.startsWith('- ')) {
        const arr = [];
        top.value[key] = arr;
        stack.push({ indent: next.indent, type: 'seq', value: arr });
      } else if (next && next.indent > indent) {
        const child = {};
        top.value[key] = child;
        stack.push({ indent: next.indent, type: 'map', value: child });
      } else {
        top.value[key] = '';
      }
      continue;
    }
    top.value[key] = unquote(val);
  }
  return rootMap;
}

function startGithub(mode = 'ok') {
  const comments = [];
  const hits = [];
  let seq = 1;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const bodyText = Buffer.concat(chunks).toString('utf8');
      hits.push({
        method: req.method,
        url: req.url,
        auth: req.headers.authorization || '',
        body: bodyText,
      });
      if (mode === '403' || mode === '404') {
        const status = mode === '403' ? 403 : 404;
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ message: 'nope' }));
        return;
      }
      if (mode === 'drop') {
        req.socket.destroy();
        return;
      }
      const url = req.url || '';
      if (req.method === 'GET' && url.includes('/comments')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(comments.map((c) => ({ id: c.id, body: c.body, html_url: c.url }))));
        return;
      }
      if (req.method === 'POST' && url.includes('/comments')) {
        const parsed = JSON.parse(bodyText);
        const id = seq++;
        const html = `http://127.0.0.1/acme/app/pull/12#issuecomment-${id}`;
        comments.push({ id, body: parsed.body, url: html });
        res.writeHead(201, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ id, body: parsed.body, html_url: html }));
        return;
      }
      if (req.method === 'PATCH') {
        const parsed = JSON.parse(bodyText);
        const id = Number(url.split('/').filter(Boolean).pop());
        const existing = comments.find((c) => c.id === id);
        if (!existing) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end('{}');
          return;
        }
        existing.body = parsed.body;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ id, body: existing.body, html_url: existing.url }));
        return;
      }
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end('{}');
    });
  });
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('mock listen failed'));
        return;
      }
      resolve({
        comments,
        hits,
        url: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

describe('v1.0.39 GitHub Action and pr-comment', { concurrency: 1 }, () => {
  const dirs = [];
  after(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  function freshDir(prefix) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    return dir;
  }

  function repo(prefix) {
    const dir = freshDir(prefix);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# demo\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    const init = cli(dir, ['init']);
    assert.equal(init.code, 0, init.err);
    return dir;
  }

  function captureClean(dir) {
    writeFileSync(join(dir, 'app.txt'), 'hello\n');
    git(dir, ['add', 'app.txt']);
    git(dir, ['commit', '-m', 'app']);
    const cap = cli(dir, ['capture', '--message', 'clean change']);
    assert.equal(cap.code, 0, cap.err);
  }

  function captureSecret(dir) {
    writeFileSync(join(dir, 'secret.txt'), `aws ${AWS}\npat ${GHP}\n`);
    git(dir, ['add', 'secret.txt']);
    git(dir, ['commit', '-m', 'secret']);
    const cap = cli(dir, ['capture', '--message', `ship ${AWS} ${GHP}`]);
    assert.equal(cap.code, 0, cap.out + cap.err);
  }

  function eventFile(dir, pr = 12) {
    const path = join(dir, 'event.json');
    writeFileSync(path, JSON.stringify({ pull_request: { number: pr } }));
    return path;
  }

  function ghEnv(dir, api, extra = {}) {
    return {
      GITHUB_TOKEN: TOKEN,
      GITHUB_REPOSITORY: 'acme/app',
      GITHUB_EVENT_PATH: eventFile(dir),
      GITHUB_API_URL: api,
      GITHUB_STEP_SUMMARY: join(dir, 'step-summary.md'),
      ...extra,
    };
  }

  function assertNoToken(text) {
    assert.equal(text.includes(TOKEN), false);
    assert.equal(text.includes('ghs_[REDACTED]'), false);
  }

  it('parses action.yml and pins an exact version', () => {
    const text = readFileSync(join(root, 'action.yml'), 'utf8');
    const action = parseYaml(text);
    assert.equal(action.name, 'Agent Receipt');
    assert.match(action.description, /Gate a pull request/);
    assert.equal(action.branding.icon, 'shield');
    assert.equal(action.branding.color, 'blue');
    assert.equal(action.runs.using, 'composite');
    for (const key of [
      'version',
      'command',
      'fail-on',
      'policy',
      'receipts',
      'require-signature',
      'certificate-identity',
      'certificate-identity-regexp',
      'certificate-oidc-issuer',
      'comment',
      'comment-mode',
      'github-token',
    ]) {
      assert.ok(action.inputs[key], `missing input ${key}`);
    }
    assert.equal(action.inputs.version.default, '1.0.39');
    assert.equal(action.inputs.command.default, 'gate');
    assert.equal(action.inputs.comment.default, 'on');
    assert.equal(action.inputs['comment-mode'].default, 'update');
    assert.equal(action.inputs['github-token'].default, '${{ github.token }}');
    for (const key of ['verdict', 'risk', 'receipts-count', 'summary-path', 'comment-url']) {
      assert.ok(action.outputs[key], `missing output ${key}`);
      assert.match(action.outputs[key].value, /steps\.gate\.outputs/);
    }
    const script = action.runs.steps[0].run;
    assert.match(script, /npx --yes "@pramodreddyboddu\/agent-receipt@\$\{AR_VERSION\}"/);
    assert.match(script, /Never latest/);
    assert.equal(script.includes('@latest'), false);
    assert.equal(script.includes('agent-receipt@latest'), false);
    assert.match(script, /pr-comment/);

    const scriptPath = join(freshDir('agent-receipt-1034-act-'), 'action.sh');
    writeFileSync(scriptPath, script);
    chmodSync(scriptPath, 0o755);
    const binDir = freshDir('agent-receipt-1034-npx-');
    const npxLog = join(binDir, 'npx-args');
    writeFileSync(
      join(binDir, 'npx'),
      `#!/bin/sh\nprintf '%s\\n' "$@" > "${npxLog}"\nprintf '%s\\n' '{"verdict":"pass","risk":{"maxSeverity":null},"receiptsCount":2,"summaryPath":"/tmp/agent-receipt-summary.md","commentUrl":"http://example.test/c/1","exitCode":0}'\nexit 0\n`,
    );
    chmodSync(join(binDir, 'npx'), 0o755);
    const output = join(binDir, 'github-output');
    const baseEnv = {
      PATH: `${binDir}:${process.env.PATH}`,
      AR_COMMAND: 'gate',
      AR_FAIL_ON: '',
      AR_POLICY: '',
      AR_RECEIPTS: '',
      AR_REQUIRE_SIG: 'false',
      AR_CERT_ID: '',
      AR_CERT_RE: '',
      AR_ISSUER: '',
      AR_COMMENT: 'on',
      AR_COMMENT_MODE: 'update',
      GITHUB_TOKEN: TOKEN,
      GITHUB_WORKSPACE: binDir,
      RUNNER_TEMP: binDir,
      GITHUB_OUTPUT: output,
    };
    const rejected = spawnSync('bash', [scriptPath], {
      encoding: 'utf8',
      env: { ...baseEnv, AR_VERSION: 'latest' },
    });
    assert.equal(rejected.status, 1, rejected.stdout + rejected.stderr);
    assert.match(rejected.stderr, /Never latest/);
    let npxCalled = false;
    try {
      readFileSync(npxLog, 'utf8');
      npxCalled = true;
    } catch {
      npxCalled = false;
    }
    assert.equal(npxCalled, false);
    assertNoToken(rejected.stdout + rejected.stderr);

    const bad = spawnSync('bash', [scriptPath], {
      encoding: 'utf8',
      env: { ...baseEnv, AR_VERSION: '1.0.39', AR_COMMAND: 'ship' },
    });
    assert.equal(bad.status, 1, bad.stderr);
    assert.match(bad.stderr, /command must be/);

    const ok = spawnSync('bash', [scriptPath], {
      encoding: 'utf8',
      env: { ...baseEnv, AR_VERSION: '1.0.39' },
    });
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    const args = readFileSync(npxLog, 'utf8');
    assert.match(args, /@pramodreddyboddu\/agent-receipt@1\.0\.39/);
    assert.equal(args.includes('latest'), false);
    assert.match(args, /pr-comment/);
    const produced = readFileSync(output, 'utf8');
    assert.match(produced, /^verdict=pass$/m);
    assert.match(produced, /^risk=none$/m);
    assert.match(produced, /^receipts-count=2$/m);
    assert.match(produced, /^comment-url=http:\/\/example\.test\/c\/1$/m);
    assertNoToken(ok.stdout + ok.stderr + produced + args);
  });

  it('renders a pass summary and a fail summary', () => {
    const passDir = repo('agent-receipt-1034-pass-');
    captureClean(passDir);
    const passOut = join(passDir, 'summary.md');
    const pass = cli(passDir, ['pr-comment', '--dry-run', '--out', passOut, '--fail-on', 'high']);
    assert.equal(pass.code, 0, pass.out + pass.err);
    assert.match(pass.out, /<!-- agent-receipt:summary -->/);
    assert.match(pass.out, /\*\*Verdict:\*\* pass/);
    assert.match(pass.out, /\*\*Receipts checked:\*\* 1/);
    assert.match(pass.out, /\*\*Risk:\*\* none/);
    assert.match(pass.out, /\*\*Hash-chain head:\*\* `[0-9a-f]{64}`/);
    assert.equal(readFileSync(passOut, 'utf8').includes('**Verdict:** pass'), true);

    const failDir = repo('agent-receipt-1034-fail-');
    captureSecret(failDir);
    const failSummary = join(failDir, 'step-summary.md');
    const fail = cli(failDir, ['pr-comment', '--dry-run', '--fail-on', 'high'], {
      GITHUB_STEP_SUMMARY: failSummary,
    });
    assert.equal(fail.code, 2, fail.out + fail.err);
    assert.match(fail.out, /\*\*Verdict:\*\* fail/);
    assert.match(fail.out, /\*\*Risk:\*\* high/);
    assert.match(fail.out, /aws-access-key|github-token/);
    const summary = readFileSync(failSummary, 'utf8');
    assert.match(summary, /\*\*Verdict:\*\* fail/);
    assert.equal(fail.out.includes(AWS), false);
    assert.equal(fail.out.includes(GHP), false);
    assert.equal(summary.includes(AWS), false);
    assert.equal(summary.includes(GHP), false);
    assert.match(fail.out, /AKIA\[REDACTED\]/);
    assert.match(summary, /ghp_\[REDACTED\]/);
  });

  it('updates one sticky comment and does not duplicate it', async () => {
    const mock = await startGithub('ok');
    try {
      const dir = repo('agent-receipt-1034-sticky-');
      captureClean(dir);
      const env = ghEnv(dir, mock.url);
      const first = await cliAsync(dir, ['pr-comment', '--comment', 'on', '--comment-mode', 'update'], env);
      assert.equal(first.code, 0, first.out + first.err);
      assert.equal(mock.comments.length, 1);
      assert.match(mock.comments[0].body, /<!-- agent-receipt:summary -->/);
      assert.match(first.out, /comment http:\/\/127\.0\.0\.1\/acme\/app\/pull\/12#issuecomment-1/);
      const created = mock.hits.filter((hit) => hit.method === 'POST');
      assert.equal(created.length, 1);

      writeFileSync(join(dir, 'more.txt'), 'second\n');
      git(dir, ['add', 'more.txt']);
      git(dir, ['commit', '-m', 'more']);
      const againCap = cli(dir, ['capture', '--message', 'second pass']);
      assert.equal(againCap.code, 0, againCap.err);
      const second = await cliAsync(dir, ['pr-comment', '--comment-mode', 'update'], env);
      assert.equal(second.code, 0, second.out + second.err);
      assert.equal(mock.comments.length, 1);
      assert.match(mock.comments[0].body, /second pass/);
      const patches = mock.hits.filter((hit) => hit.method === 'PATCH');
      assert.equal(patches.length, 1);
      assert.equal(mock.hits.filter((hit) => hit.method === 'POST').length, 1);
      const blob = first.out + first.err + second.out + second.err + mock.comments[0].body + readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8');
      assertNoToken(blob);
      assert.equal(mock.hits.every((hit) => hit.auth === `Bearer ${TOKEN}`), true);
    } finally {
      await mock.close();
    }
  });

  it('falls back on 403 and 404 without changing the gate exit code', async () => {
    const forbidden = await startGithub('403');
    const missing = await startGithub('404');
    try {
      const failDir = repo('agent-receipt-1034-403-');
      captureSecret(failDir);
      const failEnv = ghEnv(failDir, forbidden.url);
      const failed = await cliAsync(failDir, ['pr-comment', '--fail-on', 'high'], failEnv);
      assert.equal(failed.code, 2, failed.out + failed.err);
      assert.match(failed.err, /403/);
      assert.match(failed.err, /step summary/);
      assert.match(readFileSync(failEnv.GITHUB_STEP_SUMMARY, 'utf8'), /\*\*Verdict:\*\* fail/);
      assert.equal(forbidden.comments.length, 0);
      assertNoToken(failed.out + failed.err);

      const passDir = repo('agent-receipt-1034-404-');
      captureClean(passDir);
      const passEnv = ghEnv(passDir, missing.url);
      const passed = await cliAsync(passDir, ['pr-comment', '--fail-on', 'high'], passEnv);
      assert.equal(passed.code, 0, passed.out + passed.err);
      assert.match(passed.err, /404/);
      assert.match(readFileSync(passEnv.GITHUB_STEP_SUMMARY, 'utf8'), /\*\*Verdict:\*\* pass/);
      assertNoToken(passed.out + passed.err);
    } finally {
      await forbidden.close();
      await missing.close();
    }
  });

  it('keeps the gate exit code when the API connection fails', async () => {
    const mock = await startGithub('drop');
    try {
      const dir = repo('agent-receipt-1034-net-');
      captureSecret(dir);
      const env = ghEnv(dir, mock.url);
      const failed = await cliAsync(dir, ['pr-comment', '--fail-on', 'high'], env);
      assert.equal(failed.code, 2, failed.out + failed.err);
      assert.match(failed.err, /network|fetch|ECONN|socket|verdict is unchanged/i);
      assert.match(readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8'), /\*\*Verdict:\*\* fail/);
      assertNoToken(failed.out + failed.err + readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8'));
    } finally {
      await mock.close();
    }
  });

  it('fails clearly without pull request context and no-ops on --dry-run', () => {
    const dir = repo('agent-receipt-1034-ctx-');
    captureClean(dir);
    const missing = cli(dir, ['pr-comment', '--comment', 'on']);
    assert.equal(missing.code, 1, missing.out + missing.err);
    assert.match(missing.err, /pull request|GITHUB_EVENT_PATH|--pr/);
    assertNoToken(missing.out + missing.err);

    const dry = cli(dir, ['pr-comment', '--dry-run']);
    assert.equal(dry.code, 0, dry.out + dry.err);
    assert.match(dry.out, /\*\*Verdict:\*\* pass/);
    assert.equal(/Error:/.test(dry.err), false);
  });

  it('prints JSON that matches the summary and the exit code', () => {
    const dir = repo('agent-receipt-1034-json-');
    captureSecret(dir);
    const failed = cli(dir, ['pr-comment', '--json', '--dry-run', '--fail-on', 'high']);
    assert.equal(failed.code, 2, failed.out + failed.err);
    const body = JSON.parse(failed.out);
    assert.equal(body.command, 'pr-comment');
    assert.equal(body.version, '1.0.39');
    assert.equal(body.verdict, 'fail');
    assert.equal(body.exitCode, 2);
    assert.equal(body.ok, false);
    assert.ok(body.risk.high >= 1);
    assert.equal(body.receiptsCount, 1);
    assert.match(body.hashChainHead, /^[0-9a-f]{64}$/);
    assert.match(body.summary, /\*\*Verdict:\*\* fail/);
    assert.match(body.summary, /\*\*Risk:\*\* high/);
    assert.equal(body.summary.includes(AWS), false);
    assert.equal(body.summary.includes(GHP), false);
    assert.equal(failed.out.includes(TOKEN), false);

    const passDir = repo('agent-receipt-1034-json-pass-');
    captureClean(passDir);
    const passed = cli(passDir, ['pr-comment', '--json', '--dry-run']);
    assert.equal(passed.code, 0, passed.out + passed.err);
    const ok = JSON.parse(passed.out);
    assert.equal(ok.verdict, 'pass');
    assert.equal(ok.exitCode, 0);
    assert.equal(ok.receiptsCount, 1);
    assert.match(ok.summary, /\*\*Verdict:\*\* pass/);
  });

  it('documents 1.0.39 and rejects an unknown command', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.39');
    assert.equal(pkg.dependencies, undefined);
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.34\]/);
    assert.match(changelog, /pr-comment/);
    assert.match(changelog, /action\.yml/);
    const help = cli(root, ['help', 'pr-comment']);
    assert.equal(help.code, 0, help.err);
    assert.match(help.out, /--dry-run/);
    assert.match(help.out, /comment-mode/);
    assert.match(help.out, /GITHUB_TOKEN/);
    assert.match(help.out, /never printed/);
    const docs = readFileSync(join(root, 'docs', 'github-action.md'), 'utf8');
    assert.match(docs, /id-token: write/);
    assert.match(docs, /pull-requests: write/);
    assert.match(docs, /permissions:/);
    assert.match(docs, /Marketplace/);
    assert.match(docs, /v1/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /## GitHub Action/);
    const bad = cli(root, ['pr-comment', '--command', 'ship']);
    assert.equal(bad.code, 1);
    assert.match(bad.err, /gate, verify, or attest-verify/);
  });
});
