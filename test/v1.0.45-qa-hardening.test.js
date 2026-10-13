/**
 * v1.0.45 — share/report redaction of --message and --agent,
 * session-manifest member hash fail-closed, session stdout EPIPE,
 * and one manifest read for a multi-member package.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import {
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendHashFooter } from '../dist/lib/hash.js';
import {
  resetSessionManifestReads,
  sessionManifestReadCount,
} from '../dist/lib/session-package.js';
import { cmdOtlpExport } from '../dist/commands/otlp.js';
import { cmdAttest } from '../dist/commands/attest.js';
import { cmdReport } from '../dist/commands/report.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const GHP_MSG = `ghp_${'m'.repeat(36)}`;
const GHP_AGENT = `ghp_${'a'.repeat(36)}`;
const REDACTED = 'ghp_[REDACTED]';

after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function keep(dir) {
  dirs.push(dir);
  return dir;
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args, maxBuffer = 16 * 1024 * 1024) {
  const result = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    maxBuffer,
    timeout: 30000,
  });
  const extra = result.error ? result.error.message : '';
  return {
    code: result.status === null ? 1 : result.status,
    out: result.stdout || '',
    err: `${result.stderr || ''}${extra}`,
  };
}

function gitRepo(prefix) {
  const dir = keep(mkdtempSync(join(tmpdir(), prefix)));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# qa\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  assert.equal(cli(dir, ['init']).code, 0);
  return dir;
}

function parseJson(result) {
  assert.equal(result.code, 0, result.err + result.out);
  return JSON.parse(result.out);
}

function payloadOf(html) {
  const match = html.match(
    /<script type="application\/json" id="agent-receipt-report">([\s\S]*?)<\/script>/,
  );
  assert.ok(match, 'embedded payload missing');
  return JSON.parse(match[1]);
}

function walkFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const filePath = join(dir, name);
    const st = lstatSync(filePath);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) out.push(...walkFiles(filePath));
    else out.push(filePath);
  }
  return out;
}

function packageText(dir) {
  return walkFiles(dir).map((filePath) => readFileSync(filePath)).join('\n');
}

function assertNoToken(text, label) {
  assert.equal(text.includes(GHP_MSG), false, `${label} still has the message token`);
  assert.equal(text.includes(GHP_AGENT), false, `${label} still has the agent token`);
}

function assertNoStack(text) {
  assert.doesNotMatch(text, /Unhandled/);
  assert.doesNotMatch(text, /node:events/);
  assert.doesNotMatch(text, /^\s+at /m);
}

function latestReceipt(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  const files = readdirSync(out)
    .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
    .map((name) => join(out, name));
  assert.ok(files.length > 0, 'expected a receipt');
  files.sort((a, b) => lstatSync(b).mtimeMs - lstatSync(a).mtimeMs);
  return files[0];
}

/** Minimal 1.0.28 writer header so the session scanner accepts the receipt. */
function linkEraBody(fieldLines) {
  const fields = {};
  for (const line of fieldLines) {
    const match = line.match(/^- \*\*([^*]+)\*\*: (.*)$/);
    if (match) fields[match[1]] = match[2];
  }
  const timestamp = fields.Timestamp || '2026-10-13T00:00:00.000Z';
  const lines = [
    '# Agent Receipt',
    '',
    `> **TL;DR** ci · ${timestamp} · main @ abcdef012345 · 0 files · +0/\u22120 · risk none`,
    '',
    '## What to review',
    '',
    '_Nothing flagged. Skim the file list if this session should have been a no-op._',
    '',
    '## Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    '| Files | 0 |',
    '| Lines | +0 / \u22120 |',
    '| Commits | 0 |',
    '| Risk | none |',
    '',
    '## Session',
    '',
    '- **Version**: 1.0.28',
    `- **Timestamp**: ${timestamp}`,
    '- **Branch**: `main`',
    '- **HEAD**: `abcdef0123456789abcdef0123456789abcdef01`',
    '- **Range**: `HEAD~0..HEAD` (`abcdef012345` \u2192 HEAD)',
  ];
  for (const label of ['Id', 'Agent', 'Session', 'Parent', 'Host']) {
    if (fields[label]) lines.push(`- **${label}**: ${fields[label]}`);
  }
  lines.push('- **Workspace**: `/tmp`', '', '## Files changed', '', '_No file changes in range._', '');
  return lines.join('\n');
}

function seal(body) {
  return appendHashFooter(body.endsWith('\n') ? body : `${body}\n`);
}

function writeSealed(dir, sessionId, count) {
  const outDir = join(dir, '.agent-receipt', 'receipts');
  mkdirSync(outDir, { recursive: true });
  for (let i = 0; i < count; i += 1) {
    const id = `r-${i.toString(16).padStart(16, '0')}`;
    const second = String(i % 60).padStart(2, '0');
    writeFileSync(
      join(outDir, `${id}.md`),
      seal(
        linkEraBody([
          `- **Id**: ${id}`,
          `- **Timestamp**: 2026-10-13T00:${second}:00.000Z`,
          '- **Agent**: ci',
          `- **Session**: ${sessionId}`,
        ]),
      ),
    );
  }
  return outDir;
}

function runChild(cwd, args, { destroyStdout = false, stdoutFd = null, timeout = 20000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...args], {
      cwd,
      env: { ...process.env, NO_COLOR: '1' },
      stdio: ['ignore', stdoutFd === null ? 'pipe' : stdoutFd, 'pipe'],
    });
    if (typeof stdoutFd === 'number') closeSync(stdoutFd);
    let err = '';
    if (child.stderr) child.stderr.on('data', (buf) => {
      err += buf.toString('utf8');
    });
    if (destroyStdout && child.stdout) child.stdout.destroy();
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code: code === null ? 1 : code, signal, err });
    });
  });
}

function pipeHead(cwd, sessionId) {
  return new Promise((resolve) => {
    // Ubuntu CI uses dash as /bin/sh, and dash rejects `set -o pipefail`
    // (exit 2) before `session | head` runs. bash reports the session
    // status when head closes the pipe early.
    const child = spawn(
      'bash',
      ['-c', 'set -o pipefail; "$NODE" "$BIN" session "$SESS" | head -n 1'],
      {
        cwd,
        env: {
          ...process.env,
          NO_COLOR: '1',
          NODE: process.execPath,
          BIN: bin,
          SESS: sessionId,
        },
      },
    );
    let err = '';
    let out = '';
    child.stdout.on('data', (buf) => {
      out += buf.toString('utf8');
    });
    child.stderr.on('data', (buf) => {
      err += buf.toString('utf8');
    });
    const timer = setTimeout(() => child.kill('SIGKILL'), 60000);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code: code === null ? 1 : code, signal, err, out });
    });
  });
}

function flipRecordedManifestHash(sigPath) {
  const raw = readFileSync(sigPath, 'utf8');
  const doc = JSON.parse(raw);
  assert.match(doc.sha256, /^[0-9a-f]{64}$/);
  const flipped = (doc.sha256[0] === 'a' ? 'b' : 'a') + doc.sha256.slice(1);
  const quoted = `"sha256": "${doc.sha256}"`;
  assert.equal(raw.includes(quoted), true);
  const next = raw.replace(quoted, `"sha256": "${flipped}"`);
  assert.equal(JSON.parse(next).sha256, flipped);
  assert.equal(JSON.parse(next).sha256.length, 64);
  writeFileSync(sigPath, next);
}

describe('v1.0.45 share and report redaction', () => {
  it('masks ghp_ tokens in --message and --agent on share and report', () => {
    const dir = gitRepo('ar1045-redact-');
    const message = `note ${GHP_MSG} please`;
    const wrapped = cli(dir, [
      'wrap',
      '--agent',
      GHP_AGENT,
      '--message',
      message,
      '--session',
      's-redact',
      '--json',
    ]);
    assert.equal(wrapped.code, 0, wrapped.err + wrapped.out);
    const receipt = latestReceipt(dir);
    const original = readFileSync(receipt, 'utf8');
    assert.equal(original.includes(GHP_MSG), true);
    assert.equal(original.includes(GHP_AGENT), true);
    const verified = cli(dir, ['verify', receipt]);
    assert.equal(verified.code, 0, verified.err + verified.out);

    const sharedResult = cli(dir, ['share', receipt, '--package', '--json']);
    const shared = parseJson(sharedResult);
    assert.equal(shared.verified, true);
    const packed = packageText(shared.packagePath);
    assertNoToken(packed, 'share package');
    assertNoToken(sharedResult.out, 'share stdout');
    assert.equal(packed.includes(REDACTED), true);
    assert.equal(packed.includes('note '), true);
    assert.equal(packed.includes(' please'), true);
    const packageVerify = cli(dir, ['verify', '--package', shared.packagePath]);
    assert.equal(packageVerify.code, 0, packageVerify.err + packageVerify.out);

    const made = parseJson(cli(dir, ['report', receipt, '--json']));
    const html = readFileSync(made.htmlPath, 'utf8');
    assertNoToken(html, 'report html');
    const payload = payloadOf(html);
    assert.equal(payload.receipts[0].agent, REDACTED);
    assert.match(payload.receipts[0].message, /note ghp_\[REDACTED\] please/);
    assert.equal(html.includes(REDACTED), true);

    const sessionReport = parseJson(cli(dir, [
      'report',
      '--session',
      's-redact',
      '--out',
      join(dir, 'sess.report.html'),
      '--json',
    ]));
    const sessionHtml = readFileSync(sessionReport.htmlPath, 'utf8');
    assertNoToken(sessionHtml, 'session report');
    const sessionPayload = payloadOf(sessionHtml);
    assert.equal(sessionPayload.receipts[0].agent, REDACTED);
    assert.match(sessionPayload.tree, /agent=ghp_\[REDACTED\]/);
    assert.equal(sessionPayload.tree.includes(GHP_AGENT), false);

    const openShare = parseJson(cli(dir, [
      'share',
      receipt,
      '--package',
      '--no-redact',
      '--out',
      `${join(dir, 'open.share')}/`,
      '--json',
    ]));
    const openPacked = packageText(openShare.packagePath);
    assert.equal(openPacked.includes(GHP_MSG), true);
    assert.equal(openPacked.includes(GHP_AGENT), true);

    const openReport = parseJson(cli(dir, [
      'report',
      receipt,
      '--no-redact',
      '--out',
      join(dir, 'open.report.html'),
      '--json',
    ]));
    const openHtml = readFileSync(openReport.htmlPath, 'utf8');
    assert.equal(openHtml.includes(GHP_MSG), true);
    assert.equal(openHtml.includes(GHP_AGENT), true);
    assert.equal(payloadOf(openHtml).receipts[0].agent, GHP_AGENT);
  });
});

describe('v1.0.45 session-manifest tamper', () => {
  it('fails closed when the recorded session-manifest.json hash is rewritten', () => {
    const dir = gitRepo('ar1045-tamper-');
    assert.equal(cli(dir, ['keygen']).code, 0);
    assert.equal(cli(dir, [
      'wrap',
      '--session',
      'sess-tamper',
      '--agent',
      'ci',
      '--message',
      'tamper fixture',
      '--json',
    ]).code, 0);
    const packed = parseJson(cli(dir, ['session', 'export', 'sess-tamper', '--json']));
    const made = parseJson(cli(dir, ['report', packed.packagePath, '--json']));
    assert.equal(made.exitCode, 0);
    assert.equal(made.verdict, 'VERIFIED');
    const before = cli(dir, ['report', 'verify', made.htmlPath, '--receipts', packed.packagePath]);
    assert.equal(before.code, 0, before.err + before.out);
    assert.match(before.out, /^VERIFIED/m);

    flipRecordedManifestHash(join(packed.packagePath, 'session-manifest.sig.json'));
    const again = cli(dir, ['report', packed.packagePath, '--out', join(dir, 'tampered.report.html')]);
    assert.equal(again.code, 2, again.err + again.out);
    assert.doesNotMatch(again.out, /^VERIFIED/m);
    assert.doesNotMatch(again.err, /^VERIFIED/m);
    assert.match(again.err, /session manifest signature does not match/);
    assert.equal(existsSync(join(dir, 'tampered.report.html')), false);

    const checked = cli(dir, ['report', 'verify', made.htmlPath, '--receipts', packed.packagePath]);
    assert.equal(checked.code, 2, checked.err + checked.out);
    assert.doesNotMatch(checked.out, /^VERIFIED/m);
    assert.doesNotMatch(checked.err, /^VERIFIED/m);
    assert.match(checked.err, /session manifest signature does not match/);
    assert.match(checked.out, /^FAILED/m);

    const json = cli(dir, [
      'report',
      'verify',
      made.htmlPath,
      '--receipts',
      packed.packagePath,
      '--json',
    ]);
    assert.equal(json.code, 2, json.err + json.out);
    const body = JSON.parse(json.out);
    assert.equal(body.exitCode, 2);
    assert.equal(body.verdict, 'FAILED');
    assert.match(body.reason, /session manifest signature does not match/);
    assert.doesNotMatch(json.out, /^VERIFIED/m);
  });
});

describe('v1.0.45 session stdout', () => {
  it('exits 0 on EPIPE and exits cleanly when stdout cannot accept a write', async () => {
    const small = keep(mkdtempSync(join(tmpdir(), 'ar1045-epipe-')));
    writeSealed(small, 'sess-small', 3);

    const closed = await runChild(small, ['session', 'sess-small'], { destroyStdout: true });
    assert.equal(closed.code, 0, closed.err);
    assert.equal(closed.signal, null);
    assertNoStack(closed.err);

    const jsonClosed = await runChild(small, ['session', 'sess-small', '--json'], { destroyStdout: true });
    assert.equal(jsonClosed.code, 0, jsonClosed.err);
    assert.equal(jsonClosed.signal, null);
    assertNoStack(jsonClosed.err);

    const missing = await runChild(small, ['session', 'sess-missing'], { destroyStdout: true });
    assert.equal(missing.code, 1, missing.err);
    assert.match(missing.err, /no receipts in session sess-missing/);
    assertNoStack(missing.err);

    const outDir = join(small, '.agent-receipt', 'receipts');
    const brokenPath = join(outDir, 'r-0000000000000000.md');
    const brokenText = readFileSync(brokenPath, 'utf8').replace(
      /agent-receipt-sha256:[0-9a-f]{64}/,
      (line) => {
        const hex = line.slice(line.length - 64);
        const next = (hex[0] === 'a' ? 'b' : 'a') + hex.slice(1);
        return `agent-receipt-sha256:${next}`;
      },
    );
    writeFileSync(brokenPath, brokenText);
    const failed = await runChild(small, ['session', 'sess-small'], { destroyStdout: true });
    assert.equal(failed.code, 1, failed.err);
    assertNoStack(failed.err);
    writeFileSync(brokenPath, seal(linkEraBody([
      '- **Id**: r-0000000000000000',
      '- **Timestamp**: 2026-10-13T00:00:00.000Z',
      '- **Agent**: ci',
      '- **Session**: sess-small',
    ])));

    const fullFd = openSync('/dev/full', 'w');
    const full = await runChild(small, ['session', 'sess-small'], { stdoutFd: fullFd });
    assert.notEqual(full.code, 0);
    assert.match(full.err, /no space left on device/);
    assertNoStack(full.err);
    const fullLines = full.err.split('\n').filter((line) => line.includes('no space left on device'));
    assert.equal(fullLines.length, 1);

    const jsonFd = openSync('/dev/full', 'w');
    const jsonFull = await runChild(small, ['session', 'sess-small', '--json'], { stdoutFd: jsonFd });
    assert.notEqual(jsonFull.code, 0);
    assert.match(jsonFull.err, /no space left on device/);
    assertNoStack(jsonFull.err);

    const wide = keep(mkdtempSync(join(tmpdir(), 'ar1045-head-')));
    writeSealed(wide, 'sess-pipe', 1400);
    const piped = await pipeHead(wide, 'sess-pipe');
    assert.equal(piped.code, 0, piped.err + piped.out);
    assert.equal(piped.signal, null);
    assert.match(piped.out, /^session sess-pipe\n?$/);
    assertNoStack(piped.err);
  });
});

describe('v1.0.45 manifest read count', () => {
  it('counts every session-manifest load once for a package with two receipts', async () => {
    // A one-member package cannot catch a per-member re-read.
    const dir = gitRepo('ar1045-reads-');
    const first = parseJson(cli(dir, ['capture', '--json', '--commits', '1', '--agent', 'cursor', '--session', 'sess-1045-read']));
    const second = parseJson(cli(dir, ['capture', '--json', '--commits', '1', '--agent', 'cursor', '--session', 'sess-1045-read', '--message', 'second']));
    assert.notEqual(first.path, second.path);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const packed = parseJson(cli(dir, ['session', 'export', 'sess-1045-read', '--json']));
    const manifest = JSON.parse(readFileSync(join(packed.packagePath, 'session-manifest.json'), 'utf8'));
    assert.ok(manifest.receipts.length >= 2);

    resetSessionManifestReads();
    assert.equal(cmdOtlpExport(dir, packed.packagePath, { out: join(dir, 'two.otlp.json') }), 0);
    assert.equal(sessionManifestReadCount(), 1);

    resetSessionManifestReads();
    assert.equal(
      await cmdAttest(dir, packed.packagePath, { noSign: true, out: join(dir, 'two.intoto.jsonl') }),
      0,
    );
    assert.equal(sessionManifestReadCount(), 1);

    resetSessionManifestReads();
    assert.equal(cmdReport(dir, packed.packagePath, { json: true, out: join(dir, 'two.report.html') }), 0);
    assert.equal(sessionManifestReadCount(), 1);
  });
});
