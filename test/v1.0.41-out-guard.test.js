/**
 * v1.0.41 identity --out guard and session-package export verification.
 * A symlinked parent must not overwrite the source. A tampered package
 * manifest exits 2 and writes nothing.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cmdAttest } from '../dist/commands/attest.js';
import { cmdOtlpExport } from '../dist/commands/otlp.js';
import { writeExclusiveFile, writeExclusiveTemp } from '../dist/lib/exclusive-write.js';
import { appendHashFooter } from '../dist/lib/hash.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];

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
  });
  const extra = result.error ? result.error.message : '';
  return {
    code: result.status ?? 1,
    out: result.stdout || '',
    err: `${result.stderr || ''}${extra}`,
  };
}

function gitRepo() {
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1041-')));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# guard\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  assert.equal(cli(dir, ['init']).code, 0);
  return dir;
}

function parseJson(result) {
  assert.equal(result.code, 0, result.err + result.out);
  return JSON.parse(result.out);
}

function capture(dir, extra = []) {
  return parseJson(cli(dir, ['capture', '--json', '--commits', '1', '--agent', 'cursor', ...extra]));
}

function linkEraBody(fields) {
  const timestamp = fields.Timestamp || '2026-09-29T00:00:00.000Z';
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

function sealReceipt(body) {
  return appendHashFooter(body.endsWith('\n') ? body : `${body}\n`);
}

function caseFolds(dir) {
  const name = join(dir, 'CaseFoldProbe');
  writeFileSync(name, 'a');
  try {
    const flipped = join(dir, 'casefoldprobe');
    return statSync(name).ino === statSync(flipped).ino && statSync(name).dev === statSync(flipped).dev;
  } catch {
    return false;
  } finally {
    rmSync(name, { force: true });
  }
}

function exportArgs(format, source, out) {
  const args = ['export', source, '--out', out];
  if (format !== 'html') args.push('--format', format);
  return args;
}

describe('v1.0.41 --out identity guard', () => {
  it('refuses a symlinked parent that names the source receipt', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const before = readFileSync(captured.path);
    const linkdir = join(dir, 'linkdir');
    symlinkSync(dirname(captured.path), linkdir);
    const viaLink = join(linkdir, basename(captured.path));
    for (const format of ['html', 'markdown', 'otlp', 'intoto']) {
      const result = cli(dir, exportArgs(format, captured.path, viaLink));
      assert.equal(result.code, 1, `${format}\n${result.err}${result.out}`);
      assert.match(result.err, /over the receipt/, format);
      assert.equal(result.out.includes('wrote') || result.out.includes('Wrote'), false, format);
      assert.deepEqual(readFileSync(captured.path), before, format);
    }
    const other = join(linkdir, 'other.html');
    const ok = cli(dir, ['export', captured.path, '--out', other]);
    assert.equal(ok.code, 0, ok.err + ok.out);
    assert.equal(existsSync(join(dirname(captured.path), 'other.html')), true);
    assert.deepEqual(readFileSync(captured.path), before);
  });

  it('refuses a symlinked-file --out and a dangling symlink', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const before = readFileSync(captured.path);
    const target = join(dir, 'real-target.html');
    writeFileSync(target, 'keep-me');
    const via = join(dir, 'via-link.html');
    symlinkSync(target, via);
    for (const format of ['html', 'otlp']) {
      const result = cli(dir, exportArgs(format, captured.path, via));
      assert.equal(result.code, 1, `${format}\n${result.err}`);
      assert.match(result.err, /refusing to write through a symlink/, format);
      assert.doesNotMatch(result.err, /dangling/, format);
      assert.equal(readFileSync(target, 'utf8'), 'keep-me');
      assert.deepEqual(readFileSync(captured.path), before);
    }
    const missing = join(dir, 'missing-target.html');
    const dangling = join(dir, 'dangling.html');
    symlinkSync(missing, dangling);
    const hung = cli(dir, ['export', captured.path, '--out', dangling]);
    assert.equal(hung.code, 1, hung.err);
    assert.match(hung.err, /dangling symlink/);
    assert.equal(existsSync(missing), false);
    assert.equal(lstatSync(dangling).isSymbolicLink(), true);
    const hungOtlp = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', dangling]);
    assert.equal(hungOtlp.code, 1, hungOtlp.err);
    assert.match(hungOtlp.err, /dangling symlink/);
    assert.equal(existsSync(missing), false);
    assert.deepEqual(readFileSync(captured.path), before);
  });

  it('gives a clear error for a trailing slash or an existing directory', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const before = readFileSync(captured.path);
    const sub = join(dir, 'outdir');
    mkdirSync(sub);
    const asDir = cli(dir, ['export', captured.path, '--out', sub]);
    assert.equal(asDir.code, 1, asDir.err);
    assert.match(asDir.err, /--out is a directory/);
    assert.equal(existsSync(join(sub, 'index.html')), false);
    const slashed = cli(dir, ['export', '--format', 'markdown', captured.path, '--out', `${sub}/`]);
    assert.equal(slashed.code, 1, slashed.err);
    assert.match(slashed.err, /--out must be a file path, not a directory/);
    assert.deepEqual(readFileSync(captured.path), before);
    const names = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', `${sub}/`]);
    assert.equal(names.code, 0, names.err + names.out);
    assert.equal(existsSync(join(sub, `${basename(captured.path).replace(/\.md$/i, '')}.otlp.json`)), true);
  });

  it('refuses session-manifest.json as --out', () => {
    const dir = gitRepo();
    const captured = capture(dir, ['--session', 's-guard']);
    const packed = parseJson(cli(dir, ['session', 'export', 's-guard', '--json']));
    const manifestPath = join(packed.packagePath, 'session-manifest.json');
    const before = readFileSync(manifestPath);
    const manifest = JSON.parse(before.toString('utf8'));
    const packagedReceipt = join(packed.packagePath, manifest.receipts[0].path);
    const otlp = cli(dir, ['export', '--format', 'otlp', packed.packagePath, '--out', manifestPath]);
    assert.equal(otlp.code, 1, otlp.err + otlp.out);
    assert.match(otlp.err, /session-manifest\.json/);
    assert.equal(otlp.out.includes('wrote'), false);
    assert.deepEqual(readFileSync(manifestPath), before);
    const html = cli(dir, ['export', packagedReceipt, '--out', manifestPath]);
    assert.equal(html.code, 1, html.err + html.out);
    assert.match(html.err, /session-manifest\.json/);
    assert.deepEqual(readFileSync(manifestPath), before);
    const linkdir = join(dir, 'pkg-link');
    symlinkSync(packed.packagePath, linkdir);
    const via = join(linkdir, 'session-manifest.json');
    const linked = cli(dir, ['export', '--format', 'intoto', packed.packagePath, '--out', via]);
    assert.equal(linked.code, 1, linked.err + linked.out);
    assert.match(linked.err, /session-manifest\.json/);
    assert.deepEqual(readFileSync(manifestPath), before);
  });

  it('exits 2 when a package manifest sha256 or bytes hash is wrong', () => {
    const dir = gitRepo();
    capture(dir, ['--session', 's-tamper']);
    const packed = parseJson(cli(dir, ['session', 'export', 's-tamper', '--json']));
    const manifestPath = join(packed.packagePath, 'session-manifest.json');
    const original = readFileSync(manifestPath, 'utf8');
    const doc = JSON.parse(original);
    const entry = doc.receipts[0];
    assert.ok(entry);
    const flip = entry.sha256.startsWith('ab') ? 'cd'.repeat(32) : 'ab'.repeat(32);
    entry.sha256 = flip;
    writeFileSync(manifestPath, `${JSON.stringify(doc, null, 2)}\n`);
    const shaOut = join(dir, 'bad-sha.otlp.json');
    const sha = cli(dir, ['export', '--format', 'otlp', packed.packagePath, '--out', shaOut]);
    assert.equal(sha.code, 2, sha.err + sha.out);
    assert.match(sha.err, /canonical sha256/);
    assert.equal(existsSync(shaOut), false);
    assert.equal(sha.out.includes('wrote'), false);

    const again = JSON.parse(original);
    again.receipts[0].bytes = again.receipts[0].bytes.startsWith('ef') ? '12'.repeat(32) : 'ef'.repeat(32);
    writeFileSync(manifestPath, `${JSON.stringify(again, null, 2)}\n`);
    const bytesOut = join(dir, 'bad-bytes.intoto.jsonl');
    const bytes = cli(dir, ['export', '--format', 'intoto', packed.packagePath, '--out', bytesOut]);
    assert.equal(bytes.code, 2, bytes.err + bytes.out);
    assert.match(bytes.err, /file hash mismatch/);
    assert.equal(existsSync(bytesOut), false);
    assert.equal(bytes.out.includes('wrote'), false);
  });

  it('still writes each export format to a fresh path', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const before = readFileSync(captured.path);
    const html = join(dir, 'fresh.html');
    const md = join(dir, 'fresh.md');
    const otlp = join(dir, 'fresh.otlp.json');
    const intoto = join(dir, 'fresh.intoto.jsonl');
    const htmlRun = cli(dir, ['export', captured.path, '--out', html]);
    const mdRun = cli(dir, ['export', '--format', 'markdown', captured.path, '--out', md]);
    const otlpRun = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', otlp]);
    const intotoRun = cli(dir, ['export', '--format', 'intoto', captured.path, '--out', intoto]);
    assert.equal(htmlRun.code, 0, htmlRun.err);
    assert.equal(mdRun.code, 0, mdRun.err);
    assert.equal(otlpRun.code, 0, otlpRun.err);
    assert.equal(intotoRun.code, 0, intotoRun.err);
    assert.match(readFileSync(html, 'utf8'), /Agent Receipt/);
    assert.match(readFileSync(md, 'utf8'), /## Integrity/);
    assert.equal(JSON.parse(readFileSync(otlp, 'utf8')).resourceSpans.length, 1);
    assert.match(readFileSync(intoto, 'utf8'), /payload/);
    assert.deepEqual(readFileSync(captured.path), before);
  });

  it('refuses a case-variant of the source on a case-insensitive volume', (t) => {
    const dir = gitRepo();
    if (!caseFolds(dir)) {
      t.skip('filesystem is case-sensitive');
      return;
    }
    const captured = capture(dir);
    const before = readFileSync(captured.path);
    const base = basename(captured.path);
    const flipped = base.replace(/[a-z]/i, (ch) => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()));
    if (flipped === base) {
      t.skip('receipt basename has no letters');
      return;
    }
    const variant = join(dirname(captured.path), flipped);
    const result = cli(dir, ['export', captured.path, '--out', variant]);
    assert.equal(result.code, 1, result.err);
    assert.match(result.err, /over the receipt/);
    assert.deepEqual(readFileSync(captured.path), before);
  });

  it('verifies a 12k-node parent chain without overflowing the stack', { timeout: 180000 }, () => {
    const dir = gitRepo();
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    const count = 12000;
    let prev = null;
    const origin = Date.UTC(2026, 0, 1);
    for (let i = 0; i < count; i += 1) {
      const id = `r-${i.toString(16).padStart(16, '0')}`;
      const fields = {
        Id: id,
        Timestamp: new Date(origin + i * 1000).toISOString(),
        Agent: 'chain',
        Session: 'sess-chain',
      };
      if (prev) fields.Parent = prev;
      writeFileSync(join(outDir, `chain-${String(i).padStart(5, '0')}.md`), sealReceipt(linkEraBody(fields)));
      prev = id;
    }
    const result = cli(dir, ['session', 'sess-chain', '--json'], 64 * 1024 * 1024);
    assert.equal(result.code, 0, result.err.slice(0, 800));
    const body = JSON.parse(result.out);
    assert.equal(body.receipts.length, count);
    assert.equal(body.receipts[0].parent, null);
    assert.equal(body.receipts[count - 1].parent, `r-${(count - 2).toString(16).padStart(16, '0')}`);
    assert.equal(body.receipts.some((row) => row.cycle), false);
  });

  it('exports a 2000-member package in under 10 seconds', { timeout: 180000 }, () => {
    const dir = gitRepo();
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    const count = 2000;
    const origin = Date.UTC(2026, 0, 1);
    for (let i = 0; i < count; i += 1) {
      const fields = {
        Id: `r-${i.toString(16).padStart(16, '0')}`,
        Timestamp: new Date(origin + i * 1000).toISOString(),
        Agent: 'bulk',
        Session: 'sess-fast',
      };
      writeFileSync(join(outDir, `fast-${String(i).padStart(5, '0')}.md`), sealReceipt(linkEraBody(fields)));
    }
    const packed = parseJson(
      cli(dir, ['session', 'export', 'sess-fast', '--include-host', '--json'], 64 * 1024 * 1024),
    );
    assert.equal(packed.receiptCount, count);
    const out = join(dir, 'fast.otlp.json');
    const started = Date.now();
    const result = cli(dir, ['export', '--format', 'otlp', packed.packagePath, '--out', out], 64 * 1024 * 1024);
    const elapsed = Date.now() - started;
    assert.equal(result.code, 0, result.err.slice(0, 800));
    assert.ok(elapsed < 10000, `otlp export took ${elapsed}ms`);
    const trace = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(trace.resourceSpans.length, 1);
    assert.equal(result.out.includes('wrote'), true);
  });

  it('refuses --out that would overwrite a local receipt .sig.json sidecar', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const sig = captured.path.replace(/\.md$/i, '.sig.json');
    const beforeMd = readFileSync(captured.path);
    const missing = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', sig]);
    assert.equal(missing.code, 1, missing.err);
    assert.match(missing.err, /signature sidecar/);
    assert.equal(existsSync(sig), false);
    assert.deepEqual(readFileSync(captured.path), beforeMd);
    const body = '{"keep":"sidecar"}\n';
    writeFileSync(sig, body);
    for (const format of ['html', 'markdown', 'otlp', 'intoto']) {
      const result = cli(dir, exportArgs(format, captured.path, sig));
      assert.equal(result.code, 1, `${format}\n${result.err}`);
      assert.match(result.err, /signature sidecar/, format);
      assert.equal(readFileSync(sig, 'utf8'), body, format);
      assert.deepEqual(readFileSync(captured.path), beforeMd, format);
      assert.equal(result.out.includes('wrote') || result.out.includes('Wrote'), false, format);
    }
    const linkdir = join(dir, 'sig-link');
    symlinkSync(dirname(sig), linkdir);
    const via = join(linkdir, basename(sig));
    const linked = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', via]);
    assert.equal(linked.code, 1, linked.err);
    assert.match(linked.err, /signature sidecar/);
    assert.equal(readFileSync(sig, 'utf8'), body);
    assert.equal(lstatSync(sig).isSymbolicLink(), false);
  });

  it('does not follow a pre-existing temp file or symlink', async () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const canary = join(dir, 'canary-secret');
    writeFileSync(canary, 'do-not-follow');

    const otlpOut = join(dir, 'trace.otlp.json');
    const otlpLink = join(dirname(otlpOut), `.${basename(otlpOut)}.${process.pid}.tmp`);
    symlinkSync(canary, otlpLink);
    const otlpFile = join(dirname(otlpOut), `.${basename(otlpOut)}.tmp`);
    writeFileSync(otlpFile, 'keep-file');
    assert.equal(cmdOtlpExport(dir, captured.path, { out: otlpOut }), 0);
    assert.equal(readFileSync(canary, 'utf8'), 'do-not-follow');
    assert.equal(readFileSync(otlpFile, 'utf8'), 'keep-file');
    assert.equal(lstatSync(otlpLink).isSymbolicLink(), true);
    assert.equal(readlinkSync(otlpLink), canary);
    assert.equal(lstatSync(otlpOut).isSymbolicLink(), false);
    assert.match(readFileSync(otlpOut, 'utf8'), /resourceSpans/);

    const intotoOut = join(dir, 'trace.intoto.jsonl');
    const intotoLink = join(dirname(intotoOut), `.${basename(intotoOut)}.${process.pid}.tmp`);
    symlinkSync(canary, intotoLink);
    const intotoFile = join(dirname(intotoOut), `.${basename(intotoOut)}.tmp`);
    writeFileSync(intotoFile, 'keep-intoto');
    assert.equal(await cmdAttest(dir, captured.path, { out: intotoOut }), 0);
    assert.equal(readFileSync(canary, 'utf8'), 'do-not-follow');
    assert.equal(readFileSync(intotoFile, 'utf8'), 'keep-intoto');
    assert.equal(lstatSync(intotoLink).isSymbolicLink(), true);
    assert.equal(readlinkSync(intotoLink), canary);
    assert.equal(lstatSync(intotoOut).isSymbolicLink(), false);
    assert.match(readFileSync(intotoOut, 'utf8'), /payload/);

    const names = readdirSync(dir);
    assert.equal(
      names.some((name) => name.endsWith('.tmp') && name !== basename(otlpLink) && name !== basename(otlpFile) && name !== basename(intotoLink) && name !== basename(intotoFile)),
      false,
    );

    assert.throws(() => writeExclusiveTemp(otlpLink, join(dir, 'should-not-write.json'), 'pwned'));
    assert.equal(readFileSync(canary, 'utf8'), 'do-not-follow');
    assert.equal(lstatSync(otlpLink).isSymbolicLink(), true);
    assert.equal(existsSync(join(dir, 'should-not-write.json')), false);
    assert.throws(() => writeExclusiveTemp(otlpFile, join(dir, 'should-not-write.json'), 'pwned'));
    assert.equal(readFileSync(otlpFile, 'utf8'), 'keep-file');
    assert.equal(existsSync(join(dir, 'should-not-write.json')), false);

    const blocked = join(dir, 'blocked-dir');
    mkdirSync(blocked);
    assert.throws(() => writeExclusiveFile(blocked, 'hello'));
    assert.equal(lstatSync(blocked).isDirectory(), true);
    assert.equal(
      readdirSync(dir).some((name) => name.startsWith('.blocked-dir.') && name.endsWith('.tmp')),
      false,
    );
  });

  it('refuses HTML and Markdown --out newdir/ instead of writing a file', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const before = readFileSync(captured.path);
    for (const format of ['html', 'markdown']) {
      const dest = join(dir, `newdir-${format}`);
      const result = cli(dir, exportArgs(format, captured.path, `${dest}/`));
      assert.equal(result.code, 1, `${format}\n${result.err}`);
      assert.match(result.err, /not a directory/, format);
      assert.equal(existsSync(dest), false, format);
      assert.deepEqual(readFileSync(captured.path), before, format);
    }
  });

  it('refuses --out that would overwrite a share package manifest.json', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const shared = parseJson(cli(dir, ['share', captured.path, '--package', '--json']));
    const manifestPath = join(shared.packagePath, 'manifest.json');
    const before = readFileSync(manifestPath);
    const fromLocal = cli(dir, ['export', '--format', 'otlp', 'last', '--out', manifestPath]);
    assert.equal(fromLocal.code, 1, fromLocal.err + fromLocal.out);
    assert.match(fromLocal.err, /share package file: manifest\.json/);
    assert.deepEqual(readFileSync(manifestPath), before);
    assert.equal(fromLocal.out.includes('wrote'), false);
    const fromPacked = cli(dir, [
      'export',
      join(shared.packagePath, 'receipt.md'),
      '--out',
      manifestPath,
    ]);
    assert.equal(fromPacked.code, 1, fromPacked.err + fromPacked.out);
    assert.match(fromPacked.err, /share package file: manifest\.json/);
    assert.deepEqual(readFileSync(manifestPath), before);
    const sigPath = join(shared.packagePath, 'manifest.sig.json');
    assert.equal(existsSync(sigPath), true);
    const sigBefore = readFileSync(sigPath);
    const overSig = cli(dir, ['export', '--format', 'otlp', 'last', '--out', sigPath]);
    assert.equal(overSig.code, 1, overSig.err + overSig.out);
    assert.match(overSig.err, /share package file: manifest\.sig\.json/);
    assert.deepEqual(readFileSync(sigPath), sigBefore);
    const linkdir = join(dir, 'share-link');
    symlinkSync(shared.packagePath, linkdir);
    const via = join(linkdir, 'manifest.json');
    const linked = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', via]);
    assert.equal(linked.code, 1, linked.err + linked.out);
    assert.match(linked.err, /share package file: manifest\.json/);
    assert.deepEqual(readFileSync(manifestPath), before);
  });

  it('refuses last --out that names another receipt companion .json', () => {
    const dir = gitRepo();
    const first = capture(dir);
    const second = capture(dir, ['--message', 'second']);
    const past = new Date(Date.now() - 120_000);
    utimesSync(first.path, past, past);
    utimesSync(second.path, new Date(), new Date());
    const latest = cli(dir, ['last', '--path']);
    assert.equal(latest.code, 0, latest.err);
    assert.equal(latest.out.trim(), second.path);
    const otherJson = first.path.replace(/\.md$/i, '.json');
    assert.equal(existsSync(otherJson), true);
    const before = readFileSync(otherJson);
    const result = cli(dir, ['export', '--format', 'otlp', 'last', '--out', otherJson]);
    assert.equal(result.code, 1, result.err + result.out);
    assert.match(result.err, /companion \.json/);
    assert.deepEqual(readFileSync(otherJson), before);
    assert.equal(result.out.includes('wrote'), false);
    const own = second.path.replace(/\.md$/i, '.json');
    const ownBefore = readFileSync(own);
    const overOwn = cli(dir, ['export', '--format', 'otlp', 'last', '--out', own]);
    assert.equal(overOwn.code, 1, overOwn.err + overOwn.out);
    assert.match(overOwn.err, /companion \.json/);
    assert.deepEqual(readFileSync(own), ownBefore);
  });
});
