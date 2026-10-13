/**
 * v1.0.43 — share-file identity, one manifest read per package,
 * long-s / dotless-i fold, and a fenced hash marker.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  appendHashFooter,
  canonicalBody,
  hasTrailingAfterIntegrity,
  verifyMarkdown,
} from '../dist/lib/hash.js';
import {
  OutGuardError,
  assertProtectedOut,
  assertWritableOutFile,
} from '../dist/lib/out-guard.js';
import {
  exportProtectedPaths,
  inspectSessionManifestSignature,
  loadSessionManifest,
  resetSessionManifestReads,
  sessionManifestReadCount,
  sessionManifestSha256,
} from '../dist/lib/session-package.js';
import { sha256FileBytes } from '../dist/lib/share-package.js';
import { cmdOtlpExport } from '../dist/commands/otlp.js';
import { cmdAttest } from '../dist/commands/attest.js';
import { cmdReport } from '../dist/commands/report.js';

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
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1043-')));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# identity\n');
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

function exportArgs(format, source, out) {
  const args = ['export', source, '--out', out];
  if (format !== 'html') args.push('--format', format);
  return args;
}

function refusal(err, pattern) {
  assert.ok(err instanceof OutGuardError);
  assert.equal(err.exitCode, 1);
  assert.match(err.message, pattern);
  return true;
}

const HASH = 'ab'.repeat(32);

describe('v1.0.43 share identity', () => {
  it('refuses a hardlink alias of each share package file and still writes a fresh --out', (t) => {
    const dir = gitRepo();
    const captured = capture(dir);
    const sourceBefore = readFileSync(captured.path);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const shared = parseJson(cli(dir, ['share', captured.path, '--package', '--json']));
    const names = ['receipt.md', 'receipt.sig.json', 'manifest.json', 'manifest.sig.json'];
    for (const name of names) {
      const src = join(shared.packagePath, name);
      assert.equal(existsSync(src), true, name);
      const before = readFileSync(src);
      const alias = join(dir, `alias-${name}`);
      try {
        linkSync(src, alias);
      } catch (err) {
        t.skip(`hardlinks are unsupported (${err.code || err.message})`);
        return;
      }
      for (const format of ['html', 'markdown', 'otlp', 'intoto']) {
        const result = cli(dir, exportArgs(format, captured.path, alias));
        assert.equal(result.code, 1, `${format} ${name}\n${result.err}${result.out}`);
        assert.match(result.err, /share package file/, `${format} ${name}`);
        assert.equal(
          result.out.includes('wrote') || result.out.includes('Wrote'),
          false,
          `${format} ${name}`,
        );
        assert.deepEqual(readFileSync(src), before, `${format} ${name}`);
        assert.deepEqual(readFileSync(alias), before, `${format} ${name}`);
        assert.deepEqual(readFileSync(captured.path), sourceBefore, `${format} ${name}`);
      }
    }

    for (const format of ['html', 'markdown', 'otlp', 'intoto']) {
      const ext = { html: '.html', markdown: '.md', otlp: '.otlp.json', intoto: '.intoto.jsonl' };
      const out = join(dir, `fresh-${format}${ext[format]}`);
      const result = cli(dir, exportArgs(format, captured.path, out));
      assert.equal(result.code, 0, `${format}\n${result.err}${result.out}`);
      assert.equal(existsSync(out), true, format);
      assert.deepEqual(readFileSync(captured.path), sourceBefore, format);
    }
  });

  it('still refreshes receipt.md inside the share package', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const first = parseJson(cli(dir, ['share', captured.path, '--package', '--json']));
    const receiptMd = join(first.packagePath, 'receipt.md');
    assert.equal(existsSync(receiptMd), true);
    const again = cli(dir, ['share', captured.path, '--package', '--json']);
    assert.equal(again.code, 0, again.err + again.out);
    assert.ok(readFileSync(receiptMd).length > 0);
    const verified = cli(dir, ['verify', '--package', first.packagePath]);
    assert.equal(verified.code, 0, verified.err + verified.out);
  });

  it('refuses long s and dotless i when the volume folds case', () => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'ar1043-fold-')));
    const share = join(dir, 'demo.share');
    mkdirSync(share);
    const manifest = join(share, 'manifest.json');
    const receipt = join(share, 'receipt.md');
    writeFileSync(manifest, '{"keep":"manifest"}\n');
    writeFileSync(receipt, 'keep-receipt\n');
    const beforeManifest = readFileSync(manifest);
    const beforeReceipt = readFileSync(receipt);
    const longS = join(share, 'manife\u017ft.json');
    const longSExt = join(share, 'manifest.j\u017fon');
    const dotless = join(share, 'rece\u0131pt.md');

    assert.throws(
      () => assertWritableOutFile(longS, { foldsCase: true }),
      (err) => refusal(err, /share package file: manife\u017ft\.json/),
    );
    assert.throws(
      () => assertWritableOutFile(longSExt, { foldsCase: true }),
      (err) => refusal(err, /share package file: manifest\.j\u017fon/),
    );
    assert.throws(
      () => assertWritableOutFile(dotless, { foldsCase: true }),
      (err) => refusal(err, /share package file: rece\u0131pt\.md/),
    );
    assert.deepEqual(readFileSync(manifest), beforeManifest);
    assert.deepEqual(readFileSync(receipt), beforeReceipt);
    assert.equal(existsSync(longS), false);
    assert.equal(existsSync(longSExt), false);
    assert.equal(existsSync(dotless), false);

    assert.doesNotThrow(() => assertWritableOutFile(longS, { foldsCase: false }));
    assert.doesNotThrow(() => assertWritableOutFile(dotless, { foldsCase: false }));

    const md = join(dir, 'foo.md');
    writeFileSync(
      md,
      '# Agent Receipt\n\n## Session\n\n- **Version**: 1.0.43\n',
    );
    const json = join(dir, 'foo.json');
    writeFileSync(
      json,
      `{"version":"1","integrity":{"algorithm":"sha256","sha256":"${HASH}"}}\n`,
    );
    const beforeJson = readFileSync(json);
    const foldedJson = join(dir, 'foo.j\u017fon');
    const protectedPaths = exportProtectedPaths(dir, [md], { companionJson: true });
    assert.throws(
      () => assertProtectedOut(foldedJson, protectedPaths, 'export', { foldsCase: true }),
      (err) => refusal(err, /companion \.json/),
    );
    assert.deepEqual(readFileSync(json), beforeJson);
    assert.equal(existsSync(foldedJson), false);
    assert.doesNotThrow(() =>
      assertProtectedOut(foldedJson, protectedPaths, 'export', { foldsCase: false }),
    );
  });

  it('keeps a fenced hash marker and does not protect a fenced README.json', () => {
    const outside = `before\n<!-- agent-receipt-sha256: ${HASH} -->\nafter\n`;
    const cut = canonicalBody(outside);
    assert.match(cut, /before/);
    assert.equal(cut.includes('after'), false);

    const quoted = [
      '# Agent Receipt',
      '',
      '```',
      `<!-- agent-receipt-sha256: ${HASH} -->`,
      'SENTINEL',
      '```',
      '',
      '## Session',
      '',
      '- **Version**: 1.0.43',
      '',
    ].join('\n');
    const sealed = appendHashFooter(quoted);
    assert.match(sealed, /SENTINEL/);
    assert.match(canonicalBody(sealed), /SENTINEL/);
    assert.equal(canonicalBody(sealed).includes('## Integrity'), false);
    const check = verifyMarkdown(sealed);
    assert.equal(check.ok, true, check.reason);
    assert.equal(check.trailingIgnored, false);
    assert.equal(hasTrailingAfterIntegrity(sealed), false);

    const dir = gitRepo();
    writeFileSync(join(dir, 'quoted.txt'), `<!-- agent-receipt-sha256: ${HASH} -->\nSENTINEL-KEEP\n`);
    git(dir, ['add', 'quoted.txt']);
    git(dir, ['commit', '-m', 'quote the marker']);
    const captured = capture(dir);
    const text = readFileSync(captured.path, 'utf8');
    assert.match(text, /SENTINEL-KEEP/);
    assert.match(text, /## Integrity/);
    const verified = cli(dir, ['verify', captured.path]);
    assert.equal(verified.code, 0, verified.err + verified.out);
    const sourceBefore = readFileSync(captured.path);
    const fresh = join(dir, 'fresh-fenced.html');
    const exported = cli(dir, ['export', captured.path, '--out', fresh]);
    assert.equal(exported.code, 0, exported.err + exported.out);
    assert.equal(existsSync(fresh), true);
    assert.deepEqual(readFileSync(captured.path), sourceBefore);

    const readme = join(dirname(captured.path), 'README.md');
    writeFileSync(
      readme,
      [
        '# Notes',
        '',
        '```',
        '# Agent Receipt',
        '',
        '## Session',
        '',
        '- **Version**: 1.0.43',
        '',
        `<!-- agent-receipt-sha256: ${HASH} -->`,
        '```',
        '',
      ].join('\n'),
    );
    const readmeBefore = readFileSync(readme);
    const readmeJson = join(dirname(captured.path), 'README.json');
    const otlp = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', readmeJson]);
    assert.equal(otlp.code, 0, otlp.err + otlp.out);
    assert.equal(existsSync(readmeJson), true);
    assert.deepEqual(readFileSync(readme), readmeBefore);
    assert.deepEqual(readFileSync(captured.path), sourceBefore);
  });

  it('verifies capture --since base of an edit inside a fenced doc.md block', () => {
    const dir = gitRepo();
    const doc = [
      '# Notes',
      '',
      '```js',
      'const value = "before";',
      '```',
      '',
      'tail',
      '',
    ].join('\n');
    writeFileSync(join(dir, 'doc.md'), doc);
    git(dir, ['add', 'doc.md']);
    git(dir, ['commit', '-m', 'add fenced doc']);
    git(dir, ['tag', 'base']);
    writeFileSync(
      join(dir, 'doc.md'),
      doc.replace('const value = "before";', 'const value = "after-fence";'),
    );
    git(dir, ['add', 'doc.md']);
    git(dir, ['commit', '-m', 'edit inside the fence']);
    const captured = parseJson(
      cli(dir, ['capture', '--since', 'base', '--json', '--agent', 'cursor']),
    );
    const text = readFileSync(captured.path, 'utf8');
    assert.match(text, /after-fence/);
    assert.match(text, /```diff/);
    assert.match(text, /^ ```$/m);
    assert.match(text, /## Integrity/);
    assert.match(text, /\btail\b/);
    const verified = cli(dir, ['verify', captured.path]);
    assert.equal(verified.code, 0, verified.err + verified.out);
  });

  it('counts every session-manifest load once per package, including a cache hit', async () => {
    const sessionSrc = readFileSync(join(root, 'src/lib/session-package.ts'), 'utf8');
    const reportSrc = readFileSync(join(root, 'src/commands/report.ts'), 'utf8');
    assert.equal(sessionSrc.includes('sha256FileBytes('), false);
    assert.equal(reportSrc.includes('sha256FileBytes'), false);

    const dir = gitRepo();
    capture(dir, ['--session', 'sess-1043']);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const packed = parseJson(
      cli(dir, ['session', 'export', 'sess-1043', '--include-host', '--json']),
    );
    const manifestPath = join(packed.packagePath, 'session-manifest.json');
    assert.equal(existsSync(manifestPath), true);
    assert.equal(existsSync(join(packed.packagePath, 'session-manifest.sig.json')), true);

    resetSessionManifestReads();
    assert.equal(cmdOtlpExport(dir, packed.packagePath, { out: join(dir, 'once.otlp.json') }), 0);
    assert.equal(sessionManifestReadCount(), 1);

    resetSessionManifestReads();
    assert.equal(
      await cmdAttest(dir, packed.packagePath, { noSign: true, out: join(dir, 'once.intoto.jsonl') }),
      0,
    );
    assert.equal(sessionManifestReadCount(), 1);

    resetSessionManifestReads();
    assert.equal(cmdReport(dir, packed.packagePath, { json: true, out: join(dir, 'once.report.html') }), 0);
    assert.equal(sessionManifestReadCount(), 1);

    resetSessionManifestReads();
    const loaded = loadSessionManifest(manifestPath);
    assert.equal(sessionManifestReadCount(), 1);
    assert.equal(loadSessionManifest(manifestPath), loaded);
    const disk = createHash('sha256').update(readFileSync(manifestPath)).digest('hex');
    assert.equal(sessionManifestSha256(manifestPath), disk);
    const inspected = inspectSessionManifestSignature(packed.packagePath);
    assert.equal(inspected.present, true);
    assert.equal(inspected.ok, true, inspected.reason);
    assert.equal(sessionManifestReadCount(), 1);

    sha256FileBytes(manifestPath);
    assert.equal(sessionManifestReadCount(), 2);
  });
});
