/**
 * v1.0.42 --out guard follow-ups.
 * Case-folded share package names, other receipts' companions, and
 * plain README.json next to README.md.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertWritableOutFile, OutGuardError } from '../dist/lib/out-guard.js';

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
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1042-')));
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

function refusal(err, pattern) {
  assert.ok(err instanceof OutGuardError);
  assert.equal(err.exitCode, 1);
  assert.match(err.message, pattern);
  return true;
}

describe('v1.0.42 --out guard follow-ups', () => {
  it('refuses case-folded share manifest names when the volume folds', () => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'ar1042-share-')));
    const share = join(dir, 'demo.share');
    mkdirSync(share);
    const manifest = join(share, 'manifest.json');
    const sig = join(share, 'manifest.sig.json');
    writeFileSync(manifest, '{"keep":"manifest"}\n');
    writeFileSync(sig, '{"keep":"sig"}\n');
    const beforeManifest = readFileSync(manifest);
    const beforeSig = readFileSync(sig);

    assert.throws(
      () => assertWritableOutFile(join(share, 'MANIFEST.JSON'), { foldsCase: true }),
      (err) => refusal(err, /refusing to write over a share package file: MANIFEST\.JSON/),
    );
    assert.throws(
      () => assertWritableOutFile(join(share, 'MANIFEST.SIG.JSON'), { foldsCase: true }),
      (err) => refusal(err, /refusing to write over a share package file: MANIFEST\.SIG\.JSON/),
    );
    assert.deepEqual(readFileSync(manifest), beforeManifest);
    assert.deepEqual(readFileSync(sig), beforeSig);
    assert.equal(existsSync(join(share, 'MANIFEST.JSON')), false);
    assert.equal(existsSync(join(share, 'MANIFEST.SIG.JSON')), false);

    assert.doesNotThrow(() => assertWritableOutFile(join(share, 'MANIFEST.JSON'), { foldsCase: false }));
    assert.doesNotThrow(() => assertWritableOutFile(join(share, 'MANIFEST.SIG.JSON'), { foldsCase: false }));
    if (!caseFolds(share)) {
      assert.doesNotThrow(() => assertWritableOutFile(join(share, 'MANIFEST.SIG.JSON')));
    }
    assert.equal(existsSync(join(share, 'MANIFEST.JSON')), false);

    assert.throws(
      () => assertWritableOutFile(manifest),
      (err) => refusal(err, /refusing to write over a share package file: manifest\.json/),
    );
    assert.throws(
      () => assertWritableOutFile(sig),
      (err) => refusal(err, /refusing to write over a share package file: manifest\.sig\.json/),
    );
    assert.deepEqual(readFileSync(manifest), beforeManifest);
    assert.deepEqual(readFileSync(sig), beforeSig);

    const missing = join(dir, 'nowhere.share', 'manifest.json');
    assert.throws(
      () => assertWritableOutFile(missing),
      (err) => refusal(err, /refusing to write over a share package file: manifest\.json/),
    );
    assert.equal(existsSync(join(dir, 'nowhere.share')), false);
    assert.doesNotThrow(() => assertWritableOutFile(join(dir, 'MANIFEST.JSON'), { foldsCase: true }));
  });

  it('refuses a hardlinked case-variant of the share manifest by inode', (t) => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'ar1042-link-')));
    const share = join(dir, 'demo.share');
    mkdirSync(share);
    const manifest = join(share, 'manifest.json');
    writeFileSync(manifest, '{"keep":"manifest"}\n');
    const before = readFileSync(manifest);
    const alias = join(share, 'MANIFEST.JSON');
    try {
      linkSync(manifest, alias);
    } catch (err) {
      t.skip(`cannot hardlink a case variant (${err.code || err.message})`);
      return;
    }
    assert.throws(
      () => assertWritableOutFile(alias),
      (err) => refusal(err, /refusing to write over a share package file: MANIFEST\.JSON/),
    );
    assert.deepEqual(readFileSync(manifest), before);
    assert.deepEqual(readFileSync(alias), before);
  });

  it('refuses MANIFEST.JSON on a case-folding filesystem', (t) => {
    const dir = gitRepo();
    if (!caseFolds(dir)) {
      t.skip('filesystem is case-sensitive');
      return;
    }
    const captured = capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const shared = parseJson(cli(dir, ['share', captured.path, '--package', '--json']));
    const manifest = join(shared.packagePath, 'manifest.json');
    const sig = join(shared.packagePath, 'manifest.sig.json');
    const beforeManifest = readFileSync(manifest);
    const beforeSig = readFileSync(sig);
    const overManifest = cli(dir, ['export', '--format', 'otlp', 'last', '--out', join(shared.packagePath, 'MANIFEST.JSON')]);
    assert.equal(overManifest.code, 1, overManifest.err + overManifest.out);
    assert.match(overManifest.err, /share package file: MANIFEST\.JSON/);
    assert.equal(overManifest.out.includes('wrote') || overManifest.out.includes('Wrote'), false);
    assert.deepEqual(readFileSync(manifest), beforeManifest);
    const overSig = cli(dir, ['export', '--format', 'otlp', 'last', '--out', join(shared.packagePath, 'MANIFEST.SIG.JSON')]);
    assert.equal(overSig.code, 1, overSig.err + overSig.out);
    assert.match(overSig.err, /share package file: MANIFEST\.SIG\.JSON/);
    assert.deepEqual(readFileSync(sig), beforeSig);
  });

  it('refuses --out onto another receipt .md and .sig.json', () => {
    const dir = gitRepo();
    const first = capture(dir);
    const second = capture(dir, ['--message', 'second']);
    const past = new Date(Date.now() - 120_000);
    utimesSync(first.path, past, past);
    utimesSync(second.path, new Date(), new Date());
    const latest = cli(dir, ['last', '--path']);
    assert.equal(latest.out.trim(), second.path);
    const beforeMd = readFileSync(first.path);
    const sig = first.path.replace(/\.md$/i, '.sig.json');
    const sigBody = '{"keep":"sidecar"}\n';
    writeFileSync(sig, sigBody);
    for (const format of ['otlp', 'html']) {
      const overMd = cli(dir, exportArgs(format, second.path, first.path));
      assert.equal(overMd.code, 1, `${format}\n${overMd.err}${overMd.out}`);
      assert.match(overMd.err, /over the receipt/, format);
      assert.equal(overMd.out.includes('wrote') || overMd.out.includes('Wrote'), false, format);
      assert.deepEqual(readFileSync(first.path), beforeMd, format);
      const overSig = cli(dir, exportArgs(format, second.path, sig));
      assert.equal(overSig.code, 1, `${format}\n${overSig.err}${overSig.out}`);
      assert.match(overSig.err, /signature sidecar/, format);
      assert.equal(readFileSync(sig, 'utf8'), sigBody, format);
      assert.deepEqual(readFileSync(first.path), beforeMd, format);
    }
  });

  it('refuses --out onto a share receipt.md and receipt.sig.json', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const shared = parseJson(cli(dir, ['share', captured.path, '--package', '--json']));
    const receiptMd = join(shared.packagePath, 'receipt.md');
    const receiptSig = join(shared.packagePath, 'receipt.sig.json');
    assert.equal(existsSync(receiptMd), true);
    assert.equal(existsSync(receiptSig), true);
    const beforeMd = readFileSync(receiptMd);
    const beforeSig = readFileSync(receiptSig);
    const overMd = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', receiptMd]);
    assert.equal(overMd.code, 1, overMd.err + overMd.out);
    assert.match(overMd.err, /share package file: receipt\.md/);
    assert.equal(overMd.out.includes('wrote'), false);
    assert.deepEqual(readFileSync(receiptMd), beforeMd);
    const overSig = cli(dir, ['export', '--format', 'html', captured.path, '--out', receiptSig]);
    assert.equal(overSig.code, 1, overSig.err + overSig.out);
    assert.match(overSig.err, /share package file: receipt\.sig\.json/);
    assert.equal(overSig.out.includes('Wrote'), false);
    assert.deepEqual(readFileSync(receiptSig), beforeSig);
    assert.deepEqual(readFileSync(receiptMd), beforeMd);
  });

  it('writes README.json next to a plain README.md', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const beforeReceipt = readFileSync(captured.path);
    const receipts = dirname(captured.path);
    const readme = join(receipts, 'README.md');
    const readmeBody = '# notes\n\nNot a receipt.\n';
    writeFileSync(readme, readmeBody);
    const out = join(receipts, 'README.json');
    const result = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', out]);
    assert.equal(result.code, 0, result.err + result.out);
    assert.equal(existsSync(out), true);
    assert.ok(readFileSync(out).length > 0);
    assert.equal(readFileSync(readme, 'utf8'), readmeBody);
    assert.deepEqual(readFileSync(captured.path), beforeReceipt);

    const rootCopy = join(dir, 'note.md');
    writeFileSync(rootCopy, beforeReceipt);
    const rootOut = join(dir, 'README.json');
    const rootResult = cli(dir, ['export', '--format', 'html', rootCopy, '--out', rootOut]);
    assert.equal(rootResult.code, 0, rootResult.err + rootResult.out);
    assert.ok(readFileSync(rootOut).length > 0);
    assert.equal(readFileSync(join(dir, 'README.md'), 'utf8'), '# guard\n');
    assert.deepEqual(readFileSync(rootCopy), beforeReceipt);
    assert.deepEqual(readFileSync(captured.path), beforeReceipt);
  });

  it('writes a fresh --out for each export format', () => {
    const dir = gitRepo();
    const captured = capture(dir);
    const before = readFileSync(captured.path);
    for (const format of ['html', 'markdown', 'otlp', 'intoto']) {
      const out = join(dir, `fresh-${format}.out`);
      const result = cli(dir, exportArgs(format, captured.path, out));
      assert.equal(result.code, 0, `${format}\n${result.err}${result.out}`);
      assert.equal(existsSync(out), true, format);
      assert.ok(readFileSync(out).length > 0, format);
      assert.deepEqual(readFileSync(captured.path), before, format);
    }
  });

  it('refuses a missing companion through a bind-mounted parent', (t) => {
    const dir = gitRepo();
    const captured = capture(dir);
    const sig = captured.path.replace(/\.md$/i, '.sig.json');
    if (existsSync(sig)) rmSync(sig);
    const before = readFileSync(captured.path);
    const mountPoint = join(dir, 'bound');
    mkdirSync(mountPoint);
    const mount = spawnSync('mount', ['--bind', dirname(captured.path), mountPoint], { encoding: 'utf8' });
    if (mount.status !== 0) {
      t.skip('bind mount is not permitted');
      return;
    }
    try {
      const via = join(mountPoint, basename(sig));
      const result = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', via]);
      assert.equal(result.code, 1, result.err + result.out);
      assert.match(result.err, /signature sidecar/);
      assert.equal(existsSync(sig), false);
      assert.equal(existsSync(via), false);
      assert.deepEqual(readFileSync(captured.path), before);
      assert.equal(result.out.includes('wrote'), false);
    } finally {
      spawnSync('umount', [mountPoint]);
    }
  });
});
