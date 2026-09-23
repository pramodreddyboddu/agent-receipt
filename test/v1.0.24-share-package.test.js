import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifySignature } from '../dist/lib/sign.js';
import { listReceiptFiles } from '../dist/lib/retention.js';
import { isInsideSharePackage, isSharePackageDirName } from '../dist/lib/receipt.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cliResult(cwd, args) {
  const r = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    code: r.status === null ? 1 : r.status,
    out: r.stdout || '',
    err: r.stderr || '',
  };
}

function cli(cwd, args) {
  const r = cliResult(cwd, args);
  if (r.code !== 0) throw new Error(`exit ${r.code}\n${r.out}\n${r.err}`);
  return r.out;
}

function parseJson(out) {
  return JSON.parse(out);
}

function fileSha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function auditEvents(dir) {
  const path = join(dir, '.agent-receipt', 'audit.jsonl');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

describe('v1.0.24 share package', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1024-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# share-package\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function wrapClean(dir, message) {
    writeFileSync(join(dir, 'note.txt'), `${message}\n`);
    git(dir, ['add', 'note.txt']);
    git(dir, ['commit', '-m', message]);
    const wrapped = cliResult(dir, ['wrap', '--agent', 'ci', '--message', message, '--json']);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    return parseJson(wrapped.out);
  }

  it('documents version 1.0.24, share --package, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.24\]/);
    assert.match(changelog, /share --package/);
    assert.match(changelog, /manifest\.json/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    assert.match(changelog, /not a CA/i);
    assert.match(changelog, /prove --html/);
    assert.match(changelog, /background deleter/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.24');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.24');
    assert.equal(lock.packages[''].version, '1.0.24');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.24/);

    const help = cli(root, ['help', 'share']);
    assert.match(help, /share --package/);
    assert.match(help, /--pack/);
    assert.match(help, /receipt\.html/);
    assert.match(help, /receipt\.md/);
    assert.match(help, /manifest\.sig\.json/);
    assert.match(help, /unsigned/i);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /share --package/);
    assert.match(business, /1\.0\.24/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.24/);
    assert.match(mirror, /share --package/);
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'share-package.schema.json'), 'utf8'));
    assert.equal(schema.properties.kind.const, 'agent-receipt-share');
    const gateSchema = JSON.parse(readFileSync(join(root, 'docs', 'gate.schema.json'), 'utf8'));
    assert.equal(gateSchema.required.includes('packagePath'), false);
    assert.equal(typeof gateSchema.properties.packagePath, 'object');

    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /share --package/);
      assert.doesNotMatch(live, /v1\.0\.24/);
    }
  });

  it('ignores paths inside a *.share directory', () => {
    assert.equal(isSharePackageDirName('foo.share'), true);
    assert.equal(isSharePackageDirName('foo.md'), false);
    assert.equal(isSharePackageDirName('manifest.json'), false);
    assert.equal(
      isInsideSharePackage('/repo/.agent-receipt/receipts/foo.share/receipt.md'),
      true,
    );
    assert.equal(
      isInsideSharePackage('/repo/.agent-receipt/receipts/foo.share/manifest.json'),
      true,
    );
    assert.equal(isInsideSharePackage('/repo/.agent-receipt/receipts/foo.md'), false);
  });

  it('share --package writes receipt.md, receipt.html, and manifest.json', () => {
    const dir = initRepo();
    const wrapped = wrapClean(dir, 'package-basic');
    const before = auditEvents(dir);
    const human = cliResult(dir, ['share', '--package']);
    assert.equal(human.code, 0, human.out + human.err);
    assert.match(human.out, /package:/);
    assert.match(human.out, /verify --require-sig/);
    assert.match(human.out, /receipt\.md/);

    const shared = cliResult(dir, ['share', '--package', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.command, 'share');
    assert.equal(gate.ok, true);
    assert.equal(gate.redacted, true);
    assert.equal(typeof gate.packagePath, 'string');
    assert.equal(basename(gate.packagePath), `${basename(wrapped.path).replace(/\.md$/i, '')}.share`);
    assert.equal(gate.htmlPath, join(gate.packagePath, 'receipt.html'));
    assert.equal(gate.markdownPath, join(gate.packagePath, 'receipt.md'));
    assert.equal(gate.sigPath, null);
    assert.equal(existsSync(gate.htmlPath), true);
    assert.equal(existsSync(gate.markdownPath), true);
    assert.equal(existsSync(join(gate.packagePath, 'manifest.json')), true);
    assert.equal(existsSync(join(gate.packagePath, 'receipt.sig.json')), false);
    assert.equal(existsSync(join(gate.packagePath, 'receipt.html.sig.json')), false);

    const manifest = JSON.parse(readFileSync(join(gate.packagePath, 'manifest.json'), 'utf8'));
    assert.equal(manifest.kind, 'agent-receipt-share');
    assert.equal(manifest.version, 1);
    assert.equal(manifest.cliVersion, '1.0.24');
    assert.equal(manifest.redacted, true);
    assert.equal(manifest.signed, false);
    assert.equal(manifest.fingerprint, null);
    assert.equal(manifest.sha256, gate.sha256);
    assert.equal(manifest.files['receipt.md'], fileSha256(gate.markdownPath));
    assert.equal(manifest.files['receipt.html'], fileSha256(gate.htmlPath));
    assert.equal(manifest.files['receipt.sig.json'], undefined);

    const checked = cliResult(dir, ['verify', gate.markdownPath]);
    assert.equal(checked.code, 0, checked.out + checked.err);

    const added = auditEvents(dir).slice(before.length);
    assert.ok(added.length >= 1);
    assert.ok(added.every((event) => event.event === 'share'));
    assert.equal(added.some((event) => event.event === 'export'), false);
  });

  it('with keygen, signs receipt.md and manifest and verify --require-sig passes', () => {
    const dir = initRepo();
    wrapClean(dir, 'package-signed');
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const shared = cliResult(dir, ['share', '--pack', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(typeof gate.packagePath, 'string');
    assert.equal(gate.sigPath, join(gate.packagePath, 'receipt.sig.json'));
    assert.equal(existsSync(gate.sigPath), true);
    assert.doesNotMatch(readFileSync(gate.sigPath, 'utf8'), /PRIVATE KEY/);
    assert.equal(existsSync(join(gate.packagePath, 'manifest.sig.json')), true);
    assert.equal(existsSync(join(gate.packagePath, 'receipt.html.sig.json')), false);

    const manifest = JSON.parse(readFileSync(join(gate.packagePath, 'manifest.json'), 'utf8'));
    assert.equal(manifest.signed, true);
    assert.equal(manifest.fingerprint, keys.fingerprint);
    assert.equal(manifest.files['receipt.sig.json'], fileSha256(gate.sigPath));
    assert.equal(manifest.sha256, gate.sha256);

    const manifestPath = join(gate.packagePath, 'manifest.json');
    const manifestSig = JSON.parse(readFileSync(join(gate.packagePath, 'manifest.sig.json'), 'utf8'));
    const manifestCheck = verifySignature(manifestSig, fileSha256(manifestPath));
    assert.equal(manifestCheck.ok, true, manifestCheck.reason || '');
    assert.equal(manifestSig.fingerprint, keys.fingerprint);
    assert.doesNotMatch(readFileSync(join(gate.packagePath, 'manifest.sig.json'), 'utf8'), /PRIVATE KEY/);

    const checked = cliResult(dir, ['verify', '--require-sig', gate.markdownPath, '--json']);
    assert.equal(checked.code, 0, checked.out + checked.err);
    const body = parseJson(checked.out);
    assert.equal(body.signature.ok, true);
    assert.equal(body.signature.fingerprint, keys.fingerprint);

    const last = parseJson(cli(dir, ['last', '--json']));
    assert.equal(last.path.includes('.share'), false);
    const history = parseJson(cli(dir, ['history', '--json']));
    assert.ok(Array.isArray(history));
    assert.ok(history.every((row) => !String(row.path).includes('.share/')));
    const listed = listReceiptFiles(dir);
    assert.ok(listed.every((file) => !file.rel.includes('.share')));
    const pruned = parseJson(cli(dir, ['prune', '--dry-run', '--json']));
    assert.ok(pruned.deleted.every((row) => !String(row.path || row.rel || '').includes('.share')));
  });

  it('redact rewrite without keys writes html and md and leaves no stale sidecar', () => {
    const dir = initRepo();
    wrapClean(dir, 'package-nokeys');
    cli(dir, ['keygen']);
    const source = parseJson(cli(dir, ['sign', '--json']));
    rmSync(join(dir, '.agent-receipt', 'keys'), { recursive: true, force: true });

    const shared = cliResult(dir, ['share', '--package', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.exitCode, 0);
    assert.equal(gate.sigPath, null);
    assert.equal(existsSync(gate.htmlPath), true);
    assert.equal(existsSync(gate.markdownPath), true);
    assert.equal(existsSync(join(gate.packagePath, 'receipt.sig.json')), false);
    assert.equal(existsSync(join(gate.packagePath, 'manifest.sig.json')), false);
    assert.equal(existsSync(source.sigPath), true);
    const manifest = JSON.parse(readFileSync(join(gate.packagePath, 'manifest.json'), 'utf8'));
    assert.equal(manifest.signed, false);
    assert.equal(manifest.fingerprint, null);
    assert.match(shared.err + shared.out, /keygen/);
    assert.match(shared.err + shared.out, /sign/);
  });

  it('without --package, share does not create a .share directory', () => {
    const dir = initRepo();
    const wrapped = wrapClean(dir, 'package-unchanged');
    const shared = cliResult(dir, ['share', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(Object.prototype.hasOwnProperty.call(gate, 'packagePath'), false);
    assert.equal(gate.markdownPath, null);
    assert.equal(gate.sigPath, null);
    assert.equal(typeof gate.htmlPath, 'string');
    assert.equal(existsSync(gate.htmlPath), true);
    const shareDir = wrapped.path.replace(/\.md$/i, '.share');
    assert.equal(existsSync(shareDir), false);
  });

  it('a tampered source is not rewritten into a package', () => {
    const dir = initRepo();
    const wrapped = wrapClean(dir, 'package-tamper');
    const body = readFileSync(wrapped.path, 'utf8').replace(
      'package-tamper',
      'package-tamper-edited',
    );
    writeFileSync(wrapped.path, body);
    const shareDir = wrapped.path.replace(/\.md$/i, '.share');
    const shared = cliResult(dir, ['share', '--package', '--json']);
    assert.equal(shared.code, 2, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.ok, false);
    assert.equal(gate.verified, false);
    assert.equal(gate.htmlPath, null);
    assert.equal(gate.markdownPath, null);
    assert.equal(Object.prototype.hasOwnProperty.call(gate, 'packagePath'), false);
    assert.equal(existsSync(shareDir), false);
  });

  it('--out directory and --no-redact still apply inside the package', () => {
    const dir = initRepo();
    wrapClean(dir, 'package-out');
    cli(dir, ['keygen']);
    const signed = parseJson(cli(dir, ['sign', '--json']));
    rmSync(join(dir, '.agent-receipt', 'keys'), { recursive: true, force: true });

    const dest = join(dir, 'handoff');
    mkdirSync(dest);
    const shared = cliResult(dir, [
      'share',
      '--package',
      '--no-redact',
      '--out',
      'handoff',
      '--json',
    ]);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.redacted, false);
    assert.equal(gate.packagePath, dest);
    assert.equal(gate.sigPath, join(dest, 'receipt.sig.json'));
    assert.equal(readFileSync(gate.sigPath).equals(readFileSync(signed.sigPath)), true);
    const manifest = JSON.parse(readFileSync(join(dest, 'manifest.json'), 'utf8'));
    assert.equal(manifest.redacted, false);
    assert.equal(manifest.signed, true);
    assert.equal(existsSync(join(dest, 'manifest.sig.json')), false);

    const positional = cliResult(dir, ['share', '--package', signed.path, '--out', 'bundle/', '--json']);
    assert.equal(positional.code, 0, positional.out + positional.err);
    const again = parseJson(positional.out);
    assert.equal(basename(again.packagePath), 'bundle');
    assert.equal(existsSync(join(again.packagePath, 'receipt.md')), true);
    assert.equal(existsSync(join(again.packagePath, 'receipt.html')), true);
  });
});
