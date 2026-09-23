import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
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
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

function auditEvents(dir) {
  const path = join(dir, '.agent-receipt', 'audit.jsonl');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

describe('v1.0.25 verify share package', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1025-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# verify-package\n');
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

  function sharePackage(dir) {
    const shared = cliResult(dir, ['share', '--package', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    return parseJson(shared.out);
  }

  it('documents version 1.0.25, verify --package, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.25\]/);
    assert.match(changelog, /verify --package/);
    assert.match(changelog, /\bimport\b/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    assert.match(changelog, /not a CA/i);
    assert.match(changelog, /prove --html/);
    assert.match(changelog, /background deleter/);
    assert.match(changelog, /manifest\.sig\.json/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.25');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.25');
    assert.equal(lock.packages[''].version, '1.0.25');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.25/);

    const help = cli(root, ['help', 'verify']);
    assert.match(help, /verify --package/);
    assert.match(help, /--pack/);
    assert.match(help, /manifest\.json/);
    assert.match(help, /filesOk/);
    const helpImport = cli(root, ['help', 'import']);
    assert.match(helpImport, /receipt-import-/);
    assert.match(helpImport, /--dry-run/);
    assert.match(helpImport, /does not append the audit log/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /verify --package/);
    assert.match(business, /1\.0\.25/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.25/);
    assert.match(mirror, /verify --package/);
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'share-package.schema.json'), 'utf8'));
    assert.match(schema.description, /verify --package/);
    const gateSchema = JSON.parse(readFileSync(join(root, 'docs', 'gate.schema.json'), 'utf8'));
    assert.equal(gateSchema.required.includes('filesOk'), false);
    assert.equal(gateSchema.required.includes('importPath'), false);
    assert.equal(gateSchema.properties.command.enum.includes('import'), true);
    assert.equal(gateSchema.properties.command.enum.includes('verify'), true);

    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /verify --package/);
      assert.doesNotMatch(live, /v1\.0\.25/);
    }
  });

  it('round-trips share --package into verify --package', () => {
    const dir = initRepo();
    const wrapped = wrapClean(dir, 'package-verify');
    const shared = sharePackage(dir);
    const manifest = JSON.parse(readFileSync(join(shared.packagePath, 'manifest.json'), 'utf8'));
    assert.equal(manifest.signed, false);
    assert.equal(existsSync(join(shared.packagePath, 'manifest.sig.json')), false);

    const human = cliResult(dir, ['verify', '--package', shared.packagePath]);
    assert.equal(human.code, 0, human.out + human.err);
    assert.match(human.out, /VERIFIED/);
    assert.match(human.out, /files: ok/);
    assert.match(human.out, /receipt: ok/);
    assert.match(human.out, /signature: absent/);
    assert.match(human.out, /manifestSig: absent/);
    assert.match(human.out, /tip: open/);
    assert.match(human.out, /receipt\.html/);

    const checked = cliResult(dir, ['verify', '--package', shared.packagePath, '--json']);
    assert.equal(checked.code, 0, checked.out + checked.err);
    const gate = parseJson(checked.out);
    assert.equal(gate.command, 'verify');
    assert.equal(gate.ok, true);
    assert.equal(gate.exitCode, 0);
    assert.equal(gate.verified, true);
    assert.equal(gate.filesOk, true);
    assert.equal(gate.manifestOk, true);
    assert.equal(gate.signed, false);
    assert.equal(gate.fingerprint, null);
    assert.equal(gate.sha256, manifest.sha256);
    assert.equal(gate.path, shared.packagePath);
    assert.equal(gate.packagePath, shared.packagePath);
    assert.equal(gate.markdownPath, join(shared.packagePath, 'receipt.md'));
    assert.equal(gate.manifestSig.present, false);
    assert.equal(gate.manifestSig.ok, null);
    assert.equal(gate.signature.present, false);
    assert.equal(Object.hasOwn(gate, 'importPath'), false);
    assert.equal(gate.version, '1.0.25');

    const packed = cliResult(dir, ['verify', '--pack', shared.packagePath, '--json']);
    assert.equal(packed.code, 0, packed.out + packed.err);
    assert.equal(parseJson(packed.out).filesOk, true);

    const viaManifest = cliResult(dir, [
      'verify',
      '--package',
      join(shared.packagePath, 'manifest.json'),
      '--json',
    ]);
    assert.equal(viaManifest.code, 0, viaManifest.out + viaManifest.err);
    assert.equal(parseJson(viaManifest.out).path, shared.packagePath);

    const plain = cliResult(dir, ['verify', wrapped.path, '--json']);
    assert.equal(plain.code, 0, plain.out + plain.err);
    const plainGate = parseJson(plain.out);
    assert.equal(plainGate.command, 'verify');
    assert.equal(plainGate.ok, true);
    assert.equal(plainGate.verified, true);
    assert.equal(Object.hasOwn(plainGate, 'filesOk'), false);
    assert.equal(Object.hasOwn(plainGate, 'packagePath'), false);
    assert.equal(Object.hasOwn(plainGate, 'manifestSig'), false);

    const inner = cliResult(dir, ['verify', join(shared.packagePath, 'receipt.md'), '--json']);
    assert.equal(inner.code, 0, inner.out + inner.err);
    assert.equal(Object.hasOwn(parseJson(inner.out), 'filesOk'), false);
  });

  it('auto-detects a share directory and manifest.json without --package', () => {
    const dir = initRepo();
    wrapClean(dir, 'auto-detect');
    const shared = sharePackage(dir);
    const auto = cliResult(dir, ['verify', shared.packagePath, '--json']);
    assert.equal(auto.code, 0, auto.out + auto.err);
    const gate = parseJson(auto.out);
    assert.equal(gate.command, 'verify');
    assert.equal(gate.filesOk, true);
    assert.equal(gate.packagePath, shared.packagePath);

    const viaFile = cliResult(dir, ['verify', join(shared.packagePath, 'manifest.json'), '--json']);
    assert.equal(viaFile.code, 0, viaFile.out + viaFile.err);
    assert.equal(parseJson(viaFile.out).path, shared.packagePath);
  });

  it('verify --package --require-sig passes when the package is signed', () => {
    const dir = initRepo();
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    wrapClean(dir, 'signed-package');
    cli(dir, ['wrap', '--sign', '--agent', 'ci', '--message', 'signed-package-2', '--json']);
    const shared = sharePackage(dir);
    assert.equal(existsSync(join(shared.packagePath, 'receipt.sig.json')), true);
    assert.equal(existsSync(join(shared.packagePath, 'manifest.sig.json')), true);

    const checked = cliResult(dir, [
      'verify',
      '--package',
      shared.packagePath,
      '--require-sig',
      '--json',
    ]);
    assert.equal(checked.code, 0, checked.out + checked.err);
    const gate = parseJson(checked.out);
    assert.equal(gate.ok, true);
    assert.equal(gate.signed, true);
    assert.equal(gate.filesOk, true);
    assert.equal(gate.manifestOk, true);
    assert.equal(gate.fingerprint, keys.fingerprint);
    assert.equal(gate.signature.present, true);
    assert.equal(gate.signature.ok, true);
    assert.equal(gate.signature.fingerprint, keys.fingerprint);
    assert.equal(gate.manifestSig.present, true);
    assert.equal(gate.manifestSig.ok, true);
    assert.equal(gate.manifestSig.fingerprint, keys.fingerprint);
  });

  it('fails closed on tampered receipt bytes, file bytes, manifest sha, kind, and a missing manifest', () => {
    const dir = initRepo();
    wrapClean(dir, 'tamper-base');
    const shared = sharePackage(dir);
    const pkg = shared.packagePath;
    const manifestPath = join(pkg, 'manifest.json');

    const html = readFileSync(join(pkg, 'receipt.html'), 'utf8');
    writeFileSync(join(pkg, 'receipt.html'), `${html}\n<!-- tamper -->\n`);
    const fileTamper = cliResult(dir, ['verify', '--package', pkg, '--json']);
    assert.equal(fileTamper.code, 2, fileTamper.out + fileTamper.err);
    const fileGate = parseJson(fileTamper.out);
    assert.equal(fileGate.ok, false);
    assert.equal(fileGate.exitCode, 2);
    assert.equal(fileGate.filesOk, false);
    assert.equal(fileGate.verified, true);
    assert.match(fileGate.reason, /file hash mismatch: receipt\.html/);
    writeFileSync(join(pkg, 'receipt.html'), html);

    const mdPath = join(pkg, 'receipt.md');
    const md = readFileSync(mdPath, 'utf8');
    writeFileSync(mdPath, md.replace('## Summary', '## Summary tampered'));
    const bodyTamper = cliResult(dir, ['verify', '--package', pkg, '--json']);
    assert.equal(bodyTamper.code, 2, bodyTamper.out + bodyTamper.err);
    const bodyGate = parseJson(bodyTamper.out);
    assert.equal(bodyGate.verified, false);
    assert.equal(bodyGate.filesOk, false);
    writeFileSync(mdPath, md);

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const originalSha = manifest.sha256;
    manifest.sha256 = `${originalSha.slice(0, -1)}${originalSha.endsWith('a') ? 'b' : 'a'}`;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const shaTamper = cliResult(dir, ['verify', '--package', pkg, '--json']);
    assert.equal(shaTamper.code, 2, shaTamper.out + shaTamper.err);
    const shaGate = parseJson(shaTamper.out);
    assert.equal(shaGate.exitCode, 2);
    assert.equal(shaGate.manifestOk, false);
    assert.equal(shaGate.filesOk, true);
    assert.match(shaGate.reason, /manifest sha256 does not match receipt hash/);
    manifest.sha256 = originalSha;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    manifest.kind = 'nope';
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const badKind = cliResult(dir, ['verify', '--package', pkg, '--json']);
    assert.equal(badKind.code, 1, badKind.out + badKind.err);
    const kindGate = parseJson(badKind.out);
    assert.equal(kindGate.ok, false);
    assert.equal(kindGate.exitCode, 1);
    assert.equal(kindGate.command, 'verify');
    assert.match(kindGate.reason, /kind/);

    const empty = join(dir, 'empty-pack');
    mkdirSync(empty);
    const missing = cliResult(dir, ['verify', '--package', empty, '--json']);
    assert.equal(missing.code, 1, missing.out + missing.err);
    assert.match(parseJson(missing.out).reason, /manifest\.json/);

    const notPackage = cliResult(dir, ['verify', '--package', join(pkg, 'receipt.md'), '--json']);
    assert.equal(notPackage.code, 1, notPackage.out + notPackage.err);
    assert.match(parseJson(notPackage.out).reason, /not a share package/);

    const noPath = cliResult(dir, ['verify', '--package', '--json']);
    assert.equal(noPath.code, 1, noPath.out + noPath.err);
  });

  it('rejects an invalid receipt sidecar and an invalid manifest sidecar', () => {
    const dir = initRepo();
    cli(dir, ['keygen', '--json']);
    wrapClean(dir, 'sig-tamper');
    const shared = sharePackage(dir);
    const pkg = shared.packagePath;
    const manifestPath = join(pkg, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

    const sigPath = join(pkg, 'receipt.sig.json');
    const sig = JSON.parse(readFileSync(sigPath, 'utf8'));
    sig.signature = 'A'.repeat(88);
    writeFileSync(sigPath, `${JSON.stringify(sig, null, 2)}\n`);
    manifest.files['receipt.sig.json'] = execFileSync(
      process.execPath,
      ['-e', 'const c=require("crypto"),f=require("fs"); process.stdout.write(c.createHash("sha256").update(f.readFileSync(process.argv[1])).digest("hex"))', sigPath],
      { encoding: 'utf8' },
    );
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    rmSync(join(pkg, 'manifest.sig.json'));
    const badSig = cliResult(dir, ['verify', '--package', pkg, '--json']);
    assert.equal(badSig.code, 2, badSig.out + badSig.err);
    const badGate = parseJson(badSig.out);
    assert.equal(badGate.filesOk, true);
    assert.equal(badGate.signature.present, true);
    assert.equal(badGate.signature.ok, false);
    assert.equal(badGate.manifestSig.present, false);

    const plain = cliResult(dir, ['verify', join(pkg, 'receipt.md'), '--json']);
    assert.equal(plain.code, 0, plain.out + plain.err);
    assert.equal(Object.hasOwn(parseJson(plain.out), 'signature'), false);
  });

  it('rejects a tampered manifest.sig.json and unsigned --require-sig', () => {
    const dir = initRepo();
    cli(dir, ['keygen', '--json']);
    wrapClean(dir, 'manifest-sig');
    const shared = sharePackage(dir);
    const pkg = shared.packagePath;
    const manifestSigPath = join(pkg, 'manifest.sig.json');
    const manifestSig = JSON.parse(readFileSync(manifestSigPath, 'utf8'));
    manifestSig.signature = 'A'.repeat(88);
    writeFileSync(manifestSigPath, `${JSON.stringify(manifestSig, null, 2)}\n`);
    const bad = cliResult(dir, ['verify', '--package', pkg, '--json']);
    assert.equal(bad.code, 2, bad.out + bad.err);
    const gate = parseJson(bad.out);
    assert.equal(gate.filesOk, true);
    assert.equal(gate.verified, true);
    assert.equal(gate.manifestSig.present, true);
    assert.equal(gate.manifestSig.ok, false);
    assert.match(gate.reason, /manifest signature|signature/);

    const unsignedDir = initRepo();
    wrapClean(unsignedDir, 'unsigned-require');
    const unsigned = sharePackage(unsignedDir);
    const required = cliResult(unsignedDir, [
      'verify',
      '--package',
      unsigned.packagePath,
      '--require-sig',
      '--json',
    ]);
    assert.equal(required.code, 2, required.out + required.err);
    const requiredGate = parseJson(required.out);
    assert.equal(requiredGate.signature.present, false);
    assert.equal(requiredGate.signature.ok, false);
    assert.match(requiredGate.reason, /signature absent/);
  });

  it('import copies the proved markdown and sidecar, and refuses a failed verify', () => {
    const dir = initRepo();
    cli(dir, ['keygen', '--json']);
    wrapClean(dir, 'import-ok');
    const shared = sharePackage(dir);
    const pkg = shared.packagePath;
    const manifest = JSON.parse(readFileSync(join(pkg, 'manifest.json'), 'utf8'));
    const destName = `receipt-import-${manifest.sha256.slice(0, 12)}.md`;
    const dest = join(dir, '.agent-receipt', 'receipts', destName);
    const indexPath = join(dir, '.agent-receipt', 'index.json');
    const indexBefore = readFileSync(indexPath, 'utf8');
    const auditBefore = auditEvents(dir).length;

    const dry = cliResult(dir, ['import', pkg, '--dry-run', '--json']);
    assert.equal(dry.code, 0, dry.out + dry.err);
    const dryGate = parseJson(dry.out);
    assert.equal(dryGate.command, 'import');
    assert.equal(dryGate.ok, true);
    assert.equal(dryGate.dryRun, true);
    assert.equal(dryGate.importPath, dest);
    assert.equal(dryGate.importSigPath, dest.replace(/\.md$/i, '.sig.json'));
    assert.equal(existsSync(dest), false);
    assert.equal(existsSync(dryGate.importSigPath), false);

    const humanDry = cliResult(dir, ['import', '--dry-run', pkg]);
    assert.equal(humanDry.code, 0, humanDry.out + humanDry.err);
    assert.match(humanDry.out, /VERIFIED/);
    assert.match(humanDry.out, /dry-run:/);
    assert.equal(existsSync(dest), false);

    const imported = cliResult(dir, ['import', pkg, '--json']);
    assert.equal(imported.code, 0, imported.out + imported.err);
    const gate = parseJson(imported.out);
    assert.equal(gate.command, 'import');
    assert.equal(gate.importPath, dest);
    assert.equal(existsSync(gate.importPath), true);
    assert.equal(existsSync(gate.importSigPath), true);
    assert.equal(
      readFileSync(gate.importPath, 'utf8'),
      readFileSync(join(pkg, 'receipt.md'), 'utf8'),
    );
    assert.equal(
      readFileSync(gate.importSigPath, 'utf8'),
      readFileSync(join(pkg, 'receipt.sig.json'), 'utf8'),
    );
    assert.equal(existsSync(join(dir, '.agent-receipt', 'receipts', 'receipt.html')), false);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'receipts', 'manifest.json')), false);
    assert.equal(readFileSync(indexPath, 'utf8'), indexBefore);
    assert.equal(auditEvents(dir).length, auditBefore);
    const checked = cliResult(dir, ['verify', gate.importPath, '--require-sig', '--json']);
    assert.equal(checked.code, 0, checked.out + checked.err);
    assert.equal(parseJson(checked.out).signature.ok, true);

    const html = readFileSync(join(pkg, 'receipt.html'), 'utf8');
    writeFileSync(join(pkg, 'receipt.html'), `${html}\n<!-- no import -->\n`);
    const otherName = `receipt-import-${'ab'.repeat(6)}.md`;
    const refused = cliResult(dir, ['import', pkg, '--json']);
    assert.equal(refused.code, 2, refused.out + refused.err);
    const refusedGate = parseJson(refused.out);
    assert.equal(refusedGate.ok, false);
    assert.equal(refusedGate.importPath, null);
    assert.equal(refusedGate.importSigPath, null);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'receipts', otherName)), false);
    assert.equal(readFileSync(indexPath, 'utf8'), indexBefore);
    assert.equal(auditEvents(dir).length, auditBefore);
    const kept = readFileSync(dest, 'utf8');
    assert.equal(kept, readFileSync(join(pkg, 'receipt.md'), 'utf8'));
  });
});
