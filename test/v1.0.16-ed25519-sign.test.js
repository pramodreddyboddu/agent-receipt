import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  statSync,
  mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const SIG_KEYS = ['alg', 'version', 'sha256', 'fingerprint', 'signature', 'publicKey'];

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

describe('v1.0.16 Ed25519 keygen and sign', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo(prefix) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# sign\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function wrapClean(dir, message) {
    writeFileSync(join(dir, 'note.txt'), `${message}\n`);
    git(dir, ['add', 'note.txt']);
    git(dir, ['commit', '-m', message]);
    const wrapped = cliResult(dir, ['wrap', '--agent', 'ci', '--message', message]);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    return wrapped;
  }

  it('keygen creates keys, is idempotent, and --force rotates the fingerprint', () => {
    const dir = initRepo('agent-receipt-1016-keygen-');
    const human = cli(dir, ['keygen']);
    assert.match(human, /created/);
    assert.match(human, /fingerprint:/);
    assert.match(human, /agent-receipt sign/);
    const priv = join(dir, '.agent-receipt', 'keys', 'ed25519.private');
    const pub = join(dir, '.agent-receipt', 'keys', 'ed25519.public');
    assert.equal(existsSync(priv), true);
    assert.equal(existsSync(pub), true);
    assert.equal(statSync(priv).mode & 0o777, 0o600);
    const privatePem = readFileSync(priv, 'utf8');
    const publicPem = readFileSync(pub, 'utf8');
    assert.match(privatePem, /BEGIN PRIVATE KEY/);
    assert.match(publicPem, /BEGIN PUBLIC KEY/);
    assert.doesNotMatch(publicPem, /PRIVATE KEY/);

    const first = parseJson(cli(dir, ['keygen', '--json']));
    assert.equal(first.ok, true);
    assert.equal(first.command, 'keygen');
    assert.equal(first.version, '1.0.17');
    assert.equal(first.exitCode, 0);
    assert.equal(first.created, false);
    assert.equal(first.rotated, false);
    assert.equal(first.fingerprint.length, 64);
    assert.equal(first.privateKeyPath, priv);
    assert.equal(first.publicKeyPath, pub);
    assert.match(cli(dir, ['keygen']), /unchanged/);
    assert.equal(readFileSync(priv, 'utf8'), privatePem);

    const rotated = parseJson(cli(dir, ['keygen', '--force', '--json']));
    assert.equal(rotated.ok, true);
    assert.equal(rotated.created, false);
    assert.equal(rotated.rotated, true);
    assert.equal(rotated.fingerprint.length, 64);
    assert.notEqual(rotated.fingerprint, first.fingerprint);
    assert.notEqual(readFileSync(priv, 'utf8'), privatePem);
    assert.match(cli(dir, ['keygen', '--force']), /rotated/);

    mkdirSync(join(dir, '.agent-receipt', 'keys'), { recursive: true });
    rmSync(pub);
    const incomplete = cliResult(dir, ['keygen', '--json']);
    assert.equal(incomplete.code, 1, incomplete.out);
    const body = parseJson(incomplete.out);
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 1);
    assert.match(body.reason, /--force/);
  });

  it('sign without keys exits 1 and does not write a sidecar', () => {
    const dir = initRepo('agent-receipt-1016-nokeys-');
    wrapClean(dir, 'unsigned');
    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.signature.present, false);
    assert.equal(proved.signature.ok, null);
    assert.equal(proved.exitCode, 0);
    const verified = cliResult(dir, ['verify']);
    assert.equal(verified.code, 0, verified.err);
    assert.match(verified.out, /OK/);

    const signed = cliResult(dir, ['sign']);
    assert.equal(signed.code, 1, signed.out + signed.err);
    assert.match(signed.err, /keygen/);
    assert.equal(existsSync(proved.path.replace(/\.md$/i, '.sig.json')), false);

    const json = cliResult(dir, ['sign', '--json']);
    assert.equal(json.code, 1);
    const body = parseJson(json.out);
    assert.equal(body.command, 'sign');
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 1);
    assert.equal(body.verified, true);
    assert.equal(body.sigPath, null);
    assert.match(body.reason, /keygen/);
  });

  it('signs the sha256 hex and prove reports signature.ok', () => {
    const dir = initRepo('agent-receipt-1016-sign-');
    wrapClean(dir, 'attest-me');
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const signed = cliResult(dir, ['sign', '--json']);
    assert.equal(signed.code, 0, signed.err + signed.out);
    const signBody = parseJson(signed.out);
    assert.equal(signBody.ok, true);
    assert.equal(signBody.command, 'sign');
    assert.equal(signBody.version, '1.0.17');
    assert.equal(signBody.exitCode, 0);
    assert.equal(signBody.verified, true);
    assert.equal(signBody.fingerprint, keys.fingerprint);
    assert.equal(signBody.sha256.length, 64);
    assert.equal(existsSync(signBody.sigPath), true);

    const sidecarText = readFileSync(signBody.sigPath, 'utf8');
    assert.doesNotMatch(sidecarText, /PRIVATE KEY/);
    const sidecar = JSON.parse(sidecarText);
    for (const key of SIG_KEYS) {
      assert.equal(Object.prototype.hasOwnProperty.call(sidecar, key), true, key);
    }
    assert.equal(sidecar.alg, 'ed25519');
    assert.equal(sidecar.version, 1);
    assert.equal(sidecar.sha256, signBody.sha256);
    assert.equal(sidecar.fingerprint, keys.fingerprint);
    assert.match(sidecar.publicKey, /BEGIN PUBLIC KEY/);
    const der = createPublicKey(sidecar.publicKey).export({ type: 'spki', format: 'der' });
    const fp = createHash('sha256').update(der).digest('hex');
    assert.equal(fp, sidecar.fingerprint);
    const raw = Buffer.from(sidecar.signature, 'base64');
    assert.equal(raw.length, 64);
    assert.equal(
      cryptoVerify(null, Buffer.from(sidecar.sha256, 'utf8'), createPublicKey(sidecar.publicKey), raw),
      true,
    );
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'signature.schema.json'), 'utf8'));
    for (const key of schema.required) {
      assert.equal(Object.prototype.hasOwnProperty.call(sidecar, key), true, key);
    }

    const human = cli(dir, ['sign']);
    assert.match(human, /SIGNED/);
    assert.match(human, /fingerprint:/);

    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.ok, true);
    assert.equal(proved.exitCode, 0);
    assert.equal(proved.verified, true);
    assert.equal(proved.signature.present, true);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.alg, 'ed25519');
    assert.equal(proved.signature.fingerprint, keys.fingerprint);
    assert.equal(proved.signature.reason, null);
    assert.match(cli(dir, ['prove']), /signature: ok /);

    rmSync(join(dir, '.agent-receipt', 'keys'), { recursive: true });
    const portable = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(portable.signature.ok, true);
    assert.equal(portable.exitCode, 0);

    const still = cliResult(dir, ['verify']);
    assert.equal(still.code, 0, still.err);
  });

  it('fails prove when the markdown or the signature bytes change', () => {
    const dir = initRepo('agent-receipt-1016-tamper-');
    wrapClean(dir, 'tamper-target');
    cli(dir, ['keygen']);
    const signed = parseJson(cli(dir, ['sign', '--json']));
    const before = readFileSync(signed.sigPath, 'utf8');

    const text = readFileSync(signed.path, 'utf8');
    writeFileSync(signed.path, text.replace('tamper-target', 'tampered-body'));
    const badHash = cliResult(dir, ['prove', '--json']);
    assert.equal(badHash.code, 2, badHash.out + badHash.err);
    const hashBody = parseJson(badHash.out);
    assert.equal(hashBody.ok, false);
    assert.equal(hashBody.verified, false);
    assert.equal(hashBody.exitCode, 2);
    const resign = cliResult(dir, ['sign', '--json']);
    assert.equal(resign.code, 2, resign.out);
    assert.equal(parseJson(resign.out).verified, false);
    assert.equal(parseJson(resign.out).sigPath, null);
    assert.equal(readFileSync(signed.sigPath, 'utf8'), before);

    writeFileSync(signed.path, text);
    const restored = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(restored.signature.ok, true);

    const sidecar = JSON.parse(readFileSync(signed.sigPath, 'utf8'));
    sidecar.signature = Buffer.alloc(64, 7).toString('base64');
    writeFileSync(signed.sigPath, JSON.stringify(sidecar, null, 2) + '\n');
    const badSig = cliResult(dir, ['prove', '--json']);
    assert.equal(badSig.code, 2, badSig.out + badSig.err);
    const sigBody = parseJson(badSig.out);
    assert.equal(sigBody.verified, true);
    assert.equal(sigBody.signature.present, true);
    assert.equal(sigBody.signature.ok, false);
    assert.equal(typeof sigBody.signature.reason, 'string');
    assert.match(sigBody.reason, /signature:/);
    assert.match(cliResult(dir, ['prove']).out, /signature: FAIL/);
    const verify = cliResult(dir, ['verify']);
    assert.equal(verify.code, 0, verify.err);

    writeFileSync(signed.sigPath, '{');
    const malformed = cliResult(dir, ['prove', '--json']);
    assert.equal(malformed.code, 2);
    const malBody = parseJson(malformed.out);
    assert.equal(malBody.signature.ok, false);
    assert.match(malBody.signature.reason, /malformed/);
  });

  it('does not copy key material into an uncommitted receipt', () => {
    const dir = initRepo('agent-receipt-1016-leak-');
    const secret = 'BEGIN PRIVATE KEY SECRETKEYMATERIAL-not-for-receipt';
    const keyDir = join(dir, '.agent-receipt', 'keys');
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(join(keyDir, 'ed25519.private'), secret + '\n');
    writeFileSync(join(dir, 'visible.txt'), 'visible-work\n');
    const captured = cliResult(dir, [
      'capture',
      '--uncommitted',
      '--agent',
      'ci',
      '--message',
      'dirty',
    ]);
    assert.equal(captured.code, 0, captured.out + captured.err);
    const latest = parseJson(cli(dir, ['last', '--json']));
    const md = readFileSync(latest.path, 'utf8');
    assert.match(md, /visible\.txt/);
    assert.doesNotMatch(md, /SECRETKEYMATERIAL/);
    assert.doesNotMatch(md, /ed25519\.private/);
  });

  it('doctor reports keys without failing when they are absent', () => {
    const dir = initRepo('agent-receipt-1016-doctor-');
    cli(dir, ['init', '--org']);
    cli(dir, ['init', '--retention']);
    const absent = parseJson(cli(dir, ['doctor', '--strict', '--json']));
    assert.equal(absent.ok, true);
    assert.equal(absent.exitCode, 0);
    const keys = absent.checks.find((c) => c.id === 'keys');
    assert.equal(keys.status, 'info');
    const made = parseJson(cli(dir, ['keygen', '--json']));
    const present = parseJson(cli(dir, ['doctor', '--json']));
    const pass = present.checks.find((c) => c.id === 'keys');
    assert.equal(pass.status, 'pass');
    assert.match(pass.detail, new RegExp(made.fingerprint));
    rmSync(made.privateKeyPath);
    const warned = cliResult(dir, ['doctor', '--json']);
    assert.equal(warned.code, 0, warned.out);
    const warn = parseJson(warned.out).checks.find((c) => c.id === 'keys');
    assert.equal(warn.status, 'warn');
    assert.match(warn.detail, /private key missing/);
  });
});

describe('v1.0.16 docs', () => {
  it('documents keygen, sign, prove signature, and version 1.0.16', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.16\]/);
    assert.match(changelog, /keygen/);
    assert.match(changelog, /prove/);
    assert.match(changelog, /PKI\/CA/);
    assert.match(changelog, /auto-sign on capture/);
    assert.match(changelog, /always-fail/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.17');
    assert.equal(pkg.dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.17/);
    const help = cli(root, ['help']);
    assert.match(help, /\bkeygen\b/);
    assert.match(help, /\bsign\b/);
    assert.match(cli(root, ['help', 'keygen']), /fingerprint/);
    assert.match(cli(root, ['help', 'sign']), /sig\.json/);
    assert.match(cli(root, ['help', 'prove']), /signature/);
    assert.match(cli(root, ['help', 'verify']), /hash-only/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /v1\.0\.16/);
    assert.match(mirror, /signature\.ok/);
    assert.match(mirror, /keygen/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /help keygen/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /signature\.schema\.json/);
    assert.match(business, /not a CA/);
    const security = readFileSync(join(root, 'SECURITY.md'), 'utf8');
    assert.match(security, /Ed25519/);
    assert.match(security, /no CA/);
    assert.match(security, /certificate authority/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /keygen/);
    assert.match(readme, /Thin local Ed25519 attest landed/);
  });
});
