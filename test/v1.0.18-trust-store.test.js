import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  loadTrustedFingerprints,
  isFingerprintTrusted,
  checkTrusted,
} from '../dist/lib/trust.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const OTHER = 'b'.repeat(64);
const WRONG = 'a'.repeat(64);

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

function sigBeside(mdPath) {
  return mdPath.replace(/\.md$/i, '.sig.json');
}

describe('v1.0.18 fingerprint trust store', () => {
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
    writeFileSync(join(dir, 'README.md'), '# trust-store\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function commitFile(dir, name, body, message) {
    writeFileSync(join(dir, name), body);
    git(dir, ['add', name]);
    git(dir, ['commit', '-m', message]);
  }

  function wrapClean(dir, message) {
    commitFile(dir, 'note.txt', `${message}\n`, message);
    const wrapped = cliResult(dir, ['wrap', '--agent', 'ci', '--message', message]);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    return wrapped;
  }

  function signLatest(dir) {
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const signed = parseJson(cli(dir, ['sign', '--json']));
    return { keys, signed };
  }

  it('no store keeps verify --require-sig and prove on the 1.0.17 path', () => {
    const dir = initRepo('agent-receipt-1018-nostore-');
    wrapClean(dir, 'compat');
    const { keys } = signLatest(dir);
    const verified = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(verified.code, 0, verified.out + verified.err);
    const gate = parseJson(verified.out);
    assert.equal(gate.ok, true);
    assert.equal(gate.signature.ok, true);
    assert.equal(gate.signature.fingerprint, keys.fingerprint);
    assert.equal(gate.signature.trusted, null);

    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.ok, true);
    assert.equal(proved.exitCode, 0);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.trusted, null);

    const store = loadTrustedFingerprints(dir);
    assert.equal(store.fingerprints.size, 0);
    assert.equal(store.reason, undefined);
    assert.equal(isFingerprintTrusted(keys.fingerprint, store), true);
    assert.equal(checkTrusted(keys.fingerprint, store).ok, true);
  });

  it('a matching fingerprint passes verify and prove; a different one fails both', () => {
    const dir = initRepo('agent-receipt-1018-match-');
    wrapClean(dir, 'allow');
    const { keys } = signLatest(dir);
    mkdirSync(join(dir, '.agent-receipt'), { recursive: true });
    writeFileSync(
      join(dir, '.agent-receipt', 'trusted-keys.txt'),
      `# known keys\n\n${keys.fingerprint.toUpperCase()}  \n`,
    );

    const verified = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(verified.code, 0, verified.out + verified.err);
    const gate = parseJson(verified.out);
    assert.equal(gate.signature.ok, true);
    assert.equal(gate.signature.trusted, true);

    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.exitCode, 0);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.trusted, true);
    assert.match(cli(dir, ['prove']), /trusted/);

    writeFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), `${WRONG}\n`);
    const denied = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(denied.code, 2, denied.out);
    const badGate = parseJson(denied.out);
    assert.equal(badGate.ok, false);
    assert.equal(badGate.exitCode, 2);
    assert.equal(badGate.signature.ok, false);
    assert.equal(badGate.signature.trusted, false);
    assert.match(badGate.reason, /fingerprint not trusted/);
    assert.match(badGate.reason, new RegExp(keys.fingerprint));

    const badProve = cliResult(dir, ['prove', '--json']);
    assert.equal(badProve.code, 2, badProve.out);
    const provedBad = parseJson(badProve.out);
    assert.equal(provedBad.ok, false);
    assert.equal(provedBad.exitCode, 2);
    assert.equal(provedBad.signature.ok, false);
    assert.equal(provedBad.signature.trusted, false);
    assert.match(provedBad.reason, /trust store/);
    assert.match(provedBad.signature.reason, /fingerprint not in trust store/);

    const store = loadTrustedFingerprints(dir);
    assert.equal(isFingerprintTrusted(keys.fingerprint, store), false);
    const checked = checkTrusted(keys.fingerprint, store);
    assert.equal(checked.ok, false);
    assert.match(checked.reason, new RegExp(`fingerprint not in trust store: ${keys.fingerprint}`));
  });

  it('an invalid trusted-keys line fails closed when require-sig runs', () => {
    const dir = initRepo('agent-receipt-1018-badline-');
    wrapClean(dir, 'bad-line');
    signLatest(dir);
    writeFileSync(
      join(dir, '.agent-receipt', 'trusted-keys.txt'),
      '# ok\nnot-a-fingerprint\n',
    );
    const denied = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(denied.code, 2, denied.out + denied.err);
    const body = parseJson(denied.out);
    assert.equal(body.exitCode, 2);
    assert.equal(body.signature.ok, false);
    assert.match(body.reason, /invalid fingerprint/);
    assert.match(body.signature.reason, /trusted-keys\.txt/);

    const proved = cliResult(dir, ['prove', '--json']);
    assert.equal(proved.code, 2, proved.out);
    assert.match(parseJson(proved.out).reason, /invalid fingerprint/);
  });

  it('config trustedFingerprints works alone and unions with the file', () => {
    const dir = initRepo('agent-receipt-1018-config-');
    wrapClean(dir, 'config');
    const { keys } = signLatest(dir);
    const cfg = join(dir, '.agent-receipt.yml');
    writeFileSync(
      cfg,
      readFileSync(cfg, 'utf8') + `\ntrustedFingerprints:\n  - ${keys.fingerprint}\n`,
    );
    rmSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), { force: true });
    const fromConfig = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(fromConfig.code, 0, fromConfig.out + fromConfig.err);
    assert.equal(parseJson(fromConfig.out).signature.trusted, true);

    writeFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), `${OTHER}\n`);
    writeFileSync(
      cfg,
      readFileSync(cfg, 'utf8').replace(
        `  - ${keys.fingerprint}`,
        `  - ${WRONG}`,
      ),
    );
    // File has OTHER, config has WRONG: the real fingerprint is in neither list.
    const neither = cliResult(dir, ['verify', '--require-sig']);
    assert.equal(neither.code, 2, neither.out + neither.err);

    writeFileSync(
      join(dir, '.agent-receipt', 'trusted-keys.txt'),
      `${keys.fingerprint}\n`,
    );
    const union = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(union.code, 0, union.out + union.err);
    assert.equal(parseJson(union.out).signature.trusted, true);
    const store = loadTrustedFingerprints(dir);
    assert.equal(store.fingerprints.has(keys.fingerprint), true);
    assert.equal(store.fingerprints.has(WRONG), true);
    assert.ok(store.sources.includes('.agent-receipt/trusted-keys.txt'));
    assert.ok(store.sources.includes('config:trustedFingerprints'));
  });

  it('--trusted-key unions for one invocation', () => {
    const dir = initRepo('agent-receipt-1018-cli-');
    wrapClean(dir, 'cli-key');
    const { keys } = signLatest(dir);
    const ok = cliResult(dir, [
      'verify',
      '--require-sig',
      '--trusted-key',
      keys.fingerprint,
      '--json',
    ]);
    assert.equal(ok.code, 0, ok.out + ok.err);
    assert.equal(parseJson(ok.out).signature.trusted, true);

    const comma = cliResult(dir, [
      'verify',
      '--require-sig',
      '--trusted-key',
      `${WRONG},${keys.fingerprint}`,
    ]);
    assert.equal(comma.code, 0, comma.out + comma.err);

    const denied = cliResult(dir, ['prove', '--json', '--trusted-key', WRONG]);
    assert.equal(denied.code, 2, denied.out);
    assert.equal(parseJson(denied.out).signature.trusted, false);

    const badFlag = cliResult(dir, ['verify', '--require-sig', '--trusted-key', 'nope']);
    assert.equal(badFlag.code, 1, badFlag.out + badFlag.err);
    assert.match(badFlag.err, /64 hex/);
  });

  it('doctor trust row is INFO when absent and PASS when fingerprints are listed', () => {
    const dir = initRepo('agent-receipt-1018-doctor-');
    const absent = parseJson(cli(dir, ['doctor', '--json']));
    const info = absent.checks.find((c) => c.id === 'trust');
    assert.equal(info.status, 'info');
    assert.match(info.detail, /allowlist inactive/);
    assert.equal(absent.ok, true);

    const strictMissing = cliResult(dir, ['doctor', '--strict', '--json']);
    const strictTrust = parseJson(strictMissing.out).checks.find((c) => c.id === 'trust');
    assert.equal(strictTrust.status, 'info');

    writeFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), `# none\n\n`);
    const empty = parseJson(cli(dir, ['doctor', '--json']));
    const warned = empty.checks.find((c) => c.id === 'trust');
    assert.equal(warned.status, 'warn');
    assert.match(warned.detail, /empty/);
    assert.equal(empty.ok, true);

    writeFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), `${OTHER}\n${WRONG}\n`);
    const present = parseJson(cli(dir, ['doctor', '--json']));
    const pass = present.checks.find((c) => c.id === 'trust');
    assert.equal(pass.status, 'pass');
    assert.match(pass.detail, /2 trusted fingerprints/);
    assert.match(pass.detail, new RegExp(OTHER.slice(0, 12)));

    writeFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), 'not-hex\n');
    const invalid = parseJson(cli(dir, ['doctor', '--json']));
    assert.equal(invalid.ok, true);
    assert.equal(invalid.checks.find((c) => c.id === 'trust').status, 'warn');

    cli(dir, ['init', '--org']);
    cli(dir, ['init', '--retention']);
    const strict = cliResult(dir, ['doctor', '--strict', '--json']);
    assert.equal(strict.code, 1, strict.out);
    const failed = parseJson(strict.out);
    assert.equal(failed.checks.find((c) => c.id === 'trust').status, 'fail');
    assert.equal(failed.checks.find((c) => c.id === 'policy').status, 'pass');
    assert.equal(failed.checks.find((c) => c.id === 'retention').status, 'pass');
  });

  it('trust list, add, and rm edit trusted-keys.txt', () => {
    const dir = initRepo('agent-receipt-1018-trust-cmd-');
    const added = parseJson(cli(dir, ['trust', 'add', OTHER, '--json']));
    assert.equal(added.ok, true);
    assert.equal(added.command, 'trust');
    assert.equal(added.added, true);
    assert.equal(added.count, 1);
    assert.deepEqual(added.fingerprints, [OTHER]);
    const file = readFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), 'utf8');
    assert.match(file, new RegExp(OTHER));

    const again = parseJson(cli(dir, ['trust', 'add', OTHER, '--json']));
    assert.equal(again.added, false);
    assert.equal(again.count, 1);

    const listed = parseJson(cli(dir, ['trust', 'list', '--json']));
    assert.equal(listed.active, true);
    assert.deepEqual(listed.fingerprints, [OTHER]);

    const removed = parseJson(cli(dir, ['trust', 'rm', OTHER, '--json']));
    assert.equal(removed.removed, true);
    assert.equal(removed.count, 0);
    assert.equal(removed.active, false);

    const bad = cliResult(dir, ['trust', 'add', 'short']);
    assert.equal(bad.code, 1);
    assert.match(bad.err, /64 hex/);
  });

  it('wrap and capture --sign write a sidecar only when asked and keys exist', () => {
    const dir = initRepo('agent-receipt-1018-sign-flag-');
    wrapClean(dir, 'plain');
    const plain = parseJson(cli(dir, ['last', '--json']));
    assert.equal(existsSync(sigBeside(plain.path)), false);

    commitFile(dir, 'note.txt', 'no-keys\n', 'no-keys');
    const unsigned = cliResult(dir, ['wrap', '--sign', '--agent', 'ci', '--message', 'no-keys']);
    assert.equal(unsigned.code, 0, unsigned.out + unsigned.err);
    assert.match(unsigned.out + unsigned.err, /left unsigned/);
    const noKeys = parseJson(cli(dir, ['last', '--json']));
    assert.equal(existsSync(sigBeside(noKeys.path)), false);

    const keys = parseJson(cli(dir, ['keygen', '--json']));
    commitFile(dir, 'note.txt', 'with-keys\n', 'with-keys');
    const signedWrap = cliResult(dir, ['wrap', '--sign', '--agent', 'ci', '--message', 'with-keys']);
    assert.equal(signedWrap.code, 0, signedWrap.out + signedWrap.err);
    const wrapped = parseJson(cli(dir, ['last', '--json']));
    assert.equal(existsSync(sigBeside(wrapped.path)), true);
    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.fingerprint, keys.fingerprint);
    assert.equal(proved.signature.trusted, null);

    const plainCapture = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--message',
      'plain-capture',
      '--out',
      'plain-capture.md',
    ]);
    assert.equal(plainCapture.code, 0, plainCapture.out + plainCapture.err);
    assert.equal(existsSync(join(dir, 'plain-capture.sig.json')), false);

    const signedCapture = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--sign',
      '--message',
      'signed-capture',
      '--out',
      'signed-capture.md',
    ]);
    assert.equal(signedCapture.code, 0, signedCapture.out + signedCapture.err);
    assert.equal(existsSync(join(dir, 'signed-capture.sig.json')), true);
    const sidecar = JSON.parse(readFileSync(join(dir, 'signed-capture.sig.json'), 'utf8'));
    assert.equal(sidecar.fingerprint, keys.fingerprint);
    assert.equal(sidecar.alg, 'ed25519');
  });
});

describe('v1.0.18 docs', () => {
  it('documents the trust store, version 1.0.18, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.18\]/);
    assert.match(changelog, /trusted-keys\.txt/);
    assert.match(changelog, /trustedFingerprints/);
    assert.match(changelog, /fingerprint not trusted|known-keys/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.25');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.25');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.25/);

    const helpVerify = cli(root, ['help', 'verify']);
    assert.match(helpVerify, /trust store|known-keys|trusted-keys/);
    assert.match(helpVerify, /--require-sig/);
    assert.match(helpVerify, /--trusted-key/);
    const helpDoctor = cli(root, ['help', 'doctor']);
    assert.match(helpDoctor, /trust/);
    assert.match(helpDoctor, /allowlist inactive|INFO when no store/);
    const helpProve = cli(root, ['help', 'prove']);
    assert.match(helpProve, /trusted/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /trusted-keys\.txt/);
    assert.match(readme, /known-keys allowlist/);
    const security = readFileSync(join(root, 'SECURITY.md'), 'utf8');
    assert.match(security, /trusted-keys\.txt/);
    assert.match(security, /no CA/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /trustedFingerprints/);
    assert.match(business, /not a CA/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /v1\.0\.18/);
    assert.match(mirror, /trusted-keys\.txt/);
    assert.match(mirror, /fingerprint not trusted/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /trusted-keys\.txt/);
    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /v1\.0\.18/);
    assert.match(action, /trusted-keys/);
  });
});
