import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
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

describe('v1.0.17 verify --require-sig and sidecar handoff', () => {
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
    writeFileSync(join(dir, 'README.md'), '# require-sig\n');
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

  function sigBeside(mdPath) {
    return mdPath.replace(/\.md$/i, '.sig.json');
  }

  it('verify stays hash-only; --require-sig fails when the sidecar is absent', () => {
    const dir = initRepo('agent-receipt-1017-unsigned-');
    wrapClean(dir, 'unsigned');
    const plain = cliResult(dir, ['verify']);
    assert.equal(plain.code, 0, plain.err);
    assert.match(plain.out, /OK/);

    const required = cliResult(dir, ['verify', '--require-sig']);
    assert.equal(required.code, 2, required.out + required.err);
    assert.match(required.err + required.out, /signature required/);
    assert.match(required.err + required.out, /signature absent/);

    const alias = cliResult(dir, ['verify', '--require-signature']);
    assert.equal(alias.code, 2, alias.out + alias.err);
    assert.match(alias.err + alias.out, /signature absent/);

    const gate = cliResult(dir, ['verify', '--json']);
    assert.equal(gate.code, 0, gate.err);
    const open = parseJson(gate.out);
    assert.equal(open.command, 'verify');
    assert.equal(open.ok, true);
    assert.equal(Object.prototype.hasOwnProperty.call(open, 'signature'), false);

    const closed = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(closed.code, 2, closed.out);
    const body = parseJson(closed.out);
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 2);
    assert.equal(body.verified, true);
    assert.equal(body.signature.present, false);
    assert.equal(body.signature.ok, false);
    assert.equal(body.signature.alg, null);
    assert.equal(body.signature.fingerprint, null);
    assert.match(body.signature.reason, /signature absent/);
    assert.match(body.reason, /signature absent/);
  });

  it('keygen + sign passes verify --require-sig and prove signature.ok', () => {
    const dir = initRepo('agent-receipt-1017-signed-');
    wrapClean(dir, 'attest');
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const signed = parseJson(cli(dir, ['sign', '--json']));
    assert.equal(signed.ok, true);
    const verified = cliResult(dir, ['verify', signed.path, '--require-sig', '--json']);
    assert.equal(verified.code, 0, verified.out + verified.err);
    const body = parseJson(verified.out);
    assert.equal(body.ok, true);
    assert.equal(body.exitCode, 0);
    assert.equal(body.verified, true);
    assert.equal(body.signature.present, true);
    assert.equal(body.signature.ok, true);
    assert.equal(body.signature.alg, 'ed25519');
    assert.equal(body.signature.fingerprint, keys.fingerprint);
    assert.equal(body.signature.reason, null);
    assert.equal(body.reason, null);

    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.ok, true);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.fingerprint, keys.fingerprint);
  });

  it('a corrupt sidecar fails verify --require-sig and prove, and default verify still passes', () => {
    const dir = initRepo('agent-receipt-1017-corrupt-');
    wrapClean(dir, 'corrupt');
    cli(dir, ['keygen']);
    const signed = parseJson(cli(dir, ['sign', '--json']));
    const sidecar = JSON.parse(readFileSync(signed.sigPath, 'utf8'));
    sidecar.signature = Buffer.alloc(64, 9).toString('base64');
    writeFileSync(signed.sigPath, JSON.stringify(sidecar, null, 2) + '\n');

    const plain = cliResult(dir, ['verify']);
    assert.equal(plain.code, 0, plain.out + plain.err);

    const required = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(required.code, 2, required.out);
    const body = parseJson(required.out);
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 2);
    assert.equal(body.signature.present, true);
    assert.equal(body.signature.ok, false);
    assert.equal(typeof body.signature.reason, 'string');
    assert.equal(body.reason.includes(body.signature.reason), true);

    const proved = cliResult(dir, ['prove', '--json']);
    assert.equal(proved.code, 2, proved.out);
    const proveBody = parseJson(proved.out);
    assert.equal(proveBody.signature.ok, false);
    assert.match(proveBody.reason, /signature/);
  });

  it('share --md re-signs a redacted receipt when keys exist', () => {
    const dir = initRepo('agent-receipt-1017-share-keys-');
    wrapClean(dir, 'share-me');
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const source = parseJson(cli(dir, ['sign', '--json']));
    const sourceSig = JSON.parse(readFileSync(source.sigPath, 'utf8'));

    const shared = cliResult(dir, ['share', '--md', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.command, 'share');
    assert.equal(gate.ok, true);
    assert.equal(gate.redacted, true);
    assert.equal(typeof gate.markdownPath, 'string');
    assert.equal(gate.sigPath, sigBeside(gate.markdownPath));
    assert.equal(existsSync(gate.sigPath), true);
    const published = JSON.parse(readFileSync(gate.sigPath, 'utf8'));
    assert.doesNotMatch(readFileSync(gate.sigPath, 'utf8'), /PRIVATE KEY/);
    assert.equal(published.alg, 'ed25519');
    assert.equal(published.fingerprint, keys.fingerprint);
    assert.notEqual(published.sha256, sourceSig.sha256);
    assert.equal(published.sha256, gate.sha256);

    const checked = cliResult(dir, ['verify', gate.markdownPath, '--require-sig', '--json']);
    assert.equal(checked.code, 0, checked.out + checked.err);
    assert.equal(parseJson(checked.out).signature.ok, true);
    assert.equal(existsSync(`${gate.htmlPath}.sig.json`), false);
  });

  it('share --md without keys does not copy a stale sidecar after redact', () => {
    const dir = initRepo('agent-receipt-1017-share-nokeys-');
    wrapClean(dir, 'redact-unsigned');
    cli(dir, ['keygen']);
    const source = parseJson(cli(dir, ['sign', '--json']));
    rmSync(join(dir, '.agent-receipt', 'keys'), { recursive: true, force: true });

    const shared = cliResult(dir, ['share', '--md', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.sigPath, null);
    assert.equal(gate.redacted, true);
    assert.equal(existsSync(sigBeside(gate.markdownPath)), false);
    assert.equal(existsSync(source.sigPath), true);
    assert.match(shared.err + shared.out, /keygen/);
    assert.match(shared.err + shared.out, /sign/);

    const checked = cliResult(dir, ['verify', gate.markdownPath, '--require-sig']);
    assert.equal(checked.code, 2, checked.out + checked.err);
  });

  it('share --no-redact copies a valid sidecar without local keys', () => {
    const dir = initRepo('agent-receipt-1017-share-copy-');
    wrapClean(dir, 'copy-sig');
    cli(dir, ['keygen']);
    const source = parseJson(cli(dir, ['sign', '--json']));
    const sourceBytes = readFileSync(source.sigPath);
    rmSync(join(dir, '.agent-receipt', 'keys'), { recursive: true, force: true });

    const shared = cliResult(dir, ['share', '--no-redact', '--md', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.redacted, false);
    assert.equal(gate.sigPath, sigBeside(gate.markdownPath));
    assert.equal(readFileSync(gate.sigPath).equals(sourceBytes), true);
    const checked = cliResult(dir, ['verify', gate.markdownPath, '--require-sig', '--json']);
    assert.equal(checked.code, 0, checked.out + checked.err);
    assert.equal(parseJson(checked.out).signature.ok, true);
  });

  it('html-only share does not invent a signature, and export markdown re-signs', () => {
    const dir = initRepo('agent-receipt-1017-html-export-');
    wrapClean(dir, 'html-only');
    cli(dir, ['keygen']);
    const htmlOnly = cliResult(dir, ['share', '--json']);
    assert.equal(htmlOnly.code, 0, htmlOnly.out + htmlOnly.err);
    const shareGate = parseJson(htmlOnly.out);
    assert.equal(shareGate.markdownPath, null);
    assert.equal(shareGate.sigPath, null);
    assert.equal(existsSync(shareGate.htmlPath + '.sig.json'), false);

    const exported = cliResult(dir, [
      'export',
      '--format',
      'markdown',
      '--redact',
      '--out',
      'published.md',
    ]);
    assert.equal(exported.code, 0, exported.out + exported.err);
    const mdPath = join(dir, 'published.md');
    const sigPath = sigBeside(mdPath);
    assert.equal(existsSync(sigPath), true);
    assert.doesNotMatch(readFileSync(sigPath, 'utf8'), /PRIVATE KEY/);
    const checked = cliResult(dir, ['verify', mdPath, '--require-sig']);
    assert.equal(checked.code, 0, checked.out + checked.err);
  });

  it('doctor --strict fails unset retention on a small outDir; default stays info', () => {
    const dir = initRepo('agent-receipt-1017-retention-');
    cli(dir, ['init', '--org']);
    const plain = cliResult(dir, ['doctor', '--json']);
    assert.equal(plain.code, 0, plain.out + plain.err);
    const open = parseJson(plain.out);
    const openRetention = open.checks.find((c) => c.id === 'retention');
    assert.equal(openRetention.status, 'info');

    const strict = cliResult(dir, ['doctor', '--strict', '--json']);
    assert.equal(strict.code, 1, strict.out + strict.err);
    const body = parseJson(strict.out);
    assert.equal(body.ok, false);
    assert.equal(body.strict, true);
    const policy = body.checks.find((c) => c.id === 'policy');
    const retention = body.checks.find((c) => c.id === 'retention');
    assert.equal(policy.status, 'pass');
    assert.equal(retention.status, 'fail');
    assert.match(retention.detail, /any outDir/);

    cli(dir, ['init', '--retention']);
    const fixed = cliResult(dir, ['doctor', '--strict', '--json']);
    assert.equal(fixed.code, 0, fixed.out + fixed.err);
    const fixedBody = parseJson(fixed.out);
    assert.equal(fixedBody.checks.find((c) => c.id === 'retention').status, 'pass');
  });
});

describe('v1.0.17 docs', () => {
  it('documents require-sig, the sidecar handoff, and version 1.0.17', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.17\]/);
    assert.match(changelog, /--require-sig/);
    assert.match(changelog, /sigPath/);
    assert.match(changelog, /fingerprint trust store/);
    assert.match(changelog, /auto-sign on capture/);
    assert.match(changelog, /not\*\* updated|was not edited/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.23');
    assert.equal(pkg.dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.23/);
    const helpVerify = cli(root, ['help', 'verify']);
    assert.match(helpVerify, /--require-sig/);
    assert.match(helpVerify, /hash-only/);
    assert.match(helpVerify, /signature absent/);
    const helpShare = cli(root, ['help', 'share']);
    assert.match(helpShare, /re-sign|re-signed|copied/i);
    assert.match(helpShare, /sigPath/);
    const helpExport = cli(root, ['help', 'export']);
    assert.match(helpExport, /sidecar/);
    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /require-sig/);
    assert.match(action, /v1\.0\.17/);
    const gate = readFileSync(join(root, 'examples', 'github', 'pr-gate.yml'), 'utf8');
    assert.match(gate, /require-sig/);
    assert.match(gate, /keygen/);
    assert.match(gate, /v1\.0\.17/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /verify --require-sig/);
    assert.match(mirror, /v1\.0\.17/);
    assert.match(mirror, /signature absent/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /require-sig/);
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'gate.schema.json'), 'utf8'));
    assert.equal(schema.properties.signature.type.includes('object'), true);
    assert.equal(schema.required.includes('signature'), false);
    assert.equal(schema.required.includes('sigPath'), false);
    const security = readFileSync(join(root, 'SECURITY.md'), 'utf8');
    assert.match(security, /--require-sig/);
    assert.match(security, /no CA|not a CA|no certificate authority|There is no CA/i);
  });
});
