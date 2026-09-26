import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const PASSWORD = 'SuperSecretPass123';

const PROVE_KEYS = [
  'agent',
  'audit',
  'command',
  'exitCode',
  'failOn',
  'failedOn',
  'ok',
  'path',
  'reason',
  'redacted',
  'risk',
  'sha256',
  'signature',
  'tldr',
  'trailingIgnored',
  'uncommitted',
  'verified',
  'version',
];

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

describe('v1.0.13 prove-this-run', () => {
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
    writeFileSync(join(dir, 'README.md'), '# prove\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    git(dir, ['add', '-A']);
    git(dir, ['commit', '-m', 'init agent-receipt']);
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

  function breakAudit(dir) {
    const logPath = join(dir, '.agent-receipt', 'audit.jsonl');
    const lines = readFileSync(logPath, 'utf8').trim().split('\n');
    const first = JSON.parse(lines[0]);
    first.prev = 'deadbeef';
    lines[0] = JSON.stringify(first);
    writeFileSync(logPath, lines.join('\n') + '\n');
    return logPath;
  }

  it('proves a fresh wrap: verified, trailingIgnored false, audit linked, json shape', () => {
    const dir = initRepo('agent-receipt-prove-');
    wrapClean(dir, 'prove-target');
    const human = cli(dir, ['prove']);
    assert.match(human, /PROVED/);
    assert.match(human, /trailingIgnored: no/);
    assert.match(human, /audit: present, chain OK/);
    assert.match(human, /matched/);
    assert.match(human, /not a cryptographic signature/);
    assert.doesNotMatch(human, /Verifying:/);

    const r = cliResult(dir, ['prove', '--json']);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out.trim().split('\n').length, 1);
    const body = parseJson(r.out);
    assert.deepEqual(Object.keys(body).sort(), PROVE_KEYS);
    assert.equal(body.ok, true);
    assert.equal(body.command, 'prove');
    assert.equal(body.version, '1.0.27');
    assert.equal(body.exitCode, 0);
    assert.equal(body.verified, true);
    assert.equal(body.trailingIgnored, false);
    assert.equal(body.failedOn, false);
    assert.equal(body.failOn, null);
    assert.equal(body.reason, null);
    assert.equal(body.agent, 'ci');
    assert.equal(typeof body.sha256, 'string');
    assert.equal(body.sha256.length, 64);
    assert.equal(typeof body.tldr, 'string');
    assert.ok(body.path.endsWith('.md'));
    assert.equal(typeof body.uncommitted, 'boolean');
    assert.deepEqual(Object.keys(body.risk).sort(), [
      'high',
      'low',
      'maxSeverity',
      'medium',
      'total',
    ]);
    assert.deepEqual(Object.keys(body.audit).sort(), [
      'chainOk',
      'events',
      'matched',
      'present',
      'reason',
    ]);
    assert.equal(body.audit.present, true);
    assert.equal(body.audit.chainOk, true);
    assert.equal(body.audit.matched, true);
    assert.ok(body.audit.events >= 1);
    assert.equal(body.audit.reason, null);
    assert.equal(body.signature.present, false);
    assert.equal(body.signature.ok, null);
    assert.equal(body.signature.alg, null);
    assert.equal(body.signature.fingerprint, null);
    assert.equal(body.signature.reason, null);

    const last = parseJson(cli(dir, ['last', '--json']));
    assert.equal(last.ok, true);
    assert.equal(last.command, 'last');
    assert.equal(last.version, '1.0.27');
    assert.equal(last.path, body.path);
    assert.equal(last.sha256, body.sha256);
    assert.equal(last.agent, 'ci');
    assert.equal(typeof last.failedOn, 'boolean');
    assert.equal(typeof last.uncommitted, 'boolean');
    assert.equal(last.failedOn, false);

    const both = cli(dir, ['last', '--json', '--path']);
    const bothBody = parseJson(both);
    assert.equal(bothBody.command, 'last');
    assert.notEqual(both.trim(), bothBody.path);
    assert.match(cli(dir, ['last']), /latest:/);
  });

  it('fails a tampered body with exit 2', () => {
    const dir = initRepo('agent-receipt-prove-tamper-');
    wrapClean(dir, 'prove-target');
    const ok = parseJson(cli(dir, ['prove', '--json']));
    const text = readFileSync(ok.path, 'utf8');
    writeFileSync(ok.path, text.replace('prove-target', 'tampered-body'));
    const bad = cliResult(dir, ['prove', '--json']);
    assert.equal(bad.code, 2, bad.out + bad.err);
    const body = parseJson(bad.out);
    assert.equal(body.ok, false);
    assert.equal(body.verified, false);
    assert.equal(body.exitCode, 2);
    assert.equal(body.command, 'prove');
    const human = cliResult(dir, ['prove']);
    assert.equal(human.code, 2);
    assert.match(human.out, /FAILED/);
  });

  it('fails a broken audit chain even when the hash matches', () => {
    const dir = initRepo('agent-receipt-prove-audit-');
    wrapClean(dir, 'audit-break');
    breakAudit(dir);
    const bad = cliResult(dir, ['prove', '--json']);
    assert.equal(bad.code, 2, bad.out + bad.err);
    const body = parseJson(bad.out);
    assert.equal(body.ok, false);
    assert.equal(body.verified, true);
    assert.equal(body.exitCode, 2);
    assert.equal(body.audit.present, true);
    assert.equal(body.audit.chainOk, false);
    assert.equal(typeof body.audit.reason, 'string');
    assert.match(body.reason, /audit chain broken/);
  });

  it('treats a missing audit log as present false and still exits 0', () => {
    const dir = initRepo('agent-receipt-prove-noaudit-');
    wrapClean(dir, 'no-audit');
    rmSync(join(dir, '.agent-receipt', 'audit.jsonl'));
    const r = cliResult(dir, ['prove', '--json']);
    assert.equal(r.code, 0, r.out + r.err);
    const body = parseJson(r.out);
    assert.equal(body.audit.present, false);
    assert.equal(body.audit.chainOk, null);
    assert.equal(body.audit.matched, false);
    assert.equal(body.audit.events, 0);
    assert.equal(body.verified, true);
  });

  it('reports trailingIgnored and does not apply config failOn', () => {
    const dir = initRepo('agent-receipt-prove-trail-');
    wrapClean(dir, 'trail-target');
    const before = parseJson(cli(dir, ['verify', '--json']));
    assert.equal(before.command, 'verify');
    assert.equal(before.trailingIgnored, false);
    const path = before.path;
    writeFileSync(
      path,
      readFileSync(path, 'utf8') + '\n\n## Notes\n\nappended after integrity\n',
    );
    const verify = cliResult(dir, ['verify', '--json']);
    assert.equal(verify.code, 0, verify.err);
    assert.equal(parseJson(verify.out).trailingIgnored, true);
    const proved = cliResult(dir, ['prove', '--json']);
    assert.equal(proved.code, 0, proved.err);
    assert.equal(parseJson(proved.out).trailingIgnored, true);
    assert.equal(parseJson(proved.out).verified, true);

    const yml = readFileSync(join(dir, '.agent-receipt.yml'), 'utf8');
    writeFileSync(join(dir, '.agent-receipt.yml'), `${yml}\nfailOn: high\n`);
    const ignored = cliResult(dir, ['prove', '--json']);
    assert.equal(ignored.code, 0, ignored.out + ignored.err);
    assert.equal(parseJson(ignored.out).failOn, null);
  });

  it('prove --fail-on high trips on a high-risk receipt; a stored false stays out otherwise', () => {
    const dir = initRepo('agent-receipt-prove-failon-');
    writeFileSync(
      join(dir, '.env'),
      `DATABASE_URL=postgres://app:${PASSWORD}!@db.internal:5432/app\n`,
    );
    git(dir, ['add', '.env']);
    git(dir, ['commit', '-m', 'add env']);
    const captured = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'ci',
      '--message',
      'leaky',
      '--no-redact',
    ]);
    assert.equal(captured.code, 0, captured.out + captured.err);

    const plain = cliResult(dir, ['prove', '--json']);
    assert.equal(plain.code, 0, plain.out + plain.err);
    const stored = parseJson(plain.out);
    assert.equal(stored.verified, true);
    assert.equal(stored.failedOn, false);
    assert.equal(stored.failOn, null);
    assert.ok(stored.risk.high >= 1);

    const tripped = cliResult(dir, ['prove', '--json', '--fail-on', 'high']);
    assert.equal(tripped.code, 2, tripped.out + tripped.err);
    const body = parseJson(tripped.out);
    assert.equal(body.ok, false);
    assert.equal(body.verified, true);
    assert.equal(body.failedOn, true);
    assert.equal(body.failOn, 'high');
    assert.equal(body.exitCode, 2);
  });

  it('last --json errors on an empty store; prove --json errors as one object', () => {
    const dir = initRepo('agent-receipt-prove-empty-');
    const last = cliResult(dir, ['last', '--json']);
    assert.equal(last.code, 1);
    assert.equal(last.out.trim(), '');
    assert.match(last.err, /No receipt/);

    const proved = cliResult(dir, ['prove', '--json']);
    assert.equal(proved.code, 1);
    const body = parseJson(proved.out);
    assert.equal(body.ok, false);
    assert.equal(body.command, 'prove');
    assert.equal(body.exitCode, 1);
    assert.equal(body.verified, null);
    assert.equal(body.trailingIgnored, null);

    const unknown = cliResult(dir, ['prove', '--json', '--bogus']);
    assert.equal(unknown.code, 1);
    assert.equal(parseJson(unknown.out).exitCode, 1);
    const badFail = cliResult(dir, ['prove', '--json', '--fail-on', 'nope']);
    assert.equal(badFail.code, 1);
    assert.match(parseJson(badFail.out).reason, /fail-on/);
  });

  it('sets trailingIgnored on verify/wrap/share gates and null on capture', () => {
    const dir = initRepo('agent-receipt-prove-gate-');
    const captured = cliResult(dir, [
      'capture',
      '--json',
      '--commits',
      '1',
      '--agent',
      'ci',
      '--message',
      'cap',
    ]);
    assert.equal(captured.code, 0, captured.err);
    const cap = parseJson(captured.out);
    assert.equal(cap.command, 'capture');
    assert.equal(cap.trailingIgnored, null);

    const wrapped = cliResult(dir, ['wrap', '--json', '--agent', 'ci', '--message', 'gate']);
    assert.equal(wrapped.code, 0, wrapped.err);
    const wrap = parseJson(wrapped.out);
    assert.equal(wrap.command, 'wrap');
    assert.equal(typeof wrap.trailingIgnored, 'boolean');
    assert.equal(wrap.trailingIgnored, false);

    const shared = cliResult(dir, ['share', '--json']);
    assert.equal(shared.code, 0, shared.err);
    const share = parseJson(shared.out);
    assert.equal(share.command, 'share');
    assert.equal(typeof share.trailingIgnored, 'boolean');
  });

  it('doctor --strict fails a broken audit chain; default doctor only warns', () => {
    const dir = initRepo('agent-receipt-prove-doctor-');
    wrapClean(dir, 'doctor-audit');
    breakAudit(dir);

    const plain = cliResult(dir, ['doctor', '--json']);
    assert.equal(plain.code, 0, plain.out + plain.err);
    const plainBody = parseJson(plain.out);
    assert.equal(plainBody.strict, false);
    assert.equal(plainBody.ok, true);
    const plainAudit = plainBody.checks.find((c) => c.id === 'audit');
    assert.equal(plainAudit.status, 'warn');
    assert.match(plainAudit.detail, /chain broken/);

    const human = cliResult(dir, ['doctor']);
    assert.equal(human.code, 0, human.out);
    assert.match(human.out, /\[WARN\].*audit/);
    assert.doesNotMatch(human.out, /\[FAIL\].*audit/);

    // Policy is set so this asserts the audit row. Unset policy would also fail --strict.
    cli(dir, ['init', '--org']);
    const strict = cliResult(dir, ['doctor', '--strict', '--json']);
    assert.equal(strict.code, 1, strict.out + strict.err);
    const strictBody = parseJson(strict.out);
    assert.equal(strictBody.ok, false);
    assert.equal(strictBody.strict, true);
    assert.equal(strictBody.exitCode, 1);
    const strictAudit = strictBody.checks.find((c) => c.id === 'audit');
    assert.equal(strictAudit.status, 'fail');
    assert.match(strictAudit.detail, /chain broken/);
    const policy = strictBody.checks.find((c) => c.id === 'policy');
    assert.equal(policy.status, 'pass');

    const humanStrict = cliResult(dir, ['doctor', '--strict']);
    assert.equal(humanStrict.code, 1);
    assert.match(humanStrict.out, /\[FAIL\].*audit/);
  });
});

describe('v1.0.13 docs', () => {
  it('documents prove, last --json, trailingIgnored, and strict audit without the live workflow', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.13\]/);
    assert.match(changelog, /prove \[path\]/);
    assert.match(changelog, /last --json/);
    assert.match(changelog, /trailingIgnored/);
    assert.match(changelog, /cryptographic signing/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /prove --json/);
    assert.match(mirror, /last --json/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /prove --json/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /prove --json/);
    assert.match(business, /trailingIgnored/);
    assert.match(business, /broken audit chain/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /agent-receipt prove/);
    assert.match(readme, /last --json/);
    assert.match(readme, /trailingIgnored/);
    const policy = readFileSync(join(root, 'examples', 'org-policy.yml'), 'utf8');
    assert.match(policy, /prove --json/);
    assert.match(policy, /last --json/);
    assert.equal(/^maxCount:/m.test(policy), false);
    assert.equal(/^maxAgeDays:/m.test(policy), false);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.27');
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.27/);
    const help = cliResult(root, ['help', 'prove']);
    assert.equal(help.code, 0, help.err);
    assert.match(help.out, /prove-this-run/);
    assert.match(help.out, /not a cryptographic signature/);
    assert.match(cliResult(root, ['help', 'last']).out, /--json/);
    assert.match(cliResult(root, ['help', 'verify']).out, /trailingIgnored/);
    assert.match(cliResult(root, ['help', 'doctor']).out, /broken audit chain/);
    assert.match(cliResult(root, ['help']).out, /\bprove\b/);
  });
});
