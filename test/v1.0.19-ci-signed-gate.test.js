import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync, readFileSync } from 'node:fs';
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

describe('v1.0.19 CI signed gate', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1019-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# signed-gate\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  it('documents version 1.0.19, the signed CI drop-in, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.19\]/);
    assert.match(changelog, /sign/);
    assert.match(changelog, /auto-trust|trusted-keys/);
    assert.match(changelog, /wrap --sign/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.22');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.22');
    assert.equal(lock.packages[''].version, '1.0.22');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.22/);

    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /sign:/);
    assert.match(action, /default: "false"/);
    assert.match(action, /--sign/);
    assert.match(action, /v1\.0\.19/);
    assert.match(action, /keygen/);
    assert.match(action, /fails closed|fail closed/i);
    assert.match(action, /require-sig/);
    assert.match(action, /trusted-keys/);
    assert.match(action, /signature\.trusted/);

    const gate = readFileSync(join(root, 'examples', 'github', 'pr-gate.yml'), 'utf8');
    assert.match(gate, /v1\.0\.19/);
    assert.match(gate, /require-sig/);
    assert.match(gate, /trusted-keys/);
    assert.match(gate, /auto-trust/);
    assert.match(gate, /signature\.trusted/);
    assert.match(gate, /sign:/);

    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /v1\.0\.19/);
    assert.match(mirror, /wrap --sign/);
    assert.match(mirror, /signature\.ok/);
    assert.match(mirror, /signature\.trusted/);

    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /require-sig/);
    assert.match(business, /trusted-keys|trust store|allowlist/);
    assert.match(business, /wrap --sign/);
    const recipe = readFileSync(join(root, 'docs', 'ci-signed-gate.md'), 'utf8');
    assert.match(recipe, /require-sig/);
    assert.match(recipe, /trusted-keys/);
    assert.match(recipe, /wrap --sign/);
    assert.match(recipe, /not a CA/i);

    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /ci-signed-gate\.md/);
    assert.match(readme, /v1\.0\.19/);

    const helpWrap = cli(root, ['help', 'wrap']);
    assert.match(helpWrap, /--sign/);
    assert.match(helpWrap, /ci-signed-gate\.md/);
    const helpCapture = cli(root, ['help', 'capture']);
    assert.match(helpCapture, /--sign/);
    assert.match(helpCapture, /fails closed/);

    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /wrap --sign/);
      assert.doesNotMatch(live, /v1\.0\.19/);
    }
  });

  it('wrap --sign after keygen writes a sidecar and proves signature.ok', () => {
    const dir = initRepo();
    writeFileSync(join(dir, 'note.txt'), 'signed gate\n');
    git(dir, ['add', 'note.txt']);
    git(dir, ['commit', '-m', 'note']);
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    assert.equal(keys.ok, true);
    assert.equal(keys.fingerprint.length, 64);

    const wrapped = cliResult(dir, [
      'wrap',
      '--sign',
      '--agent',
      'ci',
      '--message',
      'signed gate',
      '--json',
    ]);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    const gate = parseJson(wrapped.out);
    assert.equal(gate.ok, true);
    assert.equal(gate.exitCode, 0);
    assert.equal(typeof gate.path, 'string');
    const sig = gate.path.replace(/\.md$/i, '.sig.json');
    assert.equal(existsSync(sig), true);

    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.ok, true);
    assert.equal(proved.exitCode, 0);
    assert.equal(proved.signature.present, true);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.fingerprint, keys.fingerprint);
    assert.equal(proved.signature.trusted, null);
  });

  it('a matching trust store sets signature.trusted and verify --require-sig exits 0', () => {
    const dir = initRepo();
    writeFileSync(join(dir, 'note.txt'), 'trusted gate\n');
    git(dir, ['add', 'note.txt']);
    git(dir, ['commit', '-m', 'note']);
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const wrapped = cliResult(dir, [
      'wrap',
      '--sign',
      '--agent',
      'ci',
      '--message',
      'trusted gate',
      '--json',
    ]);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    writeFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), `${keys.fingerprint}\n`);

    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.ok, true);
    assert.equal(proved.exitCode, 0);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.trusted, true);

    const verified = cliResult(dir, ['verify', '--require-sig', '--json']);
    assert.equal(verified.code, 0, verified.out + verified.err);
    const gate = parseJson(verified.out);
    assert.equal(gate.ok, true);
    assert.equal(gate.exitCode, 0);
    assert.equal(gate.signature.ok, true);
    assert.equal(gate.signature.trusted, true);
    assert.equal(gate.signature.fingerprint, keys.fingerprint);
  });
});
