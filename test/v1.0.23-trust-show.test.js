import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const FP = 'ab'.repeat(32);

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

describe('v1.0.23 trust show', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1023-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# trust-show\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  it('documents version 1.0.23, trust show, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.23\]/);
    assert.match(changelog, /trust show/);
    assert.match(changelog, /localListed/);
    assert.match(changelog, /read-only/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /HTML\/share signed package/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    assert.match(changelog, /not a CA/i);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.27');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.27');
    assert.equal(lock.packages[''].version, '1.0.27');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.27/);

    const help = cli(root, ['help', 'trust']);
    assert.match(help, /trust show \[--json\]/);
    assert.match(help, /read-only/);
    assert.match(help, /trust add --self/);
    assert.match(help, /not a CA/i);

    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /trust show/);
    assert.match(business, /1\.0\.23/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.23/);
    assert.match(mirror, /trust show/);

    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /trust show/);
      assert.doesNotMatch(live, /v1\.0\.23/);
    }
  });

  it('no keys and an empty store: inactive, local none, does not create the file', () => {
    const dir = initRepo();
    const store = join(dir, '.agent-receipt', 'trusted-keys.txt');
    assert.equal(existsSync(store), false);
    const human = cliResult(dir, ['trust', 'show']);
    assert.equal(human.code, 0, human.out + human.err);
    assert.match(human.out, /trust show/);
    assert.match(human.out, /trusted-keys/);
    assert.match(human.out, /active: false/);
    assert.match(human.out, /count: 0/);
    assert.match(human.out, /file: \.agent-receipt\/trusted-keys\.txt/);
    assert.match(human.out, /local: \(none — run keygen\)/);
    assert.match(human.out, /localListed: n\/a/);
    assert.equal(existsSync(store), false);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'keys', 'ed25519.private')), false);

    const body = parseJson(cli(dir, ['trust', 'show', '--json']));
    assert.equal(body.ok, true);
    assert.equal(body.command, 'trust');
    assert.equal(body.action, 'show');
    assert.equal(body.exitCode, 0);
    assert.equal(body.active, false);
    assert.equal(body.count, 0);
    assert.deepEqual(body.fingerprints, []);
    assert.equal(body.localFingerprint, null);
    assert.equal(body.localListed, null);
    assert.equal(body.reason, null);
    assert.equal(typeof body.path, 'string');
    assert.match(body.path, /trusted-keys\.txt/);
    assert.ok(Array.isArray(body.sources));
    assert.equal(existsSync(store), false);
  });

  it('keygen only: inactive, local fingerprint set, localListed false', () => {
    const dir = initRepo();
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const store = join(dir, '.agent-receipt', 'trusted-keys.txt');
    const priv = join(dir, '.agent-receipt', 'keys', 'ed25519.private');
    const privBefore = readFileSync(priv, 'utf8');
    const cfgBefore = readFileSync(join(dir, '.agent-receipt.yml'), 'utf8');

    const human = cli(dir, ['trust', 'show']);
    assert.match(human, /active: false/);
    assert.match(human, new RegExp(`local: ${keys.fingerprint}`));
    assert.match(human, /localListed: false/);
    assert.match(human, /trust add --self/);
    assert.equal(existsSync(store), false);

    const body = parseJson(cli(dir, ['trust', 'status', '--json']));
    assert.equal(body.action, 'show');
    assert.equal(body.ok, true);
    assert.equal(body.exitCode, 0);
    assert.equal(body.active, false);
    assert.equal(body.count, 0);
    assert.equal(body.localFingerprint, keys.fingerprint);
    assert.equal(body.localListed, false);
    assert.equal(body.localFingerprint.length, 64);
    assert.equal(readFileSync(priv, 'utf8'), privBefore);
    assert.equal(readFileSync(join(dir, '.agent-receipt.yml'), 'utf8'), cfgBefore);
    assert.equal(existsSync(store), false);
  });

  it('keygen plus trust add --self: active, localListed true, fingerprint listed', () => {
    const dir = initRepo();
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    cli(dir, ['trust', 'add', '--self']);
    const store = join(dir, '.agent-receipt', 'trusted-keys.txt');
    const before = readFileSync(store, 'utf8');
    const stamp = statSync(store).mtimeMs;

    const human = cli(dir, ['trust', 'show']);
    assert.match(human, /active: true/);
    assert.match(human, /count: 1/);
    assert.match(human, /localListed: true/);
    assert.match(human, new RegExp(keys.fingerprint));

    const body = parseJson(cli(dir, ['trust', 'show', '--json']));
    assert.equal(body.ok, true);
    assert.equal(body.command, 'trust');
    assert.equal(body.action, 'show');
    assert.equal(body.exitCode, 0);
    assert.equal(body.active, true);
    assert.equal(body.count, 1);
    assert.ok(body.fingerprints.includes(keys.fingerprint));
    assert.ok(Array.isArray(body.sources));
    assert.ok(body.sources.length >= 1);
    assert.equal(body.localFingerprint, keys.fingerprint);
    assert.equal(body.localListed, true);
    assert.equal(typeof body.path, 'string');
    assert.match(String(body.path || body.file), /trusted-keys\.txt/);

    assert.equal(readFileSync(store, 'utf8'), before);
    assert.equal(statSync(store).mtimeMs, stamp);

    const listed = parseJson(cli(dir, ['trust', 'list', '--json']));
    assert.equal(listed.action, 'list');
    assert.equal(listed.localFingerprint, undefined);
    assert.equal(listed.localListed, undefined);
    assert.ok(listed.fingerprints.includes(keys.fingerprint));
  });

  it('trust show does not modify trusted-keys.txt and rejects a fingerprint argument', () => {
    const dir = initRepo();
    const store = join(dir, '.agent-receipt', 'trusted-keys.txt');
    writeFileSync(store, `${FP}\n# keep\n`);
    const before = readFileSync(store, 'utf8');
    const stamp = statSync(store).mtimeMs;

    const shown = parseJson(cli(dir, ['trust', 'show', '--json']));
    assert.equal(shown.active, true);
    assert.equal(shown.localFingerprint, null);
    assert.equal(shown.localListed, null);
    assert.deepEqual(shown.fingerprints, [FP]);
    cli(dir, ['trust', 'show']);
    assert.equal(readFileSync(store, 'utf8'), before);
    assert.equal(statSync(store).mtimeMs, stamp);

    const extra = cliResult(dir, ['trust', 'show', FP]);
    assert.equal(extra.code, 1);
    assert.match(`${extra.out}\n${extra.err}`, /takes no fingerprint/);
    assert.equal(readFileSync(store, 'utf8'), before);

    const badText = 'not-a-fingerprint\n';
    writeFileSync(store, badText);
    const bad = cliResult(dir, ['trust', 'show', '--json']);
    assert.equal(bad.code, 1);
    const failed = parseJson(bad.out);
    assert.equal(failed.ok, false);
    assert.equal(failed.action, 'show');
    assert.equal(failed.exitCode, 1);
    assert.match(failed.reason, /invalid fingerprint/);
    assert.equal(readFileSync(store, 'utf8'), badText);
  });
});
