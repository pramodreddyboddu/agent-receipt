import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const OTHER = 'c'.repeat(64);

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

describe('v1.0.20 trust add --self', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1020-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# trust-add-self\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  it('documents version 1.0.20, trust add --self, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.20\]/);
    assert.match(changelog, /trust add --self/);
    assert.match(changelog, /added: false|Already listed/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    assert.match(changelog, /not a CA/i);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.20');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.20');
    assert.equal(lock.packages[''].version, '1.0.20');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.20/);

    const help = cli(root, ['help', 'trust']);
    assert.match(help, /trust add --self/);
    assert.match(help, /keygen/);
    assert.match(help, /not a CA/i);

    const recipe = readFileSync(join(root, 'docs', 'ci-signed-gate.md'), 'utf8');
    assert.match(recipe, /trust add --self/);
    assert.match(recipe, /not a CA/i);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /trust add --self/);
    assert.match(business, /not a CA/i);

    const gate = readFileSync(join(root, 'examples', 'github', 'pr-gate.yml'), 'utf8');
    assert.match(gate, /trust add --self/);
    assert.match(gate, /v1\.0\.20/);
    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /trust add --self/);
    assert.match(action, /v1\.0\.20/);
    const policy = readFileSync(join(root, 'examples', 'org-policy.yml'), 'utf8');
    assert.match(policy, /v1\.0\.20/);

    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /v1\.0\.20/);
    assert.match(mirror, /trust add --self/);
    assert.match(mirror, /signature\.trusted/);

    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /trust add --self/);
    assert.match(readme, /v1\.0\.20/);

    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /trust add --self/);
      assert.doesNotMatch(live, /v1\.0\.20/);
    }
  });

  it('trust add --self without keys exits 1 and names keygen', () => {
    const dir = initRepo();
    const missing = cliResult(dir, ['trust', 'add', '--self']);
    assert.equal(missing.code, 1);
    assert.match(`${missing.out}\n${missing.err}`, /keygen/);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'trusted-keys.txt')), false);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'keys', 'ed25519.private')), false);

    const missingJson = cliResult(dir, ['trust', 'add', '--json', '--self']);
    assert.equal(missingJson.code, 1);
    const body = parseJson(missingJson.out);
    assert.equal(body.ok, false);
    assert.equal(body.command, 'trust');
    assert.equal(body.action, 'add');
    assert.equal(body.exitCode, 1);
    assert.match(body.reason, /keygen/);

    const manual = parseJson(cli(dir, ['trust', 'add', OTHER, '--json']));
    assert.equal(manual.ok, true);
    assert.equal(manual.added, true);
    assert.equal(manual.action, 'add');
    assert.equal(manual.fingerprint, undefined);
    assert.deepEqual(manual.fingerprints, [OTHER]);
  });

  it('keygen then trust add --self allowlists the fingerprint and is idempotent', () => {
    const dir = initRepo();
    writeFileSync(join(dir, 'note.txt'), 'self trust\n');
    git(dir, ['add', 'note.txt']);
    git(dir, ['commit', '-m', 'note']);

    const keys = parseJson(cli(dir, ['keygen', '--json']));
    assert.equal(keys.ok, true);
    assert.equal(keys.fingerprint.length, 64);
    const privPath = join(dir, '.agent-receipt', 'keys', 'ed25519.private');
    const privBefore = readFileSync(privPath, 'utf8');
    const cfgPath = join(dir, '.agent-receipt.yml');
    const cfgBefore = readFileSync(cfgPath, 'utf8');

    const added = parseJson(cli(dir, ['trust', 'add', '--json', '--self']));
    assert.equal(added.ok, true);
    assert.equal(added.command, 'trust');
    assert.equal(added.action, 'add');
    assert.equal(added.exitCode, 0);
    assert.equal(added.added, true);
    assert.equal(added.fingerprint, keys.fingerprint);
    assert.equal(added.active, true);
    assert.ok(added.fingerprints.includes(keys.fingerprint));
    const file = readFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), 'utf8');
    assert.match(file, new RegExp(`^${keys.fingerprint}$`, 'm'));
    assert.equal(readFileSync(privPath, 'utf8'), privBefore);
    assert.equal(readFileSync(cfgPath, 'utf8'), cfgBefore);
    assert.doesNotMatch(cfgBefore, new RegExp(keys.fingerprint));

    const again = parseJson(cli(dir, ['trust', 'add', '--self', '--json']));
    assert.equal(again.ok, true);
    assert.equal(again.added, false);
    assert.equal(again.exitCode, 0);
    assert.equal(again.fingerprint, keys.fingerprint);
    const listed = file.split(/\r?\n/).filter((line) => line === keys.fingerprint);
    const after = readFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), 'utf8');
    assert.deepEqual(
      after.split(/\r?\n/).filter((line) => line === keys.fingerprint),
      listed,
    );

    const human = cli(dir, ['trust', 'add', '--self']);
    assert.match(human, /already listed/);
    assert.match(human, new RegExp(keys.fingerprint));

    rmSync(join(dir, '.agent-receipt', 'trusted-keys.txt'));
    const alias = parseJson(cli(dir, ['trust', 'add', 'self', '--json']));
    assert.equal(alias.ok, true);
    assert.equal(alias.added, true);
    assert.equal(alias.action, 'add');
    assert.equal(alias.fingerprint, keys.fingerprint);

    const both = cliResult(dir, ['trust', 'add', '--self', OTHER]);
    assert.equal(both.code, 1);
    assert.match(`${both.out}\n${both.err}`, /does not take a fingerprint/);
    const listSelf = cliResult(dir, ['trust', 'list', '--self']);
    assert.equal(listSelf.code, 1);
    assert.match(`${listSelf.out}\n${listSelf.err}`, /does not accept --self/);

    const wrapped = cliResult(dir, [
      'wrap',
      '--sign',
      '--agent',
      'ci',
      '--message',
      'self trust',
      '--json',
    ]);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    const proved = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(proved.ok, true);
    assert.equal(proved.exitCode, 0);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.trusted, true);
    assert.equal(proved.signature.fingerprint, keys.fingerprint);

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
