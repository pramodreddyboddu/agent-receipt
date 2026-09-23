import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const PAGE_LABELS = [
  'path',
  'sha256',
  'verified',
  'trailingIgnored',
  'redacted',
  'risk',
  'tldr',
  'agent',
  'uncommitted',
  'failedOn',
  'audit',
  'signature',
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

function listProvePages(dir) {
  const hits = [];
  const walk = (current) => {
    for (const name of readdirSync(current, { withFileTypes: true })) {
      if (name.name === '.git') continue;
      const path = join(current, name.name);
      if (name.isDirectory()) walk(path);
      else if (name.name.endsWith('.prove.md')) hits.push(path);
    }
  };
  walk(dir);
  return hits;
}

describe('v1.0.21 prove human one-pager', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1021-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# prove-page\n');
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

  it('documents version 1.0.21, prove --page, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.21\]/);
    assert.match(changelog, /prove --page/);
    assert.match(changelog, /pagePath/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    assert.match(changelog, /not a CA/i);
    assert.match(changelog, /HTML\/share signed package/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.26');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.26');
    assert.equal(lock.packages[''].version, '1.0.26');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.26/);

    const help = cli(root, ['help', 'prove']);
    assert.match(help, /prove --page/);
    assert.match(help, /--out/);
    assert.match(help, /--one-pager/);
    assert.match(help, /not a certificate authority|not a CA/i);
    assert.match(help, /foo\.prove\.md/);

    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /prove --page/);
    assert.match(business, /1\.0\.21/);
    assert.match(business, /not a CA/i);
    const recipe = readFileSync(join(root, 'docs', 'ci-signed-gate.md'), 'utf8');
    assert.match(recipe, /prove --page/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /prove --page/);
    assert.match(readme, /v1\.0\.21/);

    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.21/);
    assert.match(mirror, /prove --json --page|prove --page/);
    assert.match(mirror, /pagePath/);

    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /v1\.0\.21/);
    const gate = readFileSync(join(root, 'examples', 'github', 'pr-gate.yml'), 'utf8');
    assert.match(gate, /v1\.0\.21/);
    const policy = readFileSync(join(root, 'examples', 'org-policy.yml'), 'utf8');
    assert.match(policy, /v1\.0\.21/);

    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /prove --page/);
      assert.doesNotMatch(live, /v1\.0\.21/);
    }
  });

  it('writes a sibling one-pager on prove --page and stays stdout-only without it', () => {
    const dir = initRepo();
    wrapClean(dir, 'page-target');
    assert.deepEqual(listProvePages(dir), []);

    const plain = cliResult(dir, ['prove', '--json']);
    assert.equal(plain.code, 0, plain.err);
    assert.equal(plain.out.trim().split('\n').length, 1);
    const before = parseJson(plain.out);
    assert.equal(before.ok, true);
    assert.equal(before.version, '1.0.26');
    assert.equal('pagePath' in before, false);
    assert.deepEqual(listProvePages(dir), []);

    const auditPath = join(dir, '.agent-receipt', 'audit.jsonl');
    const auditBefore = readFileSync(auditPath, 'utf8');
    const human = cli(dir, ['prove', '--page']);
    assert.match(human, /PROVED/);
    assert.match(human, /page: /);
    assert.match(human, /\.prove\.md/);
    assert.equal(readFileSync(auditPath, 'utf8'), auditBefore);

    const expected = before.path.replace(/\.md$/i, '.prove.md');
    assert.equal(existsSync(expected), true);
    const page = readFileSync(expected, 'utf8');
    assert.match(page, /# Agent Receipt — Prove/);
    assert.match(page, /\*\*Verdict:\*\* PROVED/);
    assert.match(page, new RegExp(before.sha256));
    for (const label of PAGE_LABELS) {
      assert.match(page, new RegExp(`\\*\\*${label}:\\*\\*`));
    }
    assert.match(page, /not a cryptographic signature/);
    assert.match(page, /not a certificate authority/i);
    assert.match(page, /not access control/i);
    assert.match(page, /not itself signed/i);
    assert.doesNotMatch(page, /## What to review/);
    assert.doesNotMatch(page, /## Integrity/);

    const again = cliResult(dir, ['prove', '--json']);
    assert.equal(again.code, 0, again.err);
    const newest = parseJson(again.out);
    assert.equal(newest.path, before.path);
    assert.equal(newest.ok, true);
    assert.equal('pagePath' in newest, false);
    const last = parseJson(cli(dir, ['last', '--json']));
    assert.equal(last.path, before.path);
  });

  it('--json --page adds pagePath and --out / --one-pager choose the file', () => {
    const dir = initRepo();
    wrapClean(dir, 'json-page');
    const r = cliResult(dir, ['prove', '--json', '--page']);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out.trim().split('\n').length, 1);
    const body = parseJson(r.out);
    assert.equal(body.ok, true);
    assert.equal(body.command, 'prove');
    assert.equal(body.exitCode, 0);
    assert.equal(body.pagePath, body.path.replace(/\.md$/i, '.prove.md'));
    assert.equal(existsSync(body.pagePath), true);
    const text = readFileSync(body.pagePath, 'utf8');
    assert.match(text, /PROVED/);
    assert.match(text, new RegExp(body.sha256));

    mkdirSync(join(dir, 'pages'));
    const dirOut = parseJson(cli(dir, ['prove', '--json', '--page', '--out', 'pages']));
    assert.equal(dirname(dirOut.pagePath), join(dir, 'pages'));
    assert.equal(basename(dirOut.pagePath), basename(body.path).replace(/\.md$/i, '.prove.md'));
    assert.match(readFileSync(dirOut.pagePath, 'utf8'), /PROVED/);

    mkdirSync(join(dir, 'slash-out'));
    const slash = parseJson(cli(dir, ['prove', '--json', '--one-pager', '--out', 'slash-out/']));
    assert.equal(dirname(slash.pagePath), join(dir, 'slash-out'));

    const fileOut = parseJson(
      cli(dir, ['prove', '--json', '--one-pager', '--out', 'custom/summary.md']),
    );
    assert.equal(fileOut.pagePath, join(dir, 'custom', 'summary.md'));
    assert.match(readFileSync(fileOut.pagePath, 'utf8'), /PROVED/);

    copyFileSync(body.path, join(dir, 'notes.txt'));
    const other = parseJson(cli(dir, ['prove', 'notes.txt', '--json', '--page']));
    assert.equal(other.path, join(dir, 'notes.txt'));
    assert.equal(other.pagePath, join(dir, 'notes.txt.prove.md'));
    assert.equal(existsSync(join(dir, 'notes.prove.md')), false);

    const missingOut = cliResult(dir, ['prove', '--out', 'nope.md']);
    assert.equal(missingOut.code, 1);
    assert.match(`${missingOut.out}\n${missingOut.err}`, /--page/);
    const missingJson = cliResult(dir, ['prove', '--json', '--out', 'nope.md']);
    assert.equal(missingJson.code, 1);
    assert.equal(parseJson(missingJson.out).exitCode, 1);

    const original = readFileSync(body.path, 'utf8');
    const overwrite = cliResult(dir, ['prove', '--page', '--out', body.path]);
    assert.equal(overwrite.code, 1);
    assert.match(`${overwrite.out}\n${overwrite.err}`, /overwrite/);
    assert.equal(readFileSync(body.path, 'utf8'), original);
  });

  it('writes FAILED on a tampered receipt and keeps exit 2', () => {
    const dir = initRepo();
    wrapClean(dir, 'tamper-page');
    const ok = parseJson(cli(dir, ['prove', '--json']));
    const text = readFileSync(ok.path, 'utf8');
    writeFileSync(ok.path, text.replace('tamper-page', 'tampered-body'));

    const bad = cliResult(dir, ['prove', '--json', '--page']);
    assert.equal(bad.code, 2, bad.out + bad.err);
    assert.equal(bad.out.trim().split('\n').length, 1);
    const body = parseJson(bad.out);
    assert.equal(body.ok, false);
    assert.equal(body.verified, false);
    assert.equal(body.exitCode, 2);
    assert.equal(body.pagePath, ok.path.replace(/\.md$/i, '.prove.md'));
    const page = readFileSync(body.pagePath, 'utf8');
    assert.match(page, /\*\*Verdict:\*\* FAILED/);
    assert.match(page, new RegExp(body.sha256));
    assert.doesNotMatch(page, /\*\*Verdict:\*\* PROVED/);

    const human = cliResult(dir, ['prove', '--page']);
    assert.equal(human.code, 2);
    assert.match(human.out, /FAILED/);
    assert.match(human.out, /page: /);
  });
});
