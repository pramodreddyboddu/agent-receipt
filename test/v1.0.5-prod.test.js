import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  copyFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseRiskSummaryMarkdown } from '../dist/lib/risk.js';
import { loadConfig, validateConfig } from '../dist/lib/config.js';
import { runDoctorChecks } from '../dist/commands/doctor.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const PASSWORD = 'SuperSecretPass123';

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cliResult(cwd, args) {
  try {
    const out = execFileSync(process.execPath, [bin, ...args], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: 0, out, err: '' };
  } catch (err) {
    return {
      code: err.status ?? 1,
      out: String(err.stdout || ''),
      err: String(err.stderr || ''),
    };
  }
}

function cli(cwd, args) {
  const r = cliResult(cwd, args);
  if (r.code !== 0) {
    throw new Error(`exit ${r.code}\n${r.out}\n${r.err}`);
  }
  return r.out;
}

function initRepo(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  git(dir, ['init']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  writeFileSync(join(dir, 'README.md'), '# prod fixture\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  cli(dir, ['init']);
  return dir;
}

describe('parseRiskSummaryMarkdown', () => {
  it('reads none and ranked summary rows', () => {
    assert.deepEqual(
      parseRiskSummaryMarkdown('| Risk | none |\n'),
      { high: 0, medium: 0, low: 0, total: 0, maxSeverity: null },
    );
    const ranked = parseRiskSummaryMarkdown(
      '| Risk | 3 (high 1, medium 2, low 0) |\n| Max severity | **high** |\n',
    );
    assert.equal(ranked.high, 1);
    assert.equal(ranked.medium, 2);
    assert.equal(ranked.total, 3);
    assert.equal(ranked.maxSeverity, 'high');
  });
});

describe('share + CI json gates', () => {
  let dir;

  before(() => {
    dir = initRepo('agent-receipt-share-');
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('share happy path writes html + md, verifies, prints TL;DR and paths', () => {
    writeFileSync(join(dir, 'app.js'), 'export const n = 1;\n');
    git(dir, ['add', 'app.js']);
    git(dir, ['commit', '-m', 'add app']);
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'test',
      '--message',
      'happy',
      '--out',
      'clean.md',
    ]);

    const out = cli(dir, ['share', 'clean.md', '--out', 'clean.html', '--md', 'clean.share.md']);
    assert.match(out, /TL;DR/);
    assert.match(out, /clean\.html/);
    assert.match(out, /clean\.share\.md/);
    assert.match(out, /OK/);
    assert.ok(existsSync(join(dir, 'clean.html')));
    assert.ok(existsSync(join(dir, 'clean.share.md')));
    const shared = readFileSync(join(dir, 'clean.share.md'), 'utf8');
    assert.match(shared, /Redacted/);
    assert.match(cli(dir, ['verify', 'clean.share.md']), /OK/);
    assert.match(readFileSync(join(dir, 'clean.md'), 'utf8'), /happy/);
  });

  it('share redacts DATABASE_URL passwords in html and markdown', () => {
    writeFileSync(
      join(dir, '.env'),
      `DATABASE_URL=postgres://app:${PASSWORD}!@db.internal:5432/app\n`,
    );
    git(dir, ['add', '.env']);
    git(dir, ['commit', '-m', 'add env']);
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'test',
      '--message',
      'leaky',
      '--out',
      'leaky.md',
      '--no-redact',
    ]);
    const source = readFileSync(join(dir, 'leaky.md'), 'utf8');
    assert.match(source, new RegExp(PASSWORD));

    const out = cli(dir, [
      'share',
      'leaky.md',
      '--redact',
      '--out',
      'leaky.html',
      '--md',
      'leaky.share.md',
    ]);
    assert.match(out, /TL;DR/);
    assert.match(out, /OK/);
    const html = readFileSync(join(dir, 'leaky.html'), 'utf8');
    const md = readFileSync(join(dir, 'leaky.share.md'), 'utf8');
    assert.doesNotMatch(html, new RegExp(PASSWORD));
    assert.doesNotMatch(md, new RegExp(PASSWORD));
    assert.match(md, /DATABASE_URL/);
    assert.match(md, /\[REDACTED\]/);
    assert.match(source, new RegExp(PASSWORD));
    assert.match(cli(dir, ['verify', 'leaky.share.md']), /OK/);
  });

  it('share --json is one object; --fail-on high exits 2 without the password', () => {
    const r = cliResult(dir, [
      'share',
      'leaky.md',
      '--json',
      '--fail-on',
      'high',
      '--out',
      'leaky-gate.html',
    ]);
    assert.equal(r.code, 2);
    assert.doesNotMatch(r.out, new RegExp(PASSWORD));
    const gate = JSON.parse(r.out);
    assert.equal(gate.ok, false);
    assert.equal(gate.command, 'share');
    assert.equal(gate.exitCode, 2);
    assert.equal(gate.failedOn, true);
    assert.equal(gate.verified, true);
    assert.equal(gate.redacted, true);
    assert.equal(gate.failOn, 'high');
    assert.equal(gate.version, '1.0.19');
    assert.ok(gate.risk.high >= 1);
    assert.match(gate.htmlPath, /leaky-gate\.html$/);
    assert.equal(gate.markdownPath, null);
    assert.doesNotMatch(readFileSync(gate.htmlPath, 'utf8'), new RegExp(PASSWORD));
  });

  it('share does not rewrite a tampered source', () => {
    const path = join(dir, 'clean.md');
    const original = readFileSync(path, 'utf8');
    writeFileSync(path, original.replace('happy', 'tampered-body'));
    const r = cliResult(dir, ['share', 'clean.md', '--out', 'should-not.html', '--json']);
    assert.equal(r.code, 2);
    const gate = JSON.parse(r.out);
    assert.equal(gate.verified, false);
    assert.equal(gate.ok, false);
    assert.equal(gate.htmlPath, null);
    assert.equal(existsSync(join(dir, 'should-not.html')), false);
    writeFileSync(path, original);
  });

  it('wrap and verify --json stay pure objects with stable fail-on exits', () => {
    const ok = cliResult(dir, ['verify', 'clean.md', '--json']);
    assert.equal(ok.code, 0);
    const vok = JSON.parse(ok.out);
    assert.equal(vok.command, 'verify');
    assert.equal(vok.ok, true);
    assert.equal(vok.verified, true);
    assert.equal(vok.exitCode, 0);
    assert.equal(vok.failedOn, false);

    const policy = cliResult(dir, ['verify', 'leaky.md', '--json', '--fail-on', 'high']);
    assert.equal(policy.code, 2);
    const vbad = JSON.parse(policy.out);
    assert.equal(vbad.exitCode, 2);
    assert.equal(vbad.verified, true);
    assert.equal(vbad.failedOn, true);
    assert.equal(vbad.failOn, 'high');

    const wrapDir = initRepo('agent-receipt-wrap-gate-');
    try {
      git(wrapDir, ['add', '-A']);
      git(wrapDir, ['commit', '-m', 'init config']);
      writeFileSync(join(wrapDir, 'ok.txt'), 'ok\n');
      git(wrapDir, ['add', 'ok.txt']);
      git(wrapDir, ['commit', '-m', 'ok']);
      const wrapped = cliResult(wrapDir, [
        'wrap',
        '--json',
        '--fail-on',
        'high',
        '--message',
        'ci wrap',
        '--agent',
        'ci',
      ]);
      assert.equal(wrapped.code, 0);
      const w = JSON.parse(wrapped.out);
      assert.equal(w.command, 'wrap');
      assert.equal(w.ok, true);
      assert.equal(w.verified, true);
      assert.equal(w.failedOn, false);
      assert.equal(w.exitCode, 0);
      assert.ok(w.path.endsWith('.md'));
      assert.ok(w.jsonPath.endsWith('.json'));
      assert.match(w.tldr, /ci|files/);
      assert.doesNotMatch(wrapped.out, /Wrote receipt/);

      writeFileSync(
        join(wrapDir, '.env'),
        `DATABASE_URL=postgres://app:${PASSWORD}!@db.internal/app\n`,
      );
      git(wrapDir, ['add', '-A']);
      git(wrapDir, ['commit', '-m', 'env']);
      assert.equal(git(wrapDir, ['status', '--porcelain']), '');
      const wrappedBad = cliResult(wrapDir, [
        'wrap',
        '--json',
        '--fail-on',
        'high',
        '--redact',
        '--message',
        'ci wrap secret',
        '--agent',
        'ci',
      ]);
      assert.equal(wrappedBad.code, 2);
      const wbad = JSON.parse(wrappedBad.out);
      assert.equal(wbad.ok, false);
      assert.equal(wbad.verified, true);
      assert.equal(wbad.failedOn, true);
      assert.equal(wbad.exitCode, 2);
      assert.equal(wbad.redacted, true);
      assert.doesNotMatch(wrappedBad.out + wrappedBad.err, new RegExp(PASSWORD));
      assert.doesNotMatch(readFileSync(wbad.path, 'utf8'), new RegExp(PASSWORD));
    } finally {
      rmSync(wrapDir, { recursive: true, force: true });
    }

    const bad = cliResult(dir, ['capture', '--json', '--fail-on', 'nope']);
    assert.equal(bad.code, 1);
    const errGate = JSON.parse(bad.out);
    assert.equal(errGate.ok, false);
    assert.equal(errGate.exitCode, 1);
    assert.equal(errGate.command, 'capture');
    assert.match(errGate.reason, /fail-on/);
  });
});

describe('org policy + doctor prod checklist', () => {
  let dir;

  before(() => {
    dir = initRepo('agent-receipt-org-');
    copyFileSync(join(root, 'examples/org-policy.yml'), join(dir, '.agent-receipt.yml'));
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('example policy loads and doctor shows prod ready rows', () => {
    const cfg = loadConfig(dir);
    assert.deepEqual(validateConfig(cfg), []);
    assert.equal(cfg.redact, true);
    assert.equal(cfg.failOn, 'high');

    const checks = runDoctorChecks(dir);
    const byName = Object.fromEntries(checks.map((c) => [c.name, c]));
    assert.equal(byName.redact.status, 'pass');
    assert.equal(byName.config.status, 'pass');
    assert.match(byName.config.detail, /failOn=high/);
    assert.ok(['pass', 'warn'].includes(byName['git-clean'].status));
    assert.equal(byName.cursor.status, 'info');
    assert.equal(byName.grok.status, 'info');

    const out = cli(dir, ['doctor']);
    assert.match(out, /Prod ready/);
    assert.match(out, /\[PASS\].*redact/);
    assert.match(out, /\[INFO\].*cursor/);
    assert.match(out, /\[INFO\].*grok/);
    assert.match(out, /Ready/);

    cli(dir, ['init', '--cursor', '--grok']);
    const after = cli(dir, ['doctor']);
    assert.match(after, /\[PASS\].*cursor/);
    assert.match(after, /\[PASS\].*grok/);
  });

  it('config failOn and redact apply without flags', () => {
    copyFileSync(join(root, 'examples/org-policy.yml'), join(dir, '.agent-receipt.yml'));
    writeFileSync(join(dir, 'note.txt'), 'hello\n');
    git(dir, ['add', 'note.txt']);
    git(dir, ['commit', '-m', 'note']);
    const safe = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--out',
      'note.md',
      '--json',
      '--message',
      'note',
    ]);
    assert.equal(safe.code, 0);
    const gate = JSON.parse(safe.out);
    assert.equal(gate.failedOn, false);
    assert.equal(gate.redacted, true);
    assert.equal(gate.failOn, 'high');
    assert.match(readFileSync(join(dir, 'note.md'), 'utf8'), /Redacted/);

    writeFileSync(
      join(dir, '.env'),
      `DATABASE_URL=postgres://app:${PASSWORD}!@db.internal/app\n`,
    );
    git(dir, ['add', '.env']);
    git(dir, ['commit', '-m', 'env']);
    const risky = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--out',
      'env.md',
      '--json',
      '--message',
      'env',
    ]);
    assert.equal(risky.code, 2);
    const bad = JSON.parse(risky.out);
    assert.equal(bad.exitCode, 2);
    assert.equal(bad.failedOn, true);
    assert.equal(bad.failOn, 'high');
    assert.equal(bad.redacted, true);
    const md = readFileSync(join(dir, 'env.md'), 'utf8');
    assert.doesNotMatch(md, new RegExp(PASSWORD));
    assert.match(md, /\[REDACTED\]/);
  });
});
