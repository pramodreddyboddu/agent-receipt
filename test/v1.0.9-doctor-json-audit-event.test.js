import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runDoctorChecks } from '../dist/commands/doctor.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const CHECK_IDS = [
  'node',
  'git',
  'repo',
  'outDir',
  'cli',
  'config',
  'hooks',
  'redact',
  'policy',
  'audit',
  'keys',
  'trust',
  'retention',
  'git-clean',
  'cursor',
  'grok',
];

const STATUSES = new Set(['pass', 'fail', 'warn', 'info']);

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

function initRepo(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  git(dir, ['init']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  writeFileSync(join(dir, 'README.md'), '# v1.0.9 fixture\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  cli(dir, ['init']);
  return dir;
}

function receiptMd(body) {
  return body.endsWith('\n') ? body : body + '\n';
}

function parseJsonStdout(r) {
  assert.equal(r.out.trim(), JSON.stringify(JSON.parse(r.out)), r.out);
  return JSON.parse(r.out);
}

function assertDoctorShape(body, { strict, exitCode }) {
  assert.equal(body.ok, exitCode === 0);
  assert.equal(body.command, 'doctor');
  assert.equal(body.version, '1.0.21');
  assert.equal(body.exitCode, exitCode);
  assert.equal(body.strict, strict);
  assert.deepEqual(
    body.checks.map((c) => c.id),
    CHECK_IDS,
  );
  for (const c of body.checks) {
    assert.equal(Object.keys(c).join(','), 'id,status,detail');
    assert.ok(STATUSES.has(c.status), c.status);
    assert.equal(typeof c.detail, 'string');
    assert.ok(c.detail.length > 0);
  }
}

describe('doctor --json', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function keep(dir) {
    dirs.push(dir);
    return dir;
  }

  function withReceipts(count) {
    const dir = keep(initRepo('agent-receipt-doctor-json-'));
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    for (let i = 0; i < count; i++) {
      writeFileSync(join(outDir, `receipt-n-${i}.md`), receiptMd(`# ${i}\n`));
    }
    writeFileSync(join(dir, '.agent-receipt.yml'), 'outDir: .agent-receipt/receipts\n');
    return dir;
  }

  it('prints one object and the same rows as the human checklist', () => {
    const dir = keep(initRepo('agent-receipt-doctor-json-shape-'));
    const human = cliResult(dir, ['doctor']);
    const json = cliResult(dir, ['doctor', '--json']);
    assert.equal(human.code, 0, human.out);
    assert.equal(json.code, 0, json.err);
    assert.equal(human.code, json.code);
    assert.match(human.out, /agent-receipt doctor/);
    assert.match(human.out, /Ready/);
    assert.equal(human.out.trim().startsWith('{'), false);
    assert.equal(json.err.includes('Ready'), false);
    assert.equal(json.err.includes('Environment'), false);

    const body = parseJsonStdout(json);
    assertDoctorShape(body, { strict: false, exitCode: 0 });
    const live = runDoctorChecks(dir);
    assert.equal(body.checks.length, live.length);
    for (const row of body.checks) {
      const src = live.find((c) => c.name === row.id);
      assert.ok(src, row.id);
      assert.equal(row.status, src.status);
      assert.equal(row.detail, src.detail);
    }
    assert.equal(body.checks.find((c) => c.id === 'node').status, 'pass');
    assert.equal(body.checks.find((c) => c.id === 'repo').status, 'pass');
    assert.match(cli(dir, ['help', 'doctor']), /--json/);
  });

  it('fails unset policy and unset retention under --strict on a small directory', () => {
    const dir = keep(initRepo('agent-receipt-doctor-json-small-'));
    const human = cliResult(dir, ['doctor', '--strict']);
    const json = cliResult(dir, ['doctor', '--strict', '--json']);
    assert.equal(human.code, 1, human.out);
    assert.equal(json.code, 1, json.out + json.err);
    assert.equal(human.code, json.code);
    const body = parseJsonStdout(json);
    assertDoctorShape(body, { strict: true, exitCode: 1 });
    assert.equal(body.ok, false);
    assert.equal(body.checks.find((c) => c.id === 'policy').status, 'fail');
    assert.equal(body.checks.find((c) => c.id === 'retention').status, 'fail');
    const live = runDoctorChecks(dir, { strict: true });
    for (const row of body.checks) {
      assert.equal(row.status, live.find((c) => c.name === row.id).status);
    }
  });

  it('does not change exits when pressure promotes policy and retention', () => {
    const dir = withReceipts(100);
    const plain = cliResult(dir, ['doctor']);
    const plainJson = cliResult(dir, ['doctor', '--json']);
    assert.equal(plain.code, 0, plain.out);
    assert.equal(plainJson.code, 0, plainJson.out);
    assert.equal(plain.code, plainJson.code);
    const open = parseJsonStdout(plainJson);
    assert.equal(open.ok, true);
    assert.equal(open.strict, false);
    assert.equal(open.checks.find((c) => c.id === 'policy').status, 'info');
    assert.equal(open.checks.find((c) => c.id === 'retention').status, 'warn');

    const strict = cliResult(dir, ['doctor', '--strict']);
    const strictJson = cliResult(dir, ['doctor', '--json', '--strict']);
    assert.equal(strict.code, 1, strict.out);
    assert.equal(strictJson.code, 1, strictJson.out);
    assert.equal(strict.code, strictJson.code);
    assert.match(strict.out, /\[FAIL\].*policy/);
    assert.match(strict.out, /\[FAIL\].*retention/);
    const body = parseJsonStdout(strictJson);
    assertDoctorShape(body, { strict: true, exitCode: 1 });
    assert.equal(body.ok, false);
    assert.equal(body.checks.find((c) => c.id === 'policy').status, 'fail');
    assert.equal(body.checks.find((c) => c.id === 'retention').status, 'fail');
    const live = runDoctorChecks(dir, { strict: true });
    for (const row of body.checks) {
      assert.equal(row.status, live.find((c) => c.name === row.id).status);
      assert.equal(row.detail, live.find((c) => c.name === row.id).detail);
    }
  });

  it('fails the repo check outside git, with or without --json', () => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'agent-receipt-doctor-json-norepo-')));
    const human = cliResult(dir, ['doctor']);
    const json = cliResult(dir, ['doctor', '--json']);
    assert.equal(human.code, 1, human.out);
    assert.equal(json.code, 1, json.out);
    const body = parseJsonStdout(json);
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 1);
    assert.equal(body.strict, false);
    assert.equal(body.checks.find((c) => c.id === 'repo').status, 'fail');
    assert.equal(body.checks.find((c) => c.id === 'node').status, 'pass');
  });
});

describe('audit --event', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  it('filters the listing, honors --limit, and leaves --verify on the whole chain', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-audit-event-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# audit event\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);

    const empty = cliResult(dir, ['audit', '--event', 'wrap', '--json']);
    assert.equal(empty.code, 0, empty.err);
    assert.deepEqual(parseJsonStdout(empty), []);

    const missing = cliResult(dir, ['audit', '--event']);
    assert.equal(missing.code, 1);
    assert.match(missing.err, /--event requires a name/);
    assert.match(missing.err, /prune/);

    const bad = cliResult(dir, ['log', '--event', 'Wrap', '--json']);
    assert.equal(bad.code, 1);
    assert.match(bad.err, /--event must be one of/);
    assert.match(bad.err, /capture, watch, wrap, share, export, prune/);
    assert.match(bad.err, /whole chain/);
    assert.equal(bad.out.trim(), '');

    cli(dir, ['wrap', '--agent', 'one', '--message', 'first wrap']);
    cli(dir, ['share', '--out', 'share.html']);
    writeFileSync(join(dir, 'app.js'), 'export const n = 2;\n');
    git(dir, ['add', 'app.js']);
    git(dir, ['commit', '-m', 'app']);
    cli(dir, ['wrap', '--agent', 'two', '--message', 'second wrap']);

    const all = parseJsonStdout(cliResult(dir, ['audit', '--json']));
    assert.deepEqual(
      all.map((ev) => ev.event),
      ['wrap', 'share', 'wrap'],
    );
    assert.deepEqual(
      all.map((ev) => ev.agent),
      ['one', 'one', 'two'],
    );

    const wraps = parseJsonStdout(cliResult(dir, ['audit', '--event', 'wrap', '--json']));
    assert.equal(wraps.length, 2);
    assert.deepEqual(
      wraps.map((ev) => ev.agent),
      ['one', 'two'],
    );
    for (const ev of wraps) {
      assert.equal(ev.event, 'wrap');
      assert.equal(ev.version, '1.0.21');
    }

    const newestWrap = parseJsonStdout(
      cliResult(dir, ['audit', '--event', 'wrap', '--limit', '1', '--json']),
    );
    assert.equal(newestWrap.length, 1);
    assert.equal(newestWrap[0].agent, 'two');

    const shareOnly = parseJsonStdout(
      cliResult(dir, ['log', '--event', 'share', '--limit', '1', '--json']),
    );
    assert.equal(shareOnly.length, 1);
    assert.equal(shareOnly[0].event, 'share');
    assert.match(shareOnly[0].path, /share\.html$/);

    const none = cliResult(dir, ['audit', '--event', 'capture', '--json']);
    assert.equal(none.code, 0, none.err);
    assert.deepEqual(parseJsonStdout(none), []);
    const humanNone = cli(dir, ['audit', '--event', 'export']);
    assert.match(humanNone, /No export events/);
    assert.match(humanNone, /event filter: export/);

    const humanShare = cli(dir, ['audit', '--event', 'share']);
    assert.match(humanShare, /share/);
    assert.doesNotMatch(humanShare, /\bwrap\b/);

    const verified = cliResult(dir, ['audit', '--verify', '--event', 'wrap', '--json']);
    assert.equal(verified.code, 0, verified.err);
    assert.match(verified.err, /listing-only/);
    assert.match(verified.err, /whole chain/);
    const chain = parseJsonStdout(verified);
    assert.equal(chain.ok, true);
    assert.equal(chain.command, 'audit');
    assert.equal(chain.version, '1.0.21');
    assert.equal(chain.events, 3);
    assert.equal(chain.brokenAt, null);

    const humanVerify = cliResult(dir, ['log', '--verify', '--event', 'share']);
    assert.equal(humanVerify.code, 0, humanVerify.err);
    assert.match(humanVerify.out, /audit chain OK/);
    assert.match(humanVerify.out, /3 events/);
    assert.match(humanVerify.err, /listing-only/);

    const logPath = join(dir, '.agent-receipt', 'audit.jsonl');
    const lines = readFileSync(logPath, 'utf8').trim().split('\n');
    const first = JSON.parse(lines[0]);
    const broken = lines[0].replace(first.sha256.slice(0, 8), 'deadbeef');
    writeFileSync(logPath, broken + '\n' + lines.slice(1).join('\n') + '\n');
    const badChain = cliResult(dir, ['audit', '--verify', '--event', 'wrap', '--json']);
    assert.equal(badChain.code, 2, badChain.out);
    const brokenBody = parseJsonStdout(badChain);
    assert.equal(brokenBody.ok, false);
    assert.equal(brokenBody.events, 3);
    assert.ok(brokenBody.brokenAt >= 1);

    assert.match(cli(dir, ['help', 'audit']), /--event/);
    assert.match(cli(dir, ['help']), /--event/);
    assert.match(cli(dir, ['help', 'log']), /help audit/);
  });
});

describe('v1.0.9 docs', () => {
  it('mentions doctor --json and audit --event without enabling retention', () => {
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /doctor --json/);
    assert.match(mirror, /audit --event wrap/);
    assert.match(mirror, /doctor --strict --json/);
    const policy = readFileSync(join(root, 'examples', 'org-policy.yml'), 'utf8');
    assert.match(policy, /redact:\s*true/);
    assert.match(policy, /failOn:\s*high/);
    assert.match(policy, /doctor --strict/);
    assert.match(policy, /doctor --json/);
    assert.equal(/^maxCount:/m.test(policy), false);
    assert.equal(/^maxAgeDays:/m.test(policy), false);
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.9\]/);
    assert.match(changelog, /doctor --json/);
    assert.match(changelog, /audit --event/);
  });
});
