import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { appendAuditEvent } from '../dist/lib/audit.js';

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

function parseJsonStdout(r) {
  assert.equal(r.out.trim(), JSON.stringify(JSON.parse(r.out)), r.out);
  return JSON.parse(r.out);
}

function pathsOf(events) {
  return events.map((ev) => ev.path);
}

function seed(dir, rows) {
  mkdirSync(join(dir, '.agent-receipt'), { recursive: true });
  for (const row of rows) {
    appendAuditEvent(dir, {
      event: row.event,
      path: row.path,
      sha256: 'a'.repeat(64),
      agent: row.agent,
      redacted: false,
      verified: row.verified !== false,
      failedOn: row.failedOn,
      exitCode: row.exitCode,
    });
  }
}

/** Oldest first. Mixes exact agent names, null, failedOn, and nonzero exits. */
const ROWS = [
  { event: 'wrap', path: 'receipts/r1.md', agent: 'ci', failedOn: false, exitCode: 0 },
  { event: 'wrap', path: 'receipts/r2.md', agent: 'ci', failedOn: true, exitCode: 0 },
  { event: 'share', path: 'receipts/r3.html', agent: 'ci', failedOn: false, exitCode: 2 },
  { event: 'wrap', path: 'receipts/r4.md', agent: 'other', failedOn: true, exitCode: 2 },
  { event: 'capture', path: 'receipts/r5.md', agent: null, failedOn: true, exitCode: 2 },
  { event: 'wrap', path: 'receipts/r6.md', agent: 'ci', failedOn: false, exitCode: 0 },
  { event: 'wrap', path: 'receipts/r7.md', agent: 'CI', failedOn: true, exitCode: 2 },
  { event: 'export', path: 'receipts/r8.html', agent: 'ci', failedOn: false, exitCode: 1 },
  { event: 'wrap', path: 'receipts/r9.md', agent: 'ci', failedOn: true, exitCode: 2 },
];

describe('audit --agent and --failed', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function keep(prefix) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    return dir;
  }

  it('matches --agent exactly, skips null, and combines with --event', () => {
    const dir = keep('agent-receipt-audit-agent-');
    seed(dir, ROWS);

    const ci = parseJsonStdout(cliResult(dir, ['audit', '--agent', 'ci', '--json']));
    assert.deepEqual(pathsOf(ci), [
      'receipts/r1.md',
      'receipts/r2.md',
      'receipts/r3.html',
      'receipts/r6.md',
      'receipts/r8.html',
      'receipts/r9.md',
    ]);
    for (const ev of ci) {
      assert.equal(ev.agent, 'ci');
      assert.equal(ev.version, '1.0.17');
    }

    const upper = parseJsonStdout(cliResult(dir, ['log', '--agent', 'CI', '--json']));
    assert.deepEqual(pathsOf(upper), ['receipts/r7.md']);
    assert.equal(upper[0].agent, 'CI');

    const none = cliResult(dir, ['audit', '--agent', 'nobody', '--json']);
    assert.equal(none.code, 0, none.err);
    assert.deepEqual(parseJsonStdout(none), []);

    const spelledNull = cliResult(dir, ['audit', '--agent', 'null', '--json']);
    assert.equal(spelledNull.code, 0, spelledNull.err);
    assert.deepEqual(parseJsonStdout(spelledNull), []);

    const padded = cliResult(dir, ['audit', '--agent', 'ci ', '--json']);
    assert.equal(padded.code, 0, padded.err);
    assert.deepEqual(parseJsonStdout(padded), []);

    const wraps = parseJsonStdout(
      cliResult(dir, ['audit', '--event', 'wrap', '--agent', 'ci', '--json']),
    );
    assert.deepEqual(pathsOf(wraps), ['receipts/r1.md', 'receipts/r2.md', 'receipts/r6.md', 'receipts/r9.md']);
    for (const ev of wraps) assert.equal(ev.event, 'wrap');

    const eq = parseJsonStdout(cliResult(dir, ['log', '--agent=ci', '--event=share', '--json']));
    assert.deepEqual(pathsOf(eq), ['receipts/r3.html']);

    const human = cli(dir, ['audit', '--agent', 'ci']);
    assert.match(human, /agent filter: ci/);
    assert.match(human, /exact match/);
    const listed = [...human.matchAll(/receipts\/r\d+\.(?:md|html)/g)].map((m) => m[0]);
    assert.deepEqual(listed, pathsOf(ci));
    assert.doesNotMatch(human, /receipts\/r4\.md/);
    assert.doesNotMatch(human, /receipts\/r5\.md/);
    assert.doesNotMatch(human, /receipts\/r7\.md/);

    const humanNone = cli(dir, ['audit', '--agent', 'nobody']);
    assert.match(humanNone, /No events match agent=nobody/);
    assert.equal(cliResult(dir, ['log', '--agent', 'nobody', '--json']).code, 0);
  });

  it('keeps failedOn or a nonzero exitCode', () => {
    const dir = keep('agent-receipt-audit-failed-');
    seed(dir, ROWS);

    const failed = parseJsonStdout(cliResult(dir, ['audit', '--failed', '--json']));
    assert.deepEqual(pathsOf(failed), [
      'receipts/r2.md',
      'receipts/r3.html',
      'receipts/r4.md',
      'receipts/r5.md',
      'receipts/r7.md',
      'receipts/r8.html',
      'receipts/r9.md',
    ]);
    const byPath = Object.fromEntries(failed.map((ev) => [ev.path, ev]));
    assert.equal(byPath['receipts/r2.md'].failedOn, true);
    assert.equal(byPath['receipts/r2.md'].exitCode, 0);
    assert.equal(byPath['receipts/r3.html'].failedOn, false);
    assert.equal(byPath['receipts/r3.html'].exitCode, 2);
    assert.equal(byPath['receipts/r5.md'].agent, null);
    assert.equal(byPath['receipts/r8.html'].exitCode, 1);
    assert.equal(failed.some((ev) => ev.path === 'receipts/r1.md'), false);
    assert.equal(failed.some((ev) => ev.path === 'receipts/r6.md'), false);

    const human = cli(dir, ['log', '--failed']);
    assert.match(human, /failed filter: failedOn or nonzero exitCode/);
    assert.match(human, /receipts\/r2\.md/);
    assert.doesNotMatch(human, /receipts\/r1\.md/);

    const clean = keep('agent-receipt-audit-failed-empty-');
    seed(clean, [
      { event: 'wrap', path: 'receipts/ok.md', agent: 'ci', failedOn: false, exitCode: 0 },
    ]);
    const empty = cliResult(clean, ['audit', '--failed', '--json']);
    assert.equal(empty.code, 0, empty.err);
    assert.deepEqual(parseJsonStdout(empty), []);
    assert.match(cli(clean, ['audit', '--failed']), /No events match failed/);
  });

  it('applies --event, then --agent, then --failed, then --limit as a JSON array', () => {
    const dir = keep('agent-receipt-audit-combo-');
    seed(dir, ROWS);

    const combo = parseJsonStdout(
      cliResult(dir, [
        'audit',
        '--failed',
        '--agent',
        'ci',
        '--limit',
        '2',
        '--json',
      ]),
    );
    assert.equal(Array.isArray(combo), true);
    assert.equal(combo.length, 2);
    assert.deepEqual(pathsOf(combo), ['receipts/r8.html', 'receipts/r9.md']);
    for (const ev of combo) {
      assert.equal(ev.agent, 'ci');
      assert.equal(ev.failedOn === true || ev.exitCode !== 0, true);
    }
    const ordered = parseJsonStdout(
      cliResult(dir, [
        'log',
        '--event',
        'wrap',
        '--agent',
        'ci',
        '--failed',
        '--limit',
        '2',
        '--json',
      ]),
    );
    assert.deepEqual(pathsOf(ordered), ['receipts/r2.md', 'receipts/r9.md']);
    assert.equal(ordered[0].event, 'wrap');
    assert.equal(ordered[1].event, 'wrap');

    const newest = parseJsonStdout(
      cliResult(dir, ['audit', '--event', 'wrap', '--agent', 'ci', '--limit', '1', '--json']),
    );
    assert.deepEqual(pathsOf(newest), ['receipts/r9.md']);

    const human = cli(dir, ['audit', '--agent', 'ci', '--failed', '--limit', '2']);
    assert.match(human, /showing newest 2 of 4 agent=ci failed/);
    const listed = [...human.matchAll(/receipts\/r\d+\.(?:md|html)/g)].map((m) => m[0]);
    assert.deepEqual(listed, ['receipts/r8.html', 'receipts/r9.md']);

    const miss = cliResult(dir, ['audit', '--agent', 'ci', '--event', 'prune', '--failed', '--json']);
    assert.equal(miss.code, 0, miss.err);
    assert.deepEqual(parseJsonStdout(miss), []);
  });

  it('ignores --agent and --failed on --verify and still checks the whole chain', () => {
    const dir = keep('agent-receipt-audit-verify-');
    seed(dir, ROWS);

    const plain = cliResult(dir, ['audit', '--verify']);
    assert.equal(plain.code, 0, plain.err);
    assert.doesNotMatch(plain.err, /listing-only/);
    assert.match(plain.out, /9 events/);

    const verified = cliResult(dir, [
      'audit',
      '--verify',
      '--agent',
      'nobody',
      '--failed',
      '--event',
      'wrap',
      '--json',
    ]);
    assert.equal(verified.code, 0, verified.err);
    assert.match(verified.err, /--event wrap is listing-only/);
    assert.match(verified.err, /--agent nobody is listing-only/);
    assert.match(verified.err, /--failed is listing-only/);
    assert.match(verified.err, /whole chain/);
    assert.doesNotMatch(verified.out, /listing-only/);
    const chain = parseJsonStdout(verified);
    assert.equal(Array.isArray(chain), false);
    assert.equal(chain.ok, true);
    assert.equal(chain.command, 'audit');
    assert.equal(chain.version, '1.0.17');
    assert.equal(chain.events, ROWS.length);
    assert.equal(chain.brokenAt, null);

    const human = cliResult(dir, ['log', '--verify', '--agent', 'ci', '--failed']);
    assert.equal(human.code, 0, human.err);
    assert.match(human.out, /audit chain OK/);
    assert.match(human.out, /9 events/);
    assert.match(human.err, /--agent ci is listing-only/);
    assert.match(human.err, /--failed is listing-only/);

    const logPath = join(dir, '.agent-receipt', 'audit.jsonl');
    const lines = readFileSync(logPath, 'utf8').trim().split('\n');
    const first = JSON.parse(lines[0]);
    const broken = lines[0].replace(first.sha256.slice(0, 8), 'deadbeef');
    writeFileSync(logPath, broken + '\n' + lines.slice(1).join('\n') + '\n');
    const badChain = cliResult(dir, [
      'audit',
      '--verify',
      '--agent',
      'ci',
      '--failed',
      '--json',
    ]);
    assert.equal(badChain.code, 2, badChain.out);
    assert.match(badChain.err, /listing-only/);
    const brokenBody = parseJsonStdout(badChain);
    assert.equal(brokenBody.ok, false);
    assert.equal(brokenBody.events, ROWS.length);
    assert.ok(brokenBody.brokenAt >= 1);
  });

  it('still rejects unknown flags, unknown events, and a missing --agent name', () => {
    const dir = keep('agent-receipt-audit-flags-');
    seed(dir, ROWS.slice(0, 1));

    const unknown = cliResult(dir, ['audit', '--agents', 'ci']);
    assert.equal(unknown.code, 1);
    assert.match(unknown.err, /Unknown flag: --agents/);
    assert.equal(unknown.out.trim(), '');

    const nope = cliResult(dir, ['log', '--nope']);
    assert.equal(nope.code, 1);
    assert.match(nope.err, /Unknown flag: --nope/);

    const strict = cliResult(dir, ['audit', '--strict']);
    assert.equal(strict.code, 1);
    assert.match(strict.err, /Unknown flag: --strict/);

    const badEvent = cliResult(dir, ['audit', '--event', 'Wrap', '--json']);
    assert.equal(badEvent.code, 1);
    assert.match(badEvent.err, /--event must be one of/);
    assert.match(badEvent.err, /whole chain/);
    assert.equal(badEvent.out.trim(), '');

    const missingEvent = cliResult(dir, ['log', '--event']);
    assert.equal(missingEvent.code, 1);
    assert.match(missingEvent.err, /--event requires a name/);

    const missingAgent = cliResult(dir, ['audit', '--agent']);
    assert.equal(missingAgent.code, 1);
    assert.match(missingAgent.err, /--agent requires a name/);
    assert.match(missingAgent.err, /agent null/);

    const emptyAgent = cliResult(dir, ['audit', '--agent=']);
    assert.equal(emptyAgent.code, 1);
    assert.match(emptyAgent.err, /--agent requires a name/);

    const verifyMissing = cliResult(dir, ['audit', '--verify', '--agent']);
    assert.equal(verifyMissing.code, 1);
    assert.match(verifyMissing.err, /--agent requires a name/);
    assert.doesNotMatch(verifyMissing.out, /audit chain/);

    const valuedFailed = cliResult(dir, ['audit', '--failed', 'wrap']);
    assert.equal(valuedFailed.code, 1);
    assert.match(valuedFailed.err, /--failed does not take a value/);

    const badLimit = cliResult(dir, ['log', '--limit', '0', '--agent', 'ci']);
    assert.equal(badLimit.code, 1);
    assert.match(badLimit.err, /--limit must be an integer >= 1/);

    const help = cli(dir, ['help', 'audit']);
    assert.match(help, /Filter order: load events/);
    assert.match(help, /--event/);
    assert.match(help, /--agent/);
    assert.match(help, /--failed/);
    assert.match(help, /exact, case-sensitive/);
    assert.match(help, /agent: null/);
    const order = help.indexOf('Filter order: load events');
    const eventAt = help.indexOf('--event', order);
    const agentAt = help.indexOf('--agent', eventAt);
    const failedAt = help.indexOf('--failed', agentAt);
    const limitAt = help.indexOf('--limit', failedAt);
    assert.ok(order >= 0 && eventAt > order && agentAt > eventAt && failedAt > agentAt && limitAt > failedAt);
    assert.match(cli(dir, ['help']), /--agent/);
    assert.match(cli(dir, ['help']), /--failed/);
    assert.match(cli(dir, ['help', 'log']), /help audit/);
  });

  it('filters the agent and failedOn fields that wrap writes', () => {
    const dir = keep('agent-receipt-audit-wrap-');
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# audit agent\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);

    cli(dir, ['wrap', '--agent', 'ci', '--message', 'clean']);
    const okOnly = parseJsonStdout(cliResult(dir, ['audit', '--agent', 'ci', '--json']));
    assert.equal(okOnly.length, 1);
    assert.equal(okOnly[0].event, 'wrap');
    assert.equal(okOnly[0].agent, 'ci');
    assert.equal(okOnly[0].failedOn, false);
    assert.equal(okOnly[0].exitCode, 0);
    assert.deepEqual(parseJsonStdout(cliResult(dir, ['audit', '--agent', 'CI', '--json'])), []);
    assert.deepEqual(parseJsonStdout(cliResult(dir, ['audit', '--agent', 'ci', '--failed', '--json'])), []);

    writeFileSync(join(dir, 'leak.txt'), 'token AKIAIOSFODNN7EXAMPLE\n');
    const failedWrap = cliResult(dir, [
      'wrap',
      '--agent',
      'other',
      '--fail-on',
      'high',
      '--uncommitted',
      '--message',
      'leak',
    ]);
    assert.equal(failedWrap.code, 2, failedWrap.err);

    const other = parseJsonStdout(cliResult(dir, ['log', '--agent', 'other', '--failed', '--json']));
    assert.equal(other.length, 1);
    assert.equal(other[0].event, 'wrap');
    assert.equal(other[0].agent, 'other');
    assert.equal(other[0].failedOn, true);
    assert.notEqual(other[0].exitCode, 0);
    assert.equal(JSON.stringify(other).includes('AKIA'), false);

    const allFailed = parseJsonStdout(cliResult(dir, ['audit', '--failed', '--json']));
    assert.deepEqual(
      allFailed.map((ev) => ev.agent),
      ['other'],
    );

    const chain = parseJsonStdout(
      cliResult(dir, ['audit', '--verify', '--agent', 'nobody', '--failed', '--json']),
    );
    assert.equal(chain.ok, true);
    assert.equal(chain.events, 2);
  });
});

describe('v1.0.10 docs', () => {
  it('covers --agent and --failed without editing the live workflow', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.10\]/);
    assert.match(changelog, /audit --agent/);
    assert.match(changelog, /--failed/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /audit --agent ci --failed/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /audit --agent/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /--agent <name>/);
    assert.match(business, /--failed/);
    assert.match(business, /Filter order: load the log/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /--agent/);
    assert.match(readme, /--failed/);
  });
});
