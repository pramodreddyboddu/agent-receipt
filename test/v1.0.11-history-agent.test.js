import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, utimesSync, readFileSync } from 'node:fs';
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

function messagesOf(rows) {
  return rows.map((row) => row.message);
}

const RISK = { high: 0, medium: 0, low: 0, total: 0, maxSeverity: null };

function indexEntry(fields) {
  return {
    path: fields.path,
    timestamp: fields.timestamp,
    message: fields.message,
    head: 'abc',
    branch: 'main',
    files: 1,
    insertions: 1,
    deletions: 0,
    risk: RISK,
    sha256: 'a'.repeat(64),
    ...fields,
  };
}

function receiptMd({ agent, uncommitted, message, timestamp }) {
  const lines = [
    '## Session',
    '',
    `- **Timestamp**: ${timestamp}`,
    '- **Branch**: `main`',
    '- **HEAD**: `abc123`',
  ];
  if (uncommitted) {
    lines.push('- **Snapshot**: **uncommitted** (staged + unstaged + untracked)');
  }
  if (agent !== undefined && agent !== null) {
    lines.push(`- **Agent**: ${agent}`);
  }
  lines.push(`- **Message**: ${message}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push('| Files | 1 |');
  lines.push('| Lines | +1 / −0 |');
  lines.push('| Risk | 0 |');
  lines.push('');
  return lines.join('\n');
}

describe('history --agent and --uncommitted', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function keep(prefix) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    return dir;
  }

  function writeIndex(dir) {
    mkdirSync(join(dir, '.agent-receipt', 'receipts'), { recursive: true });
    const receipts = [
      indexEntry({
        path: 'idx-new.md',
        timestamp: '2026-09-22T00:00:08.000Z',
        agent: 'ci',
        message: 'from-index-new',
        uncommitted: true,
      }),
      indexEntry({
        path: 'idx-old.md',
        timestamp: '2026-09-22T00:00:07.000Z',
        agent: 'ci',
        message: 'from-index-old',
        uncommitted: false,
      }),
      indexEntry({
        path: 'idx-omit.md',
        timestamp: '2026-09-22T00:00:06.000Z',
        agent: 'ci',
        message: 'from-index-omit',
      }),
      indexEntry({
        path: 'idx-other.md',
        timestamp: '2026-09-22T00:00:05.000Z',
        agent: 'other',
        message: 'from-index-other',
        uncommitted: true,
      }),
      indexEntry({
        path: 'idx-null.md',
        timestamp: '2026-09-22T00:00:04.000Z',
        agent: null,
        message: 'from-null',
        uncommitted: true,
      }),
      indexEntry({
        path: 'idx-missing.md',
        timestamp: '2026-09-22T00:00:03.000Z',
        message: 'from-missing',
        uncommitted: false,
      }),
      indexEntry({
        path: 'idx-CI.md',
        timestamp: '2026-09-22T00:00:02.000Z',
        agent: 'CI',
        message: 'from-CI',
        uncommitted: false,
      }),
      indexEntry({
        path: 'idx-padded.md',
        timestamp: '2026-09-22T00:00:01.000Z',
        agent: 'ci ',
        message: 'from-padded',
        uncommitted: false,
      }),
      indexEntry({
        path: 'idx-string-null.md',
        timestamp: '2026-01-01T00:00:00.000Z',
        agent: 'null',
        message: 'from-string-null',
        uncommitted: false,
      }),
    ];
    delete receipts[5].agent;
    delete receipts[2].uncommitted;
    writeFileSync(
      join(dir, '.agent-receipt', 'index.json'),
      JSON.stringify({ version: 1, updatedAt: receipts[0].timestamp, receipts }, null, 2) + '\n',
    );
    const decoy = join(dir, '.agent-receipt', 'receipts', 'disk-only.md');
    writeFileSync(
      decoy,
      receiptMd({
        agent: 'ci',
        uncommitted: true,
        message: 'disk-only-should-not-appear',
        timestamp: '2026-09-22T00:00:09.000Z',
      }),
    );
    utimesSync(decoy, new Date('2026-09-22T00:00:09.000Z'), new Date('2026-09-22T00:00:09.000Z'));
    return dir;
  }

  it('matches --agent exactly, skips null, and prefers the index over a scan', () => {
    const dir = writeIndex(keep('agent-receipt-hist-agent-'));

    const ci = parseJson(cli(dir, ['history', '--agent', 'ci', '--json']));
    assert.deepEqual(messagesOf(ci), ['from-index-new', 'from-index-old', 'from-index-omit']);
    assert.ok(ci.every((row) => row.agent === 'ci'));
    assert.equal(ci[0].uncommitted, true);
    assert.equal(ci[1].uncommitted, false);
    assert.equal(ci[2].uncommitted, undefined);
    assert.equal(JSON.stringify(ci).includes('disk-only-should-not-appear'), false);
    assert.equal(JSON.stringify(ci).includes('from-null'), false);
    assert.equal(JSON.stringify(ci).includes('from-padded'), false);
    assert.ok(ci[0].risk);
    assert.equal(typeof ci[0].files, 'number');

    const upper = parseJson(cli(dir, ['ls', '--agent', 'CI', '--json']));
    assert.deepEqual(messagesOf(upper), ['from-CI']);

    const spelledNull = parseJson(cli(dir, ['history', '--agent', 'null', '--json']));
    assert.deepEqual(messagesOf(spelledNull), ['from-string-null']);

    const padded = parseJson(cli(dir, ['history', '--agent', 'ci ', '--json']));
    assert.deepEqual(messagesOf(padded), ['from-padded']);

    const eq = parseJson(cli(dir, ['ls', '--agent=ci', '--json']));
    assert.deepEqual(messagesOf(eq), messagesOf(ci));

    const none = cliResult(dir, ['history', '--agent', 'nobody', '--json']);
    assert.equal(none.code, 0, none.err);
    assert.deepEqual(parseJson(none.out), []);

    const human = cli(dir, ['history', '--agent', 'ci', '--limit', '1']);
    assert.match(human, /Recent receipts \(1 of 3\)/);
    assert.match(human, /from-index-new/);
    assert.match(human, /\[uncommitted\]/);
    assert.doesNotMatch(human, /from-index-old/);
    assert.doesNotMatch(human, /from-CI/);
    assert.match(human, /newest: idx-new\.md/);

    const humanNone = cliResult(dir, ['ls', '--agent', 'nobody']);
    assert.equal(humanNone.code, 0, humanNone.err);
    assert.match(humanNone.out, /Recent receipts \(0 of 0\)/);
    assert.match(humanNone.out, /No receipts match agent=nobody \(9 other receipts\)/);
    assert.doesNotMatch(humanNone.out, /newest:/);
  });

  it('filters --uncommitted alone and combined with --agent, then applies --limit', () => {
    const dir = writeIndex(keep('agent-receipt-hist-unc-'));

    const dirty = parseJson(cli(dir, ['history', '--uncommitted', '--json']));
    assert.deepEqual(messagesOf(dirty), ['from-index-new', 'from-index-other', 'from-null']);
    assert.ok(dirty.every((row) => row.uncommitted === true));

    const both = parseJson(cli(dir, ['ls', '--agent', 'ci', '--uncommitted', '--json']));
    assert.deepEqual(messagesOf(both), ['from-index-new']);
    assert.equal(both[0].agent, 'ci');
    assert.equal(both[0].uncommitted, true);

    const limited = parseJson(
      cli(dir, ['history', '--agent', 'ci', '--limit', '2', '--json']),
    );
    assert.deepEqual(messagesOf(limited), ['from-index-new', 'from-index-old']);

    const limitedDirty = parseJson(
      cli(dir, ['history', '--uncommitted', '--limit', '1', '--json']),
    );
    assert.deepEqual(messagesOf(limitedDirty), ['from-index-new']);

    const miss = cliResult(dir, ['ls', '--agent', 'other', '--uncommitted', '--limit', '5', '--json']);
    assert.equal(miss.code, 0, miss.err);
    assert.deepEqual(messagesOf(parseJson(miss.out)), ['from-index-other']);

    const humanDirty = cli(dir, ['history', '--agent', 'ci', '--uncommitted']);
    assert.match(humanDirty, /Recent receipts \(1 of 1\)/);
    assert.match(humanDirty, /\[uncommitted\]/);
    assert.match(humanDirty, /from-index-new/);
    assert.doesNotMatch(humanDirty, /from-index-old/);

    const all = parseJson(cli(dir, ['history', '--json']));
    assert.equal(all.length, 9);
    assert.equal(all[0].message, 'from-index-new');
    assert.equal(all[4].agent, null);
    assert.equal('agent' in all[5], false);
  });

  it('scans outDir when the index is missing and still filters', () => {
    const dir = keep('agent-receipt-hist-scan-');
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    const files = [
      {
        name: 'newer-ci-dirty.md',
        ms: Date.parse('2026-09-22T00:00:06.000Z'),
        agent: 'ci',
        uncommitted: true,
        message: 'scan-newer-ci',
      },
      {
        name: 'mid-other-dirty.md',
        ms: Date.parse('2026-09-22T00:00:05.000Z'),
        agent: 'other',
        uncommitted: true,
        message: 'scan-other',
      },
      {
        name: 'old-ci.md',
        ms: Date.parse('2026-09-22T00:00:04.000Z'),
        agent: 'ci',
        uncommitted: false,
        message: 'scan-old-ci',
      },
      {
        name: 'case-CI.md',
        ms: Date.parse('2026-09-22T00:00:03.000Z'),
        agent: 'CI',
        uncommitted: false,
        message: 'scan-case',
      },
      {
        name: 'null-agent-dirty.md',
        ms: Date.parse('2026-09-22T00:00:02.000Z'),
        agent: null,
        uncommitted: true,
        message: 'scan-null',
      },
      {
        name: 'string-null.md',
        ms: Date.parse('2026-09-22T00:00:01.000Z'),
        agent: 'null',
        uncommitted: false,
        message: 'scan-string-null',
      },
    ];
    for (const file of files) {
      const path = join(outDir, file.name);
      writeFileSync(
        path,
        receiptMd({
          agent: file.agent,
          uncommitted: file.uncommitted,
          message: file.message,
          timestamp: new Date(file.ms).toISOString(),
        }),
      );
      const when = new Date(file.ms);
      utimesSync(path, when, when);
    }

    const ci = parseJson(cli(dir, ['history', '--agent', 'ci', '--json']));
    assert.deepEqual(messagesOf(ci), ['scan-newer-ci', 'scan-old-ci']);
    assert.equal(ci[0].agent, 'ci');
    assert.equal(ci[1].agent, 'ci');
    assert.equal('uncommitted' in ci[0], false);
    assert.deepEqual(Object.keys(ci[0]).sort(), [
      'agent',
      'branch',
      'deletions',
      'files',
      'head',
      'insertions',
      'message',
      'path',
      'risk',
      'sha256',
      'timestamp',
    ]);
    assert.equal(ci[0].risk.high, 0);
    assert.equal(ci[0].files, 1);

    const dirty = parseJson(cli(dir, ['ls', '--uncommitted', '--json']));
    assert.deepEqual(messagesOf(dirty), ['scan-newer-ci', 'scan-other', 'scan-null']);
    assert.equal(dirty[2].agent, null);

    const both = parseJson(
      cli(dir, ['history', '--agent', 'ci', '--uncommitted', '--limit', '1', '--json']),
    );
    assert.deepEqual(messagesOf(both), ['scan-newer-ci']);

    const spelled = parseJson(cli(dir, ['history', '--agent', 'null', '--json']));
    assert.deepEqual(messagesOf(spelled), ['scan-string-null']);

    const none = cliResult(dir, ['history', '--agent', 'nobody', '--uncommitted', '--json']);
    assert.equal(none.code, 0, none.err);
    assert.deepEqual(parseJson(none.out), []);

    const human = cli(dir, ['ls', '--uncommitted', '--limit', '1']);
    assert.match(human, /Recent receipts \(1 of 3\)/);
    assert.match(human, /\[uncommitted\]/);
    assert.match(human, /scan-newer-ci/);
    assert.doesNotMatch(human, /scan-old-ci/);
    assert.doesNotMatch(human, /scan-other/);
  });

  it('errors when the store is empty and exits 0 when only the filter misses', () => {
    const empty = keep('agent-receipt-hist-empty-');
    const plain = cliResult(empty, ['history']);
    assert.equal(plain.code, 1);
    assert.match(plain.err, /No receipts found/);
    assert.equal(plain.out.trim(), '');

    const filtered = cliResult(empty, ['ls', '--agent', 'ci', '--uncommitted', '--json']);
    assert.equal(filtered.code, 1);
    assert.match(filtered.err, /No receipts found/);
    assert.equal(filtered.out.trim(), '');

    const dir = writeIndex(keep('agent-receipt-hist-miss-'));
    const miss = cliResult(dir, ['history', '--agent', 'ci', '--uncommitted', '--json']);
    assert.equal(miss.code, 0, miss.err);
    assert.equal(parseJson(miss.out).length, 1);
    const none = cliResult(root, ['history', '--cwd', dir, '--agent', 'missing-name', '--json']);
    assert.equal(none.code, 0, none.err);
    assert.deepEqual(parseJson(none.out), []);
  });

  it('rejects unknown flags, a bare --agent, and --uncommitted with a value', () => {
    const dir = writeIndex(keep('agent-receipt-hist-flags-'));

    const unknown = cliResult(dir, ['history', '--agents', 'ci']);
    assert.equal(unknown.code, 1);
    assert.match(unknown.err, /Unknown flag: --agents/);
    assert.match(unknown.err, /--limit/);
    assert.match(unknown.err, /--json/);
    assert.match(unknown.err, /--agent/);
    assert.match(unknown.err, /--uncommitted/);
    assert.match(unknown.err, /--cwd/);
    assert.equal(unknown.out.trim(), '');

    const failed = cliResult(dir, ['ls', '--failed']);
    assert.equal(failed.code, 1);
    assert.match(failed.err, /Unknown flag: --failed/);

    const nope = cliResult(dir, ['history', '--nope']);
    assert.equal(nope.code, 1);
    assert.match(nope.err, /Unknown flag: --nope/);

    const bare = cliResult(dir, ['history', '--agent']);
    assert.equal(bare.code, 1);
    assert.match(bare.err, /--agent requires a name/);
    assert.match(bare.err, /agent null/);
    assert.equal(bare.out.trim(), '');

    const bareJson = cliResult(dir, ['ls', '--agent', '--json']);
    assert.equal(bareJson.code, 1);
    assert.match(bareJson.err, /--agent requires a name/);
    assert.equal(bareJson.out.trim(), '');

    const emptyAgent = cliResult(dir, ['history', '--agent=']);
    assert.equal(emptyAgent.code, 1);
    assert.match(emptyAgent.err, /--agent requires a name/);

    const valued = cliResult(dir, ['ls', '--uncommitted', 'yes']);
    assert.equal(valued.code, 1);
    assert.match(valued.err, /--uncommitted does not take a value/);

    const help = cli(dir, ['help', 'history']);
    assert.match(help, /--agent <name>/);
    assert.match(help, /--uncommitted/);
    assert.match(help, /exact, case-sensitive/);
    assert.match(help, /agent: null/);
    assert.match(help, /Filter order: load receipts/);
    assert.match(help, /--cwd/);
    const order = help.indexOf('Filter order: load receipts');
    const agentAt = help.indexOf('--agent', order);
    const uncommittedAt = help.indexOf('--uncommitted', agentAt);
    const limitAt = help.indexOf('--limit', uncommittedAt);
    assert.ok(order >= 0 && agentAt > order && uncommittedAt > agentAt && limitAt > uncommittedAt);

    assert.match(cli(dir, ['help']), /history --agent cursor/);
    assert.match(cli(dir, ['help']), /history --uncommitted/);
    assert.match(cli(dir, ['help', 'ls']), /help history/);
  });

  it('filters agent and uncommitted fields that capture writes', () => {
    const dir = keep('agent-receipt-hist-capture-');
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# history\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);

    cli(dir, ['capture', '--commits', '1', '--agent', 'ci', '--message', 'committed-ci']);
    writeFileSync(join(dir, 'README.md'), '# history\n\nedit\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'edit']);
    cli(dir, ['capture', '--commits', '1', '--agent', 'CI', '--message', 'case-ci']);
    writeFileSync(join(dir, 'wip.txt'), 'dirty\n');
    cli(dir, ['capture', '--uncommitted', '--agent', 'ci', '--message', 'dirty-ci']);

    const ci = parseJson(cli(dir, ['history', '--agent', 'ci', '--json']));
    assert.deepEqual(messagesOf(ci), ['dirty-ci', 'committed-ci']);
    assert.equal(ci[0].agent, 'ci');
    assert.equal(ci[0].uncommitted, true);
    assert.equal(ci[1].agent, 'ci');
    assert.equal(ci[1].uncommitted, false);

    const limited = parseJson(cli(dir, ['ls', '--agent', 'ci', '--limit', '1', '--json']));
    assert.deepEqual(messagesOf(limited), ['dirty-ci']);

    const upper = parseJson(cli(dir, ['history', '--agent', 'CI', '--json']));
    assert.deepEqual(messagesOf(upper), ['case-ci']);
    assert.equal(upper[0].uncommitted, false);

    const dirty = parseJson(cli(dir, ['history', '--uncommitted', '--json']));
    assert.deepEqual(messagesOf(dirty), ['dirty-ci']);

    const both = parseJson(
      cli(dir, ['ls', '--agent', 'ci', '--uncommitted', '--limit', '5', '--json']),
    );
    assert.deepEqual(messagesOf(both), ['dirty-ci']);

    const none = cliResult(dir, ['history', '--agent', 'other', '--json']);
    assert.equal(none.code, 0, none.err);
    assert.deepEqual(parseJson(none.out), []);

    const human = cli(dir, ['history', '--agent', 'ci']);
    assert.match(human, /dirty-ci/);
    assert.match(human, /committed-ci/);
    assert.match(human, /\[uncommitted\]/);
    assert.doesNotMatch(human, /case-ci/);
    assert.match(human, /Recent receipts \(2 of 2\)/);
  });
});

describe('v1.0.11 docs', () => {
  it('covers history --agent and --uncommitted without editing the live workflow', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.11\]/);
    assert.match(changelog, /history --agent/);
    assert.match(changelog, /history --uncommitted/);
    assert.match(changelog, /does not gain `--failed`/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /history --agent ci --json/);
    assert.match(mirror, /history --uncommitted --json/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /history --agent/);
    assert.doesNotMatch(live, /history --uncommitted/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /--agent <name>/);
    assert.match(business, /--uncommitted/);
    assert.match(business, /Filter order: load receipts/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /history --agent/);
    assert.match(readme, /history --uncommitted/);
  });
});
