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

const CLEAN = { high: 0, medium: 0, low: 0, total: 0, maxSeverity: null };

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
    risk: CLEAN,
    sha256: 'a'.repeat(64),
    ...fields,
  };
}

function receiptMd({ agent, uncommitted, message, timestamp, risks = [] }) {
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
  lines.push(`| Risk | ${risks.length} |`);
  lines.push('');
  lines.push('## Risk findings');
  lines.push('');
  if (risks.length) {
    lines.push('| Sev | Code | Detail |');
    lines.push('|-----|------|--------|');
    for (const r of risks) {
      lines.push(`| ${r.severity} | \`${r.code}\` | ${r.detail} |`);
    }
  } else {
    lines.push('_None detected._');
  }
  lines.push('');
  return lines.join('\n');
}

function writeIndex(dir, receipts) {
  mkdirSync(join(dir, '.agent-receipt'), { recursive: true });
  writeFileSync(
    join(dir, '.agent-receipt', 'index.json'),
    JSON.stringify(
      { version: 1, updatedAt: receipts[0]?.timestamp ?? '2026-09-22T00:00:00.000Z', receipts },
      null,
      2,
    ) + '\n',
  );
}

describe('history --failed', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function keep(prefix) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    return dir;
  }

  it('keeps failedOn true, drops clean rows, and prefers a stored false over high risk', () => {
    const dir = keep('agent-receipt-hist-failed-');
    writeIndex(dir, [
      indexEntry({
        path: 'gate-true.md',
        timestamp: '2026-09-22T00:00:06.000Z',
        agent: 'ci',
        message: 'gate-true',
        uncommitted: false,
        failedOn: true,
        risk: { high: 1, medium: 0, low: 0, total: 1, maxSeverity: 'high' },
      }),
      indexEntry({
        path: 'stored-false-high.md',
        timestamp: '2026-09-22T00:00:05.000Z',
        agent: 'ci',
        message: 'stored-false-high',
        uncommitted: true,
        failedOn: false,
        risk: { high: 3, medium: 0, low: 0, total: 3, maxSeverity: 'high' },
      }),
      indexEntry({
        path: 'medium-gate.md',
        timestamp: '2026-09-22T00:00:04.000Z',
        agent: 'other',
        message: 'medium-gate',
        uncommitted: true,
        failedOn: true,
        risk: { high: 0, medium: 1, low: 0, total: 1, maxSeverity: 'medium' },
      }),
      indexEntry({
        path: 'clean.md',
        timestamp: '2026-09-22T00:00:03.000Z',
        agent: 'ci',
        message: 'clean',
        uncommitted: false,
        failedOn: false,
        risk: CLEAN,
      }),
    ]);

    const failed = parseJson(cli(dir, ['history', '--failed', '--json']));
    assert.ok(failed[0] && Array.isArray(failed));
    assert.equal(cli(dir, ['history', '--failed', '--json']).trim().startsWith('['), true);
    assert.deepEqual(messagesOf(failed), ['gate-true', 'medium-gate']);
    assert.equal(failed[0].failedOn, true);
    assert.equal(failed[1].failedOn, true);
    assert.equal(failed[1].uncommitted, true);
    assert.equal(JSON.stringify(failed).includes('stored-false-high'), false);
    assert.equal(JSON.stringify(failed).includes('clean'), false);

    const all = parseJson(cli(dir, ['ls', '--json']));
    const byMessage = Object.fromEntries(all.map((row) => [row.message, row]));
    assert.equal(byMessage['stored-false-high'].failedOn, false);
    assert.equal(byMessage['stored-false-high'].risk.high, 3);
    assert.equal(byMessage['clean'].failedOn, false);

    const human = cli(dir, ['history']);
    const line = (msg) => human.split('\n').find((l) => l.includes(msg));
    assert.match(line('gate-true'), /\[failed\]/);
    assert.match(line('medium-gate'), /\[failed\]/);
    assert.doesNotMatch(line('stored-false-high'), /\[failed\]/);
    assert.match(line('stored-false-high'), /\[uncommitted\]/);
    assert.doesNotMatch(line('clean'), /\[failed\]/);
  });

  it('matches legacy index rows via risk.high or maxSeverity high, not medium or low', () => {
    const dir = keep('agent-receipt-hist-legacy-');
    const receipts = [
      indexEntry({
        path: 'high-count.md',
        timestamp: '2026-09-22T00:00:05.000Z',
        agent: 'ci',
        message: 'high-count',
        uncommitted: true,
        risk: { high: 2, medium: 1, low: 0, total: 3, maxSeverity: 'high' },
      }),
      indexEntry({
        path: 'severity-only.md',
        timestamp: '2026-09-22T00:00:04.000Z',
        agent: 'ci',
        message: 'severity-only',
        uncommitted: false,
        risk: { high: 0, medium: 0, low: 0, total: 0, maxSeverity: 'high' },
      }),
      indexEntry({
        path: 'medium-only.md',
        timestamp: '2026-09-22T00:00:03.000Z',
        agent: 'ci',
        message: 'medium-only',
        uncommitted: true,
        risk: { high: 0, medium: 4, low: 0, total: 4, maxSeverity: 'medium' },
      }),
      indexEntry({
        path: 'low-only.md',
        timestamp: '2026-09-22T00:00:02.000Z',
        agent: 'ci',
        message: 'low-only',
        uncommitted: false,
        risk: { high: 0, medium: 0, low: 2, total: 2, maxSeverity: 'low' },
      }),
      indexEntry({
        path: 'no-risk.md',
        timestamp: '2026-09-22T00:00:01.000Z',
        agent: 'ci',
        message: 'no-risk',
        uncommitted: false,
      }),
    ];
    delete receipts[0].failedOn;
    delete receipts[1].failedOn;
    delete receipts[2].failedOn;
    delete receipts[3].failedOn;
    delete receipts[4].failedOn;
    delete receipts[4].risk;
    writeIndex(dir, receipts);

    const onDisk = JSON.parse(readFileSync(join(dir, '.agent-receipt', 'index.json'), 'utf8'));
    assert.equal('failedOn' in onDisk.receipts[0], false);
    assert.equal('failedOn' in onDisk.receipts[2], false);

    const failed = parseJson(cli(dir, ['ls', '--failed', '--json']));
    assert.deepEqual(messagesOf(failed), ['high-count', 'severity-only']);
    assert.equal(failed[0].failedOn, true);
    assert.equal(failed[1].failedOn, true);
    assert.equal(failed[0].uncommitted, true);

    const all = parseJson(cli(dir, ['history', '--json']));
    const byMessage = Object.fromEntries(all.map((row) => [row.message, row]));
    assert.equal(byMessage['medium-only'].failedOn, false);
    assert.equal(byMessage['low-only'].failedOn, false);
    assert.equal(byMessage['no-risk'].failedOn, false);
    assert.equal(byMessage['high-count'].failedOn, true);

    const human = cli(dir, ['history', '--failed']);
    assert.match(human, /\[failed\]/);
    assert.match(human, /high-count/);
    assert.match(human, /severity-only/);
    assert.doesNotMatch(human, /medium-only/);
    assert.doesNotMatch(human, /low-only/);
  });

  it('applies --agent, then --uncommitted, then --failed, then --limit', () => {
    const dir = keep('agent-receipt-hist-combo-');
    writeIndex(dir, [
      indexEntry({
        path: 'a.md',
        timestamp: '2026-09-22T00:00:05.000Z',
        agent: 'ci',
        message: 'A',
        uncommitted: true,
        failedOn: true,
        risk: CLEAN,
      }),
      indexEntry({
        path: 'b.md',
        timestamp: '2026-09-22T00:00:04.000Z',
        agent: 'ci',
        message: 'B',
        uncommitted: false,
        failedOn: true,
        risk: CLEAN,
      }),
      indexEntry({
        path: 'c.md',
        timestamp: '2026-09-22T00:00:03.000Z',
        agent: 'ci',
        message: 'C',
        uncommitted: true,
        failedOn: false,
        risk: { high: 1, medium: 0, low: 0, total: 1, maxSeverity: 'high' },
      }),
      indexEntry({
        path: 'd.md',
        timestamp: '2026-09-22T00:00:02.000Z',
        agent: 'other',
        message: 'D',
        uncommitted: true,
        failedOn: true,
        risk: CLEAN,
      }),
      indexEntry({
        path: 'e.md',
        timestamp: '2026-09-22T00:00:01.000Z',
        agent: 'ci',
        message: 'E',
        uncommitted: true,
        failedOn: true,
        risk: CLEAN,
      }),
    ]);

    assert.deepEqual(
      messagesOf(parseJson(cli(dir, ['history', '--agent', 'ci', '--failed', '--json']))),
      ['A', 'B', 'E'],
    );
    assert.deepEqual(
      messagesOf(
        parseJson(cli(dir, ['ls', '--agent', 'ci', '--uncommitted', '--failed', '--json'])),
      ),
      ['A', 'E'],
    );
    const limited = parseJson(
      cli(dir, ['history', '--agent', 'ci', '--uncommitted', '--failed', '--limit', '1', '--json']),
    );
    assert.deepEqual(messagesOf(limited), ['A']);
    assert.equal(limited[0].failedOn, true);
    assert.equal(limited[0].uncommitted, true);
    assert.equal(limited[0].agent, 'ci');

    assert.deepEqual(
      messagesOf(parseJson(cli(dir, ['ls', '--failed', '--limit', '2', '--json']))),
      ['A', 'B'],
    );
    assert.deepEqual(
      messagesOf(parseJson(cli(dir, ['history', '--agent', 'other', '--failed', '--json']))),
      ['D'],
    );

    const human = cli(dir, ['history', '--agent', 'ci', '--uncommitted', '--failed', '--limit', '1']);
    assert.match(human, /Recent receipts \(1 of 2\)/);
    assert.match(human, /\[failed\]/);
    assert.match(human, /\[uncommitted\]/);
    assert.match(human, /\bA\b/);
    assert.doesNotMatch(human, /\bE\b/);
  });

  it('derives failedOn and uncommitted on the scan path and ignores the index when it is empty', () => {
    const dir = keep('agent-receipt-hist-scan-');
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    const files = [
      {
        name: 'new-high.md',
        ms: Date.parse('2026-09-22T00:00:06.000Z'),
        agent: 'ci',
        uncommitted: true,
        message: 'scan-high',
        risks: [{ severity: 'high', code: 'aws-access-key', detail: 'secret' }],
      },
      {
        name: 'mid.md',
        ms: Date.parse('2026-09-22T00:00:05.000Z'),
        agent: 'ci',
        uncommitted: false,
        message: 'scan-medium',
        risks: [{ severity: 'medium', code: 'package-json-change', detail: 'pkg' }],
      },
      {
        name: 'low.md',
        ms: Date.parse('2026-09-22T00:00:04.000Z'),
        agent: 'ci',
        uncommitted: true,
        message: 'scan-low',
        risks: [{ severity: 'low', code: 'lockfile-change', detail: 'lock' }],
      },
      {
        name: 'both.md',
        ms: Date.parse('2026-09-22T00:00:03.000Z'),
        agent: 'other',
        uncommitted: false,
        message: 'scan-mixed',
        risks: [
          { severity: 'high', code: 'env-file', detail: 'env' },
          { severity: 'medium', code: 'package-json-change', detail: 'pkg' },
        ],
      },
      {
        name: 'clean.md',
        ms: Date.parse('2026-09-22T00:00:02.000Z'),
        agent: 'ci',
        uncommitted: false,
        message: 'scan-clean',
        risks: [],
      },
      {
        name: 'old-high.md',
        ms: Date.parse('2026-09-22T00:00:01.000Z'),
        agent: 'ci',
        uncommitted: true,
        message: 'scan-old-high',
        risks: [{ severity: 'high', code: 'env-file', detail: 'env' }],
      },
    ];
    for (const file of files) {
      const path = join(outDir, file.name);
      writeFileSync(
        path,
        receiptMd({ ...file, timestamp: new Date(file.ms).toISOString() }),
      );
      const when = new Date(file.ms);
      utimesSync(path, when, when);
    }

    const failed = parseJson(cli(dir, ['history', '--failed', '--json']));
    assert.deepEqual(messagesOf(failed), ['scan-high', 'scan-mixed', 'scan-old-high']);
    assert.equal(failed[0].failedOn, true);
    assert.equal(failed[0].uncommitted, true);
    assert.equal(failed[1].uncommitted, false);
    assert.equal(failed[1].failedOn, true);
    assert.equal(failed[0].risk.high, 1);
    assert.equal(failed[0].risk.maxSeverity, 'high');

    const all = parseJson(cli(dir, ['ls', '--json']));
    const byMessage = Object.fromEntries(all.map((row) => [row.message, row]));
    assert.equal(byMessage['scan-medium'].failedOn, false);
    assert.equal(byMessage['scan-medium'].uncommitted, false);
    assert.equal(byMessage['scan-low'].failedOn, false);
    assert.equal(byMessage['scan-low'].uncommitted, true);
    assert.equal(byMessage['scan-clean'].failedOn, false);
    assert.equal(typeof byMessage['scan-clean'].uncommitted, 'boolean');
    assert.deepEqual(Object.keys(byMessage['scan-high']).sort(), [
      'agent',
      'branch',
      'deletions',
      'failedOn',
      'files',
      'head',
      'insertions',
      'message',
      'path',
      'risk',
      'sha256',
      'timestamp',
      'uncommitted',
    ]);

    const combo = parseJson(
      cli(dir, ['history', '--agent', 'ci', '--uncommitted', '--failed', '--limit', '1', '--json']),
    );
    assert.deepEqual(messagesOf(combo), ['scan-high']);

    const human = cli(dir, ['ls', '--failed']);
    assert.match(human, /\[failed\]/);
    assert.match(human, /scan-high/);
    assert.doesNotMatch(human, /scan-medium/);
    assert.doesNotMatch(human, /scan-low/);
    assert.doesNotMatch(human, /scan-clean/);
  });

  it('prefers the index over a high-risk scan when stored failedOn is false', () => {
    const dir = keep('agent-receipt-hist-index-wins-');
    writeIndex(dir, [
      indexEntry({
        path: 'stored.md',
        timestamp: '2026-09-22T00:00:02.000Z',
        agent: 'ci',
        message: 'stored-false',
        uncommitted: false,
        failedOn: false,
        risk: { high: 2, medium: 0, low: 0, total: 2, maxSeverity: 'high' },
      }),
    ]);
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    const decoy = join(outDir, 'disk-high.md');
    writeFileSync(
      decoy,
      receiptMd({
        agent: 'ci',
        uncommitted: false,
        message: 'disk-high',
        timestamp: '2026-09-22T00:00:09.000Z',
        risks: [{ severity: 'high', code: 'env-file', detail: 'env' }],
      }),
    );
    utimesSync(decoy, new Date('2026-09-22T00:00:09.000Z'), new Date('2026-09-22T00:00:09.000Z'));

    const failed = cliResult(dir, ['history', '--failed', '--json']);
    assert.equal(failed.code, 0, failed.err);
    assert.deepEqual(parseJson(failed.out), []);
    const all = parseJson(cli(dir, ['history', '--json']));
    assert.deepEqual(messagesOf(all), ['stored-false']);
    assert.equal(all[0].failedOn, false);
  });

  it('exits 0 when the filter misses and exits 1 when the store is empty', () => {
    const populated = keep('agent-receipt-hist-miss-failed-');
    writeIndex(populated, [
      indexEntry({
        path: 'ok.md',
        timestamp: '2026-09-22T00:00:01.000Z',
        agent: 'ci',
        message: 'ok',
        uncommitted: false,
        failedOn: false,
        risk: { high: 0, medium: 1, low: 0, total: 1, maxSeverity: 'medium' },
      }),
    ]);
    const miss = cliResult(populated, ['history', '--failed', '--json']);
    assert.equal(miss.code, 0, miss.err);
    assert.deepEqual(parseJson(miss.out), []);
    const human = cli(populated, ['ls', '--agent', 'ci', '--failed']);
    assert.match(human, /No receipts match agent=ci, failed/);
    assert.match(human, /1 other receipt/);

    const nobody = cliResult(populated, ['history', '--agent', 'nobody', '--failed', '--json']);
    assert.equal(nobody.code, 0, nobody.err);
    assert.deepEqual(parseJson(nobody.out), []);

    const empty = keep('agent-receipt-hist-empty-failed-');
    const plain = cliResult(empty, ['history', '--failed']);
    assert.equal(plain.code, 1);
    assert.match(plain.err, /No receipts found/);
    assert.equal(plain.out.trim(), '');
    const json = cliResult(empty, ['ls', '--failed', '--json']);
    assert.equal(json.code, 1);
    assert.match(json.err, /No receipts found/);
    assert.equal(json.out.trim(), '');
    const combo = cliResult(empty, ['history', '--agent', 'ci', '--uncommitted', '--failed', '--json']);
    assert.equal(combo.code, 1);
    assert.match(combo.err, /No receipts found/);
  });

  it('rejects unknown flags, a value after --failed, and a bare --agent', () => {
    const dir = keep('agent-receipt-hist-flags-failed-');
    writeIndex(dir, [
      indexEntry({
        path: 'ok.md',
        timestamp: '2026-09-22T00:00:01.000Z',
        agent: 'ci',
        message: 'ok',
        failedOn: true,
        risk: CLEAN,
      }),
    ]);

    const unknown = cliResult(dir, ['history', '--agents', 'ci']);
    assert.equal(unknown.code, 1);
    assert.match(unknown.err, /Unknown flag: --agents/);
    assert.match(unknown.err, /--failed/);
    assert.match(unknown.err, /--uncommitted/);
    assert.equal(unknown.out.trim(), '');

    const nope = cliResult(dir, ['ls', '--nope']);
    assert.equal(nope.code, 1);
    assert.match(nope.err, /Unknown flag: --nope/);

    const valued = cliResult(dir, ['history', '--failed', 'wrap']);
    assert.equal(valued.code, 1);
    assert.match(valued.err, /--failed does not take a value/);
    assert.match(valued.err, /failed the gate/);
    assert.equal(valued.out.trim(), '');

    const assigned = cliResult(dir, ['ls', '--failed=yes']);
    assert.equal(assigned.code, 1);
    assert.match(assigned.err, /--failed does not take a value/);
    assert.equal(assigned.out.trim(), '');

    const asTrue = cliResult(dir, ['history', '--failed=true', '--json']);
    assert.equal(asTrue.code, 0, asTrue.err);
    assert.deepEqual(messagesOf(parseJson(asTrue.out)), ['ok']);

    const bare = cliResult(dir, ['ls', '--agent']);
    assert.equal(bare.code, 1);
    assert.match(bare.err, /--agent requires a name/);
    assert.equal(bare.out.trim(), '');

    const help = cli(dir, ['help', 'history']);
    assert.match(help, /--failed/);
    assert.match(help, /does not take a value/);
    assert.match(help, /\[failed\]/);
    const order = help.indexOf('Filter order: load receipts');
    const agentAt = help.indexOf('--agent', order);
    const uncommittedAt = help.indexOf('--uncommitted', agentAt);
    const failedAt = help.indexOf('--failed', uncommittedAt);
    const limitAt = help.indexOf('--limit', failedAt);
    assert.ok(order >= 0 && agentAt > order && uncommittedAt > agentAt && failedAt > uncommittedAt);
    assert.ok(limitAt > failedAt);
    assert.match(cli(dir, ['help']), /history --failed/);
    assert.match(cli(dir, ['help']), /history --agent ci --failed/);
  });

  it('records failedOn on the index and companion json when capture runs', () => {
    const dir = keep('agent-receipt-hist-capture-failed-');
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, '.gitignore'), '.agent-receipt/\n');
    writeFileSync(join(dir, 'README.md'), '# history\n');
    git(dir, ['add', '.gitignore', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    git(dir, ['add', '.agent-receipt.yml']);
    git(dir, ['commit', '-m', 'config']);

    const clean = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'ci',
      '--message',
      'clean-gate',
      '--fail-on',
      'high',
      '--json',
    ]);
    assert.equal(clean.code, 0, clean.out + clean.err);
    const cleanGate = parseJson(clean.out);
    assert.equal(cleanGate.failedOn, false);
    const cleanFile = parseJson(readFileSync(cleanGate.jsonPath, 'utf8'));
    assert.equal(cleanFile.failedOn, false);

    writeFileSync(join(dir, 'wip.txt'), 'dirty\n');
    const dirtyClean = cliResult(dir, [
      'capture',
      '--uncommitted',
      '--agent',
      'ci',
      '--message',
      'dirty-clean',
      '--fail-on',
      'high',
      '--json',
    ]);
    assert.equal(dirtyClean.code, 0, dirtyClean.out + dirtyClean.err);
    const dirtyCleanFile = parseJson(readFileSync(parseJson(dirtyClean.out).jsonPath, 'utf8'));
    assert.equal(dirtyCleanFile.failedOn, false);
    assert.equal(dirtyCleanFile.uncommitted, true);

    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'hist', version: '1.0.0' }, null, 2) + '\n',
    );
    git(dir, ['add', 'package.json']);
    git(dir, ['commit', '-m', 'add package']);
    const medium = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'ci',
      '--message',
      'medium-gate',
      '--fail-on',
      'medium',
      '--json',
    ]);
    assert.equal(medium.code, 2, medium.out + medium.err);
    const mediumGate = parseJson(medium.out);
    assert.equal(mediumGate.failedOn, true);
    const mediumFile = parseJson(readFileSync(mediumGate.jsonPath, 'utf8'));
    assert.equal(mediumFile.failedOn, true);

    writeFileSync(join(dir, 'leak.js'), 'const k = "AKIAIOSFODNN7EXAMPLE";\n');
    git(dir, ['add', 'leak.js']);
    git(dir, ['commit', '-m', 'leak']);
    const storedFalse = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'other',
      '--message',
      'high-stored-false',
    ]);
    assert.equal(storedFalse.code, 0, storedFalse.out + storedFalse.err);

    const high = cliResult(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'ci',
      '--message',
      'high-gate',
      '--fail-on',
      'high',
      '--json',
    ]);
    assert.equal(high.code, 2, high.out + high.err);
    const highFile = parseJson(readFileSync(parseJson(high.out).jsonPath, 'utf8'));
    assert.equal(highFile.failedOn, true);

    writeFileSync(join(dir, '.env'), 'SECRET=1\n');
    const dirtyFail = cliResult(dir, [
      'capture',
      '--uncommitted',
      '--agent',
      'ci',
      '--message',
      'dirty-fail',
      '--fail-on',
      'high',
      '--json',
    ]);
    assert.equal(dirtyFail.code, 2, dirtyFail.out + dirtyFail.err);
    const dirtyFailFile = parseJson(readFileSync(parseJson(dirtyFail.out).jsonPath, 'utf8'));
    assert.equal(dirtyFailFile.failedOn, true);
    assert.equal(dirtyFailFile.uncommitted, true);

    const idx = parseJson(readFileSync(join(dir, '.agent-receipt', 'index.json'), 'utf8'));
    const stored = Object.fromEntries(idx.receipts.map((row) => [row.message, row]));
    assert.equal(stored['clean-gate'].failedOn, false);
    assert.equal(stored['dirty-clean'].failedOn, false);
    assert.equal(stored['dirty-clean'].uncommitted, true);
    assert.equal(stored['medium-gate'].failedOn, true);
    assert.equal(stored['medium-gate'].risk.high, 0);
    assert.equal(stored['medium-gate'].risk.maxSeverity, 'medium');
    assert.equal(stored['high-stored-false'].failedOn, false);
    assert.ok(stored['high-stored-false'].risk.high > 0);
    assert.equal(stored['high-gate'].failedOn, true);
    assert.ok(stored['high-gate'].risk.high > 0);
    assert.equal(stored['dirty-fail'].failedOn, true);
    assert.equal(stored['dirty-fail'].uncommitted, true);

    const listed = parseJson(cli(dir, ['history', '--json']));
    assert.ok(listed.every((row) => typeof row.failedOn === 'boolean'));
    assert.ok(listed.every((row) => typeof row.uncommitted === 'boolean'));
    const listedByMessage = Object.fromEntries(listed.map((row) => [row.message, row]));
    assert.equal(listedByMessage['high-stored-false'].failedOn, false);

    assert.deepEqual(
      messagesOf(parseJson(cli(dir, ['history', '--failed', '--json']))),
      ['dirty-fail', 'high-gate', 'medium-gate'],
    );
    assert.deepEqual(
      messagesOf(parseJson(cli(dir, ['ls', '--agent', 'ci', '--failed', '--json']))),
      ['dirty-fail', 'high-gate', 'medium-gate'],
    );
    assert.deepEqual(
      messagesOf(
        parseJson(cli(dir, ['history', '--agent', 'ci', '--uncommitted', '--failed', '--limit', '1', '--json'])),
      ),
      ['dirty-fail'],
    );
    const other = parseJson(cli(dir, ['history', '--agent', 'other', '--failed', '--json']));
    assert.deepEqual(other, []);

    const human = cli(dir, ['history']);
    const line = (msg) => human.split('\n').find((l) => l.includes(msg));
    assert.match(line('medium-gate'), /\[failed\]/);
    assert.match(line('dirty-fail'), /\[failed\]/);
    assert.match(line('dirty-fail'), /\[uncommitted\]/);
    assert.doesNotMatch(line('high-stored-false'), /\[failed\]/);
    assert.doesNotMatch(line('clean-gate'), /\[failed\]/);
    assert.doesNotMatch(line('dirty-clean'), /\[failed\]/);
    assert.match(line('dirty-clean'), /\[uncommitted\]/);
  });
});

describe('v1.0.12 docs', () => {
  it('covers history --failed and index failedOn without editing the live workflow', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.12\]/);
    assert.match(changelog, /history --failed/);
    assert.match(changelog, /failedOn/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /history --failed --json/);
    assert.match(mirror, /history --agent ci --failed --json/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /history --failed/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /history --failed/);
    assert.match(business, /failedOn/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /history --failed/);
    assert.match(readme, /history --agent ci --failed/);
    const policy = readFileSync(join(root, 'examples', 'org-policy.yml'), 'utf8');
    assert.match(policy, /history --failed/);
    assert.match(policy, /history --agent ci --failed/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.18');
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.18/);
  });
});
