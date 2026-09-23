import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
  utimesSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { redactSecretsInText } from '../dist/lib/redact.js';
import { analyzeRisks } from '../dist/lib/risk.js';
import { sha256Hex, appendHashFooter } from '../dist/lib/hash.js';
import { runDoctorChecks } from '../dist/commands/doctor.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const GROQ = 'gsk_' + 'A'.repeat(48);
const XAI = 'xai-' + 'b'.repeat(80);
const SECRET = 'sk-proj-' + 'C'.repeat(40);
const MESSAGE = 'do-not-log-prune-message';

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
  return appendHashFooter(body.endsWith('\n') ? body : body + '\n');
}

describe('groq and xai redaction', () => {
  const sample = [`groq=${GROQ}`, `xai=${XAI}`, 'model=xai-grok-4', 'short=gsk_abc'].join('\n');

  it('masks live keys and leaves short or hyphenated names', () => {
    const out = redactSecretsInText(sample);
    assert.equal(out.includes(GROQ), false);
    assert.equal(out.includes(XAI), false);
    assert.match(out, /gsk_\[REDACTED\]/);
    assert.match(out, /xai-\[REDACTED\]/);
    assert.match(out, /xai-grok-4/);
    assert.match(out, /gsk_abc/);
  });

  it('risk flags the same families', () => {
    const hints = analyzeRisks(
      [{ path: 'src/keys.ts', status: 'M', insertions: 2, deletions: 0, binary: false }],
      { 'src/keys.ts': `+${GROQ}\n+${XAI}\n` },
    );
    const codes = new Set(hints.map((h) => h.code));
    assert.ok(codes.has('groq-api-key'), [...codes].join(','));
    assert.ok(codes.has('xai-api-key'), [...codes].join(','));
  });
});

describe('prune audit events', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function makeDir() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-prune-audit-'));
    dirs.push(dir);
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(dir, '.agent-receipt.yml'), 'outDir: .agent-receipt/receipts\n');
    const writeReceipt = (name, iso, body) => {
      const md = join(outDir, name);
      writeFileSync(md, body);
      writeFileSync(md.replace(/\.md$/, '.json'), '{}\n');
      const t = new Date(iso);
      utimesSync(md, t, t);
      return md;
    };
    const writeIndex = (rows) => {
      writeFileSync(
        join(dir, '.agent-receipt', 'index.json'),
        JSON.stringify({ version: 1, updatedAt: '2020-01-01T00:00:00.000Z', receipts: rows }, null, 2) +
          '\n',
      );
    };
    return { dir, outDir, writeReceipt, writeIndex };
  }

  function readAudit(dir) {
    const p = join(dir, '.agent-receipt', 'audit.jsonl');
    if (!existsSync(p)) return [];
    return readFileSync(p, 'utf8')
      .split('\n')
      .filter((line) => line.length > 0);
  }

  it('dry-run plans identity fields and does not append', () => {
    const { dir, outDir, writeReceipt, writeIndex } = makeDir();
    const body = receiptMd(`# receipt\n\n${SECRET}\n\n## Diff\n\n+${SECRET}\n`);
    writeReceipt('receipt-old.md', '2020-01-01T00:00:00.000Z', body);
    writeReceipt('receipt-new.md', '2026-01-01T00:00:00.000Z', receiptMd('# keep\n'));
    writeIndex([
      {
        path: '.agent-receipt/receipts/receipt-new.md',
        timestamp: '2026-01-01T00:00:00.000Z',
        agent: 'cursor',
        message: MESSAGE,
      },
      {
        path: '.agent-receipt/receipts/receipt-old.md',
        timestamp: '2020-01-01T00:00:00.000Z',
        agent: 'cursor',
        message: MESSAGE,
        sha256: 'ignored-when-embedded',
      },
    ]);
    const preview = cliResult(dir, ['prune', '--dry-run', '--max-count', '1', '--json']);
    assert.equal(preview.code, 0, preview.err);
    const report = JSON.parse(preview.out);
    assert.equal(report.command, 'prune');
    assert.equal(report.version, '1.0.20');
    assert.equal(report.exitCode, 0);
    assert.equal(report.audited, 0);
    assert.equal(report.dryRun, true);
    assert.equal(report.deleted.length, 1);
    const row = report.deleted[0];
    assert.match(row.path, /receipt-old\.md$/);
    assert.equal(row.agent, 'cursor');
    assert.equal(row.redacted, false);
    assert.equal(row.verified, true);
    assert.equal(row.failedOn, false);
    assert.equal(row.exitCode, 0);
    assert.equal(row.sha256.length, 64);
    assert.equal(row.sha256.includes(SECRET), false);
    assert.equal(JSON.stringify(row).includes(MESSAGE), false);
    assert.equal(JSON.stringify(row).includes(SECRET), false);
    assert.equal('message' in row, false);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), true);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'audit.jsonl')), false);
  });

  it('apply appends one prune line per deleted receipt and keeps the chain', () => {
    const { dir, outDir, writeReceipt, writeIndex } = makeDir();
    const leaked = receiptMd(
      `# receipt\n\n- **Redacted**: yes — masked\n\n${SECRET}\n`,
    );
    writeReceipt('receipt-mid.md', '2024-01-01T00:00:00.000Z', leaked);
    writeReceipt('receipt-old.md', '2020-01-01T00:00:00.000Z', receiptMd('# old\n'));
    writeReceipt('receipt-new.md', '2026-01-01T00:00:00.000Z', receiptMd('# new\n'));
    writeIndex([
      {
        path: '.agent-receipt/receipts/receipt-new.md',
        timestamp: '2026-01-01T00:00:00.000Z',
        agent: 'keep',
        message: MESSAGE,
      },
      {
        path: '.agent-receipt/receipts/receipt-mid.md',
        timestamp: '2024-01-01T00:00:00.000Z',
        agent: 'mid-agent',
        message: MESSAGE,
      },
      {
        path: '.agent-receipt/receipts/receipt-old.md',
        timestamp: '2020-01-01T00:00:00.000Z',
        agent: 'old-agent',
        message: MESSAGE,
      },
    ]);

    const applied = cliResult(dir, ['retain', '--max-count', '1', '--json']);
    assert.equal(applied.code, 0, applied.err);
    const report = JSON.parse(applied.out);
    assert.equal(report.audited, 2);
    assert.equal(report.deleted.length, 2);
    assert.equal(report.kept, 1);
    assert.equal(existsSync(join(outDir, 'receipt-new.md')), true);
    assert.equal(existsSync(join(outDir, 'receipt-mid.md')), false);
    assert.equal(existsSync(join(outDir, 'receipt-mid.json')), false);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), false);

    const lines = readAudit(dir);
    assert.equal(lines.length, 2);
    const events = lines.map((line) => JSON.parse(line));
    assert.deepEqual(
      events.map((ev) => ev.event),
      ['prune', 'prune'],
    );
    assert.equal(events[0].prev, null);
    assert.equal(events[1].prev, sha256Hex(lines[0] + '\n'));
    for (const ev of events) {
      assert.equal(ev.version, '1.0.20');
      assert.equal(ev.experimental, true);
      assert.equal(ev.failedOn, false);
      assert.equal(ev.exitCode, 0);
      assert.equal(ev.verified, true);
      assert.equal(typeof ev.sha256, 'string');
      assert.equal('message' in ev, false);
      assert.equal(JSON.stringify(ev).includes(MESSAGE), false);
      assert.equal(JSON.stringify(ev).includes(SECRET), false);
      assert.equal(JSON.stringify(ev).includes('## Diff'), false);
    }
    const mid = events.find((ev) => ev.path.endsWith('receipt-mid.md'));
    const old = events.find((ev) => ev.path.endsWith('receipt-old.md'));
    assert.equal(mid.agent, 'mid-agent');
    assert.equal(mid.redacted, true);
    assert.equal(old.agent, 'old-agent');
    assert.equal(old.redacted, false);
    const midRow = report.deleted.find((d) => d.path.endsWith('receipt-mid.md'));
    assert.equal(midRow.sha256, mid.sha256);
    assert.equal(midRow.agent, mid.agent);
    assert.equal(midRow.redacted, mid.redacted);
    assert.equal(midRow.verified, mid.verified);
    assert.equal(midRow.failedOn, mid.failedOn);
    assert.equal(midRow.exitCode, mid.exitCode);

    const verified = cliResult(dir, ['audit', '--verify', '--json']);
    assert.equal(verified.code, 0, verified.err);
    const chain = JSON.parse(verified.out);
    assert.equal(chain.ok, true);
    assert.equal(chain.command, 'audit');
    assert.equal(chain.version, '1.0.20');
    assert.equal(chain.events, 2);

    const again = cliResult(dir, ['prune', '--max-count', '5', '--json']);
    assert.equal(again.code, 0, again.err);
    assert.equal(JSON.parse(again.out).audited, 0);
    assert.equal(readAudit(dir).length, 2);
  });
});

describe('doctor --strict', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function withReceipts(count, ymlExtra) {
    const dir = initRepo('agent-receipt-strict-');
    dirs.push(dir);
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    for (let i = 0; i < count; i++) {
      writeFileSync(join(outDir, `receipt-n-${i}.md`), receiptMd(`# ${i}\n`));
    }
    const base = 'outDir: .agent-receipt/receipts\n';
    writeFileSync(join(dir, '.agent-receipt.yml'), base + (ymlExtra || ''));
    return dir;
  }

  function row(dir, name, opts) {
    return runDoctorChecks(dir, opts).find((c) => c.name === name);
  }

  it('fails unset policy under --strict even when the directory is small', () => {
    const dir = withReceipts(2, '');
    assert.equal(row(dir, 'policy').status, 'info');
    assert.equal(row(dir, 'retention').status, 'info');
    assert.equal(row(dir, 'policy', { strict: true }).status, 'fail');
    assert.equal(row(dir, 'retention', { strict: true }).status, 'fail');
    const plain = cliResult(dir, ['doctor']);
    const strict = cliResult(dir, ['doctor', '--strict']);
    assert.equal(plain.code, 0, plain.out);
    assert.equal(strict.code, 1, strict.out + strict.err);
    assert.match(strict.out, /strict:/);
    assert.match(strict.out, /\[FAIL\].*policy/);
    assert.match(strict.out, /\[FAIL\].*retention/);
    assert.match(cli(dir, ['help', 'doctor']), /--strict/);
  });

  it('fails unset policy under --strict, and unset retention when the directory is under pressure', () => {
    const dir = withReceipts(100, '');
    assert.equal(row(dir, 'policy').status, 'info');
    assert.equal(row(dir, 'retention').status, 'warn');
    assert.equal(row(dir, 'policy', { strict: true }).status, 'fail');
    assert.equal(row(dir, 'retention', { strict: true }).status, 'fail');
    const plain = cliResult(dir, ['doctor']);
    assert.equal(plain.code, 0, plain.out);
    assert.match(plain.out, /\[WARN\].*retention/);
    assert.match(plain.out, /\[INFO\].*policy/);
    assert.match(plain.out, /Ready/);
    const strict = cliResult(dir, ['doctor', '--strict']);
    assert.equal(strict.code, 1, strict.out);
    assert.match(strict.out, /\[FAIL\].*policy/);
    assert.match(strict.out, /\[FAIL\].*retention/);
    assert.match(strict.out, /--fail-on/);
  });

  it('fails only the unset half when the other is configured', () => {
    const policyOnly = withReceipts(100, 'redact: true\nfailOn: high\n');
    assert.equal(row(policyOnly, 'policy', { strict: true }).status, 'pass');
    assert.equal(row(policyOnly, 'retention', { strict: true }).status, 'fail');
    const policyStrict = cliResult(policyOnly, ['doctor', '--strict']);
    assert.equal(policyStrict.code, 1, policyStrict.out);

    const both = withReceipts(100, 'redact: true\nfailOn: high\nmaxCount: 500\n');
    assert.equal(row(both, 'policy', { strict: true }).status, 'pass');
    assert.equal(row(both, 'retention', { strict: true }).status, 'pass');
    const ok = cliResult(both, ['doctor', '--strict']);
    assert.equal(ok.code, 0, ok.out + ok.err);
    assert.match(ok.out, /Ready/);
  });

  it('keeps a configured backlog as a warning under --strict', () => {
    const dir = withReceipts(100, 'maxCount: 1\n');
    assert.equal(row(dir, 'retention').status, 'warn');
    assert.equal(row(dir, 'retention', { strict: true }).status, 'warn');
    assert.equal(row(dir, 'policy', { strict: true }).status, 'fail');
    const strict = cliResult(dir, ['doctor', '--strict']);
    assert.equal(strict.code, 1, strict.out);
    assert.match(strict.out, /\[WARN\].*retention/);
    assert.match(strict.out, /\[FAIL\].*policy/);
    const plain = cliResult(dir, ['doctor']);
    assert.equal(plain.code, 0, plain.out);
  });
});
