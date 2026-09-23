import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
  symlinkSync,
  utimesSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { redactSecretsInText } from '../dist/lib/redact.js';
import { analyzeRisks } from '../dist/lib/risk.js';
import { sha256Hex } from '../dist/lib/hash.js';
import { planRetention } from '../dist/lib/retention.js';
import { runDoctorChecks } from '../dist/commands/doctor.js';
import { loadConfig, validateConfig } from '../dist/lib/config.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const LLM = 'sk-proj-' + 'A'.repeat(40);
const ANTH = 'sk-ant-' + 'B'.repeat(40);
const HF = 'hf_' + 'c'.repeat(34);
const BEARER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig';

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
  writeFileSync(join(dir, 'README.md'), '# v1.0.7 fixture\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  cli(dir, ['init']);
  return dir;
}

function receiptBody() {
  return (
    '# receipt\n\n## Integrity\n\n<!-- agent-receipt-sha256:' +
    'a'.repeat(64) +
    ' -->\n'
  );
}

describe('llm and bearer redaction', () => {
  const sample = [
    `openai=${LLM}`,
    `anthropic=${ANTH}`,
    `hf=${HF}`,
    `Authorization: Bearer ${BEARER}`,
  ].join('\n');

  it('masks the raw values', () => {
    const out = redactSecretsInText(sample);
    for (const secret of [LLM, ANTH, HF, BEARER]) {
      assert.equal(out.includes(secret), false, secret);
    }
    assert.match(out, /sk-proj-\[REDACTED\]/);
    assert.match(out, /sk-ant-\[REDACTED\]/);
    assert.match(out, /hf_\[REDACTED\]/);
    assert.match(out, /Bearer \[REDACTED\]/);
  });

  it('risk flags the same families', () => {
    const hints = analyzeRisks(
      [{ path: 'src/keys.ts', status: 'M', insertions: 4, deletions: 0, binary: false }],
      { 'src/keys.ts': sample.split('\n').map((l) => '+' + l).join('\n') + '\n' },
    );
    const codes = new Set(hints.map((h) => h.code));
    for (const code of ['llm-api-key', 'huggingface-token', 'bearer-token']) {
      assert.ok(codes.has(code), `missing ${code}`);
    }
  });
});

describe('audit events for capture, watch, and export', () => {
  let dir;

  before(() => {
    dir = initRepo('agent-receipt-audit-full-');
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('capture and export append the chain and omit --message', () => {
    writeFileSync(join(dir, 'app.js'), 'export const n = 1;\n');
    git(dir, ['add', 'app.js']);
    git(dir, ['commit', '-m', 'app']);

    const secret = 'do-not-log-capture-message';
    const captured = cliResult(dir, [
      'capture',
      '--json',
      '--agent',
      'ci',
      '--message',
      secret,
      '--commits',
      '1',
    ]);
    assert.equal(captured.code, 0, captured.err);
    const logPath = join(dir, '.agent-receipt', 'audit.jsonl');
    let lines = readFileSync(logPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    const cap = JSON.parse(lines[0]);
    assert.equal(cap.event, 'capture');
    assert.equal(cap.prev, null);
    assert.equal(cap.agent, 'ci');
    assert.equal(cap.exitCode, 0);
    assert.equal(cap.verified, true);
    assert.equal(cap.experimental, true);
    assert.equal(cap.redacted, false);
    assert.equal(typeof cap.sha256, 'string');
    assert.equal(cap.sha256.length, 64);
    assert.match(cap.path, /\.md$/);
    assert.equal(lines[0].includes(secret), false);
    assert.equal('message' in cap, false);

    const exported = cliResult(dir, ['export', '--redact', '--out', 'out.html']);
    assert.equal(exported.code, 0, exported.err);
    lines = readFileSync(logPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);
    const exp = JSON.parse(lines[1]);
    assert.equal(exp.event, 'export');
    assert.equal(exp.prev, sha256Hex(lines[0] + '\n'));
    assert.equal(exp.redacted, true);
    assert.equal(exp.verified, true);
    assert.equal(exp.failedOn, false);
    assert.equal(exp.exitCode, 0);
    assert.match(exp.path, /out\.html$/);
    assert.equal(exp.agent, 'ci');
    assert.equal(lines[1].includes(secret), false);

    const verified = cliResult(dir, ['audit', '--verify', '--json']);
    assert.equal(verified.code, 0, verified.err);
    assert.equal(JSON.parse(verified.out).ok, true);

    const wrapped = cliResult(dir, ['wrap', '--json', '--agent', 'wrapbot', '--message', secret]);
    assert.equal(wrapped.code, 0, wrapped.err);
    lines = readFileSync(logPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 3);
    const wrapEv = JSON.parse(lines[2]);
    assert.equal(wrapEv.event, 'wrap');
    assert.equal(wrapEv.prev, sha256Hex(lines[1] + '\n'));
    assert.equal(lines[2].includes(secret), false);
  });

  it('watch --once appends a watch event, not capture', async () => {
    const child = spawn(
      process.execPath,
      [bin, 'watch', '--once', '--interval', '1', '--agent', 'watch-bot', '--message', 'watch-secret-msg'],
      {
        cwd: dir,
        env: { ...process.env, NO_COLOR: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('watch did not start: ' + stdout + stderr)), 8000);
      const check = () => {
        if (/baseline:/.test(stdout)) {
          clearTimeout(t);
          resolve(true);
        }
      };
      child.stdout.on('data', check);
      check();
    });
    writeFileSync(join(dir, 'watched.js'), 'export const w = 1;\n');
    git(dir, ['add', 'watched.js']);
    git(dir, ['commit', '-m', 'watch trigger']);
    const code = await new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('watch --once did not exit: ' + stdout + stderr));
      }, 15000);
      child.on('close', (c) => {
        clearTimeout(t);
        resolve(c);
      });
    });
    assert.equal(code, 0, stdout + stderr);
    const lines = readFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n');
    const last = JSON.parse(lines[lines.length - 1]);
    assert.equal(last.event, 'watch');
    assert.equal(last.agent, 'watch-bot');
    assert.equal(last.verified, true);
    assert.equal(lines[lines.length - 1].includes('watch-secret-msg'), false);
    assert.equal(JSON.parse(cli(dir, ['audit', '--verify', '--json'])).ok, true);
  });
});

describe('planRetention', () => {
  const file = (rel, timestampMs) => ({
    abs: rel,
    rel,
    timestampMs,
    timestamp: new Date(timestampMs).toISOString(),
    bytes: 10,
    jsonAbs: null,
    jsonRel: null,
    jsonBytes: 0,
  });

  it('keeps a receipt that is exactly maxAgeDays old and drops a strictly older one', () => {
    const now = Date.UTC(2026, 0, 31);
    const day = 24 * 60 * 60 * 1000;
    const plan = planRetention(
      [file('new.md', now - 1 * day), file('exact.md', now - 2 * day), file('old.md', now - 2 * day - 1)],
      { maxCount: null, maxAgeDays: 2, enabled: true },
      now,
    );
    assert.deepEqual(
      plan.delete.map((d) => d.rel),
      ['old.md'],
    );
    assert.deepEqual(plan.delete[0].reasons, ['maxAgeDays']);
    assert.equal(plan.keep.length, 2);
  });

  it('applies count and age together', () => {
    const now = 1_700_000_000_000;
    const day = 24 * 60 * 60 * 1000;
    const plan = planRetention(
      [
        file('newest.md', now),
        file('mid.md', now - day),
        file('old.md', now - 10 * day),
      ],
      { maxCount: 2, maxAgeDays: 5, enabled: true },
      now,
    );
    const byRel = Object.fromEntries(plan.delete.map((d) => [d.rel, d.reasons]));
    assert.deepEqual(byRel['old.md'], ['maxCount', 'maxAgeDays']);
    assert.ok(!byRel['mid.md']);
    assert.equal(plan.keep.map((f) => f.rel).sort().join(), 'mid.md,newest.md');
  });

  it('deletes nothing when retention is off', () => {
    const plan = planRetention([file('a.md', 1)], { maxCount: null, maxAgeDays: null, enabled: false }, 10);
    assert.equal(plan.delete.length, 0);
    assert.equal(plan.keep.length, 1);
  });
});

describe('prune command', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function makeDir() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-prune-'));
    dirs.push(dir);
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(dir, '.agent-receipt.yml'), 'outDir: .agent-receipt/receipts\n');
    // Intact chain (prev null). A broken log would make trusted prune refuse.
    writeFileSync(
      join(dir, '.agent-receipt', 'audit.jsonl'),
      '{"event":"wrap","prev":null}\n',
    );
    writeFileSync(join(dir, '.agent-receipt', 'SETUP.md'), 'keep me\n');
    const writeReceipt = (name, iso) => {
      const md = join(outDir, name);
      writeFileSync(md, receiptBody());
      writeFileSync(md.replace(/\.md$/, '.json'), '{}\n');
      const t = new Date(iso);
      utimesSync(md, t, t);
      return md;
    };
    const writeIndex = (rows) => {
      writeFileSync(
        join(dir, '.agent-receipt', 'index.json'),
        JSON.stringify(
          { version: 1, updatedAt: '2020-01-01T00:00:00.000Z', receipts: rows },
          null,
          2,
        ) + '\n',
      );
    };
    return { dir, outDir, writeReceipt, writeIndex };
  }

  it('does nothing until a limit is set, including dry-run', () => {
    const { dir, outDir, writeReceipt } = makeDir();
    writeReceipt('receipt-old.md', '2020-01-01T00:00:00.000Z');
    writeReceipt('receipt-new.md', '2026-01-01T00:00:00.000Z');
    writeFileSync(join(outDir, 'notes.md'), 'not a receipt\n');
    const preview = cliResult(dir, ['prune', '--dry-run', '--json']);
    assert.equal(preview.code, 0, preview.err);
    const body = JSON.parse(preview.out);
    assert.equal(body.enabled, false);
    assert.equal(body.deleted.length, 0);
    assert.equal(body.indexUpdated, false);
    assert.ok(existsSync(join(outDir, 'receipt-old.md')));
    const plain = cli(dir, ['retain']);
    assert.match(plain, /opt-in/);
    assert.ok(existsSync(join(outDir, 'receipt-old.md')));
  });

  it('dry-run with --max-count does not delete or rewrite the index', () => {
    const { dir, outDir, writeReceipt, writeIndex } = makeDir();
    writeReceipt('receipt-old.md', '2020-01-01T00:00:00.000Z');
    writeReceipt('receipt-new.md', '2026-01-01T00:00:00.000Z');
    writeIndex([
      {
        path: '.agent-receipt/receipts/receipt-new.md',
        timestamp: '2026-01-01T00:00:00.000Z',
      },
      {
        path: '.agent-receipt/receipts/receipt-old.md',
        timestamp: '2020-01-01T00:00:00.000Z',
      },
    ]);
    const before = readFileSync(join(dir, '.agent-receipt', 'index.json'), 'utf8');
    const preview = cliResult(dir, ['prune', '--dry-run', '--max-count', '1', '--json']);
    assert.equal(preview.code, 0, preview.err);
    const body = JSON.parse(preview.out);
    assert.equal(body.dryRun, true);
    assert.equal(body.enabled, true);
    assert.equal(body.deleted.length, 1);
    assert.match(body.deleted[0].path, /receipt-old\.md$/);
    assert.deepEqual(body.deleted[0].reasons, ['maxCount']);
    assert.equal(body.indexUpdated, false);
    assert.ok(existsSync(join(outDir, 'receipt-old.md')));
    assert.ok(existsSync(join(outDir, 'receipt-old.json')));
    assert.equal(readFileSync(join(dir, '.agent-receipt', 'index.json'), 'utf8'), before);
  });

  it('apply keeps the newest, deletes the sibling json, and refreshes the index', () => {
    const { dir, outDir, writeReceipt, writeIndex } = makeDir();
    writeReceipt('receipt-old.md', '2020-01-01T00:00:00.000Z');
    writeReceipt('receipt-new.md', '2026-01-01T00:00:00.000Z');
    writeFileSync(join(outDir, 'notes.md'), 'not a receipt\n');
    writeIndex([
      {
        path: '.agent-receipt/receipts/receipt-new.md',
        timestamp: '2026-01-01T00:00:00.000Z',
      },
      {
        path: '.agent-receipt/receipts/receipt-old.md',
        timestamp: '2020-01-01T00:00:00.000Z',
      },
    ]);
    const applied = cliResult(dir, ['prune', '--max-count', '1', '--json']);
    assert.equal(applied.code, 0, applied.err);
    const body = JSON.parse(applied.out);
    assert.equal(body.deleted.length, 1);
    assert.equal(body.kept, 1);
    assert.equal(body.indexUpdated, true);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), false);
    assert.equal(existsSync(join(outDir, 'receipt-old.json')), false);
    assert.ok(existsSync(join(outDir, 'receipt-new.md')));
    assert.ok(existsSync(join(outDir, 'receipt-new.json')));
    assert.ok(existsSync(join(outDir, 'notes.md')));
    assert.ok(existsSync(join(dir, '.agent-receipt', 'audit.jsonl')));
    assert.ok(existsSync(join(dir, '.agent-receipt', 'SETUP.md')));
    const index = JSON.parse(readFileSync(join(dir, '.agent-receipt', 'index.json'), 'utf8'));
    assert.equal(index.receipts.length, 1);
    assert.match(index.receipts[0].path, /receipt-new\.md$/);
  });

  it('maxAgeDays from config deletes a strictly older receipt', () => {
    const { dir, outDir, writeReceipt, writeIndex } = makeDir();
    const recent = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    writeReceipt('receipt-fresh.md', recent);
    writeReceipt('receipt-aged.md', '2020-06-01T00:00:00.000Z');
    writeIndex([
      { path: '.agent-receipt/receipts/receipt-fresh.md', timestamp: recent },
      {
        path: '.agent-receipt/receipts/receipt-aged.md',
        timestamp: '2020-06-01T00:00:00.000Z',
      },
    ]);
    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      'outDir: .agent-receipt/receipts\nmaxAgeDays: 30\n',
    );
    const applied = cliResult(dir, ['prune', '--json']);
    assert.equal(applied.code, 0, applied.err);
    const body = JSON.parse(applied.out);
    assert.equal(body.maxAgeDays, 30);
    assert.ok(body.deleted.some((d) => d.path.endsWith('receipt-aged.md')));
    assert.equal(existsSync(join(outDir, 'receipt-aged.md')), false);
    assert.ok(existsSync(join(outDir, 'receipt-fresh.md')));
  });

  it('refuses a broken index and an unsafe outDir without deleting', () => {
    const { dir, outDir, writeReceipt } = makeDir();
    writeReceipt('receipt-keep.md', '2026-02-01T00:00:00.000Z');
    writeFileSync(join(dir, '.agent-receipt', 'index.json'), '{');
    const bad = cliResult(dir, ['prune', '--max-count', '1']);
    assert.equal(bad.code, 1);
    assert.match(bad.err, /not valid JSON/);
    assert.ok(existsSync(join(outDir, 'receipt-keep.md')));

    writeFileSync(join(dir, '.agent-receipt.yml'), 'outDir: .\nmaxCount: 1\n');
    writeFileSync(
      join(dir, '.agent-receipt', 'index.json'),
      JSON.stringify({ version: 1, updatedAt: '2026-01-01T00:00:00.000Z', receipts: [] }) + '\n',
    );
    const root = cliResult(dir, ['prune', '--json']);
    assert.equal(root.code, 1);
    assert.match(root.err, /repo root/);
    assert.ok(existsSync(join(outDir, 'receipt-keep.md')));
  });

  it('skips symlinks and does not follow them', () => {
    const { dir, outDir, writeReceipt, writeIndex } = makeDir();
    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      'outDir: .agent-receipt/receipts\nmaxCount: 1\n',
    );
    writeReceipt('receipt-keep.md', '2026-02-01T00:00:00.000Z');
    writeReceipt('receipt-real.md', '2024-01-01T00:00:00.000Z');
    const outside = join(dir, 'outside.md');
    writeFileSync(outside, receiptBody());
    const link = join(outDir, 'receipt-link.md');
    symlinkSync(outside, link);
    writeIndex([
      {
        path: '.agent-receipt/receipts/receipt-keep.md',
        timestamp: '2026-02-01T00:00:00.000Z',
      },
      {
        path: '.agent-receipt/receipts/receipt-real.md',
        timestamp: '2024-01-01T00:00:00.000Z',
      },
    ]);
    const applied = cliResult(dir, ['prune', '--json']);
    assert.equal(applied.code, 0, applied.err);
    assert.ok(existsSync(link));
    assert.ok(existsSync(outside));
    assert.equal(existsSync(join(outDir, 'receipt-real.md')), false);
    assert.ok(existsSync(join(outDir, 'receipt-keep.md')));
  });

  it('rejects max-count 0', () => {
    const { dir } = makeDir();
    const bad = cliResult(dir, ['prune', '--max-count', '0']);
    assert.equal(bad.code, 1);
    assert.match(bad.err, /max-count/);
  });
});

describe('doctor retention', () => {
  let dir;

  before(() => {
    dir = initRepo('agent-receipt-doctor-retain-');
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('is info when opt-in is off', () => {
    const clean = initRepo('agent-receipt-doctor-retain-info-');
    try {
      const row = runDoctorChecks(clean).find((c) => c.name === 'retention');
      assert.equal(row.status, 'info');
      assert.match(row.detail, /opt-in off/);
      const out = cli(clean, ['doctor']);
      assert.match(out, /\[INFO\].*retention/);
      assert.match(out, /Ready/);
    } finally {
      rmSync(clean, { recursive: true, force: true });
    }
  });

  it('warns when a configured limit would delete, and fails on maxCount 0', () => {
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    for (const [name, iso] of [
      ['receipt-a.md', '2026-01-02T00:00:00.000Z'],
      ['receipt-b.md', '2020-01-02T00:00:00.000Z'],
    ]) {
      writeFileSync(join(outDir, name), receiptBody());
    }
    writeFileSync(
      join(dir, '.agent-receipt', 'index.json'),
      JSON.stringify({
        version: 1,
        updatedAt: '2026-01-02T00:00:00.000Z',
        receipts: [
          { path: '.agent-receipt/receipts/receipt-a.md', timestamp: '2026-01-02T00:00:00.000Z' },
          { path: '.agent-receipt/receipts/receipt-b.md', timestamp: '2020-01-02T00:00:00.000Z' },
        ],
      }) + '\n',
    );
    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      'outDir: .agent-receipt/receipts\nmaxCount: 1\n',
    );
    const row = runDoctorChecks(dir).find((c) => c.name === 'retention');
    assert.equal(row.status, 'warn');
    assert.match(row.detail, /would be removed/);
    const out = cli(dir, ['doctor']);
    assert.match(out, /\[WARN\].*retention/);
    assert.match(out, /Ready/);

    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      'outDir: .agent-receipt/receipts\nmaxCount: 0\n',
    );
    const cfg = loadConfig(dir);
    assert.ok(validateConfig(cfg).some((p) => /maxCount/.test(p)));
    const failed = runDoctorChecks(dir).find((c) => c.name === 'retention');
    assert.equal(failed.status, 'fail');
    const doctor = cliResult(dir, ['doctor']);
    assert.equal(doctor.code, 1);
    assert.match(doctor.out, /\[FAIL\].*retention/);
  });

  it('warns on disk pressure when nothing is configured', () => {
    const outDir = join(dir, '.agent-receipt', 'receipts');
    writeFileSync(join(dir, '.agent-receipt.yml'), 'outDir: .agent-receipt/receipts\n');
    for (let i = 0; i < 100; i++) {
      writeFileSync(join(outDir, `receipt-bulk-${i}.md`), receiptBody());
    }
    const row = runDoctorChecks(dir).find((c) => c.name === 'retention');
    assert.equal(row.status, 'warn');
    assert.match(row.detail, /opt-in off/);
    const count = Number((row.detail.match(/(\d+) receipt/) || [])[1]);
    assert.ok(count >= 100, row.detail);
  });
});
