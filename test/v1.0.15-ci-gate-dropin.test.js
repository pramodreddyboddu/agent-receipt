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

describe('v1.0.15 init --retention', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function freshDir(prefix) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    return dir;
  }

  it('sets maxCount 100 and maxAgeDays 30 on a fresh init, and is idempotent', () => {
    const dir = freshDir('agent-receipt-1015-ret-fresh-');
    const out = cli(dir, ['init', '--retention']);
    assert.match(out, /Initialized/);
    assert.match(out, /maxCount: 100 \(set\)/);
    assert.match(out, /maxAgeDays: 30 \(set\)/);
    assert.match(out, /prune --dry-run/);
    const ymlPath = join(dir, '.agent-receipt.yml');
    const yml = readFileSync(ymlPath, 'utf8');
    assert.match(yml, /^maxCount:\s*100\s*$/m);
    assert.match(yml, /^maxAgeDays:\s*30\s*$/m);
    assert.match(yml, /node_modules\/\*\*/);
    assert.match(yml, /^# redact:/m);
    const again = cli(dir, ['init', '--retention']);
    assert.match(again, /maxCount: 100 \(unchanged\)/);
    assert.match(again, /maxAgeDays: 30 \(unchanged\)/);
    assert.equal(readFileSync(ymlPath, 'utf8'), yml);
  });

  it('merges retention keys and preserves ignore and redact', () => {
    const dir = freshDir('agent-receipt-1015-ret-merge-');
    const ymlPath = join(dir, '.agent-receipt.yml');
    const original = [
      'outDir: .agent-receipt/receipts',
      'ignore:',
      '  - node_modules/**',
      '  - secret-local/**',
      'redact: true',
      'failOn: medium',
      '# keep this comment',
      '# maxCount: 40',
      '',
    ].join('\n');
    writeFileSync(ymlPath, original);
    const out = cli(dir, ['init', '--retention']);
    assert.match(out, /Retention defaults applied/);
    assert.match(out, /maxCount: 100 \(set\)/);
    assert.match(out, /maxAgeDays: 30 \(set\)/);
    const after = readFileSync(ymlPath, 'utf8');
    assert.match(after, /secret-local\/\*\*/);
    assert.match(after, /^redact:\s*true\s*$/m);
    assert.match(after, /^failOn:\s*medium\s*$/m);
    assert.match(after, /^outDir:\s*\.agent-receipt\/receipts\s*$/m);
    assert.match(after, /^# keep this comment\s*$/m);
    assert.match(after, /^maxCount:\s*100\s*$/m);
    assert.match(after, /^maxAgeDays:\s*30\s*$/m);
    assert.doesNotMatch(after, /maxCount:\s*40/);
  });
});

describe('v1.0.15 trusted prune', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function makeDir(auditLine) {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1015-prune-'));
    dirs.push(dir);
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(dir, '.agent-receipt.yml'), 'outDir: .agent-receipt/receipts\n');
    const auditPath = join(dir, '.agent-receipt', 'audit.jsonl');
    if (auditLine != null) writeFileSync(auditPath, auditLine);
    const writeReceipt = (name, iso) => {
      const md = join(outDir, name);
      writeFileSync(md, '# receipt\n');
      const t = new Date(iso);
      utimesSync(md, t, t);
      return md;
    };
    writeFileSync(
      join(dir, '.agent-receipt', 'index.json'),
      JSON.stringify(
        {
          version: 1,
          updatedAt: '2020-01-01T00:00:00.000Z',
          receipts: [
            {
              path: '.agent-receipt/receipts/receipt-new.md',
              timestamp: '2026-01-01T00:00:00.000Z',
            },
            {
              path: '.agent-receipt/receipts/receipt-old.md',
              timestamp: '2020-01-01T00:00:00.000Z',
            },
          ],
        },
        null,
        2,
      ) + '\n',
    );
    writeReceipt('receipt-old.md', '2020-01-01T00:00:00.000Z');
    writeReceipt('receipt-new.md', '2026-01-01T00:00:00.000Z');
    return { dir, outDir, auditPath };
  }

  it('dry-run plans and apply deletes when the audit chain is intact', () => {
    const { dir, outDir, auditPath } = makeDir('{"event":"wrap","prev":null}\n');
    const before = readFileSync(auditPath, 'utf8');
    const preview = cliResult(dir, ['prune', '--dry-run', '--max-count', '1', '--json']);
    assert.equal(preview.code, 0, preview.err + preview.out);
    const planned = JSON.parse(preview.out);
    assert.equal(planned.ok, true);
    assert.equal(planned.exitCode, 0);
    assert.equal(planned.chainOk, true);
    assert.equal(planned.auditPresent, true);
    assert.equal(planned.dryRun, true);
    assert.equal(planned.deleted.length, 1);
    assert.match(planned.deleted[0].path, /receipt-old\.md$/);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), true);
    assert.equal(readFileSync(auditPath, 'utf8'), before);

    const applied = cliResult(dir, ['prune', '--max-count', '1', '--json']);
    assert.equal(applied.code, 0, applied.err + applied.out);
    const body = JSON.parse(applied.out);
    assert.equal(body.ok, true);
    assert.equal(body.chainOk, true);
    assert.equal(body.deleted.length, 1);
    assert.equal(body.audited, 1);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), false);
    assert.equal(existsSync(join(outDir, 'receipt-new.md')), true);
    assert.ok(readFileSync(auditPath, 'utf8').length > before.length);
  });

  it('refuses a broken audit chain, including dry-run, and --json says why', () => {
    const { dir, outDir, auditPath } = makeDir('{"event":"wrap"}\n');
    const before = readFileSync(auditPath, 'utf8');
    const preview = cliResult(dir, ['prune', '--dry-run', '--max-count', '1', '--json']);
    assert.equal(preview.code, 1, preview.out);
    const planned = JSON.parse(preview.out);
    assert.equal(planned.ok, false);
    assert.equal(planned.exitCode, 1);
    assert.equal(planned.dryRun, true);
    assert.equal(planned.chainOk, false);
    assert.equal(planned.auditPresent, true);
    assert.equal(planned.audited, 0);
    assert.match(planned.reason, /trusted prune refused/i);
    assert.match(planned.reason, /chain broken/i);
    assert.match(planned.reason, /Nothing was deleted/);
    assert.equal(planned.deleted.length, 1);
    assert.doesNotMatch(preview.out, /Would delete/);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), true);
    assert.equal(readFileSync(auditPath, 'utf8'), before);

    const applied = cliResult(dir, ['prune', '--max-count', '1', '--json']);
    assert.equal(applied.code, 1, applied.out);
    const body = JSON.parse(applied.out);
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 1);
    assert.equal(body.chainOk, false);
    assert.equal(body.auditPresent, true);
    assert.equal(body.audited, 0);
    assert.match(body.reason, /trusted prune refused/i);
    assert.match(applied.err, /trusted prune refused/i);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), true);
    assert.equal(existsSync(join(outDir, 'receipt-new.md')), true);
    assert.equal(readFileSync(auditPath, 'utf8'), before);
  });

  it('prune --force deletes when the audit chain is broken', () => {
    const { dir, outDir } = makeDir('{"event":"wrap"}\n');
    const applied = cliResult(dir, ['prune', '--force', '--max-count', '1', '--json']);
    assert.equal(applied.code, 0, applied.err + applied.out);
    const body = JSON.parse(applied.out);
    assert.equal(body.ok, true);
    assert.equal(body.exitCode, 0);
    assert.equal(body.chainOk, false);
    assert.equal(body.auditPresent, true);
    assert.equal(body.forced, true);
    assert.equal(body.reason, null);
    assert.equal(body.deleted.length, 1);
    assert.equal(existsSync(join(outDir, 'receipt-old.md')), false);
    assert.equal(existsSync(join(outDir, 'receipt-new.md')), true);
  });
});

describe('v1.0.15 gate schema and drop-in examples', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  it('wrap --json includes every key required by docs/gate.schema.json', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1015-gate-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# v1.0.15\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    const wrapped = cliResult(dir, ['wrap', '--json', '--agent', 'ci', '--message', 'gate schema']);
    assert.equal(wrapped.code, 0, wrapped.err + wrapped.out);
    const gate = JSON.parse(wrapped.out);
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'gate.schema.json'), 'utf8'));
    assert.match(schema.$id, /docs\/gate\.schema\.json$/);
    assert.ok(Array.isArray(schema.required) && schema.required.length > 0);
    for (const key of schema.required) {
      assert.equal(Object.prototype.hasOwnProperty.call(gate, key), true, key);
    }
    assert.equal(gate.command, 'wrap');
    assert.equal(gate.ok, true);
    assert.equal(gate.exitCode, 0);
  });

  it('documents the drop-in action, pr gate, and version 1.0.15', () => {
    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /install/);
    assert.match(action, /prove/);
    assert.match(action, /outputs/);
    assert.match(action, /gate-json/);
    assert.match(action, /exitCode !== 0 \|\| g\.ok !== true/);
    const gate = readFileSync(join(root, 'examples', 'github', 'pr-gate.yml'), 'utf8');
    assert.match(gate, /upload-artifact/);
    assert.match(gate, /prove/);
    assert.match(gate, /v1\.0\.17/);
    assert.match(gate, /--fail-on/);
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.15\]/);
    assert.match(changelog, /init --retention/);
    assert.match(changelog, /trusted prune/i);
    assert.match(changelog, /no minisign|signing or attest/i);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.20');
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.20/);
    const helpInit = cli(root, ['help', 'init']);
    assert.match(helpInit, /--retention/);
    assert.match(helpInit, /maxCount: 100/);
    const helpPrune = cli(root, ['help', 'prune']);
    assert.match(helpPrune, /--force/);
    assert.match(helpPrune, /broken/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /gate\.schema\.json/);
    assert.match(business, /init --retention/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /gate\.schema\.json/);
    assert.match(readme, /init --retention/);
  });
});
