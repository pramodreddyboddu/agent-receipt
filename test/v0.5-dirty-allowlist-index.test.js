import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  analyzeRisks,
  parseRiskAllowlist,
  applyRiskAllowlist,
  shannonEntropy,
} from '../dist/lib/risk.js';
import { loadConfig, parseSimpleYaml } from '../dist/lib/config.js';
import { loadIndex, INDEX_REL } from '../dist/lib/receipt-index.js';
import { isDirty, dirtyFingerprint, getWorkingTreeFiles } from '../dist/lib/git.js';
import { clampInterval } from '../dist/commands/watch.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args) {
  return execFileSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

function cliStatus(cwd, args) {
  try {
    const out = cli(cwd, args);
    return { ok: true, code: 0, out, err: '' };
  } catch (err) {
    return {
      ok: false,
      code: err.status ?? 1,
      out: String(err.stdout || ''),
      err: String(err.stderr || err.message || err),
    };
  }
}

describe('riskAllowlist + entropy', () => {
  it('parseRiskAllowlist supports code, code:path, *:path', () => {
    const entries = parseRiskAllowlist([
      'package-json-change',
      'lockfile-change:*.lock',
      '*:docs/**',
    ]);
    assert.equal(entries.length, 3);
    assert.deepEqual(entries[0], { code: 'package-json-change' });
    assert.deepEqual(entries[1], { code: 'lockfile-change', path: '*.lock' });
    assert.deepEqual(entries[2], { code: '*', path: 'docs/**' });
  });

  it('applyRiskAllowlist drops matching findings', () => {
    const hints = analyzeRisks([
      { path: 'package.json', status: 'M', insertions: 2, deletions: 1, binary: false },
      { path: '.env', status: 'A', insertions: 1, deletions: 0, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'package-json-change'));
    const filtered = applyRiskAllowlist(hints, ['package-json-change']);
    assert.ok(!filtered.some((h) => h.code === 'package-json-change'));
    assert.ok(filtered.some((h) => h.code === 'env-file'));
  });

  it('analyzeRisks honor allowlist arg', () => {
    const hints = analyzeRisks(
      [{ path: 'package.json', status: 'M', insertions: 1, deletions: 0, binary: false }],
      {},
      ['package-json-change'],
    );
    assert.ok(!hints.some((h) => h.code === 'package-json-change'));
  });

  it('shannonEntropy is high for random-looking tokens', () => {
    const low = shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const high = shannonEntropy('K8vQm2nXp9Lr4sT7wYcB1dF6hJ0aZ3eR');
    assert.ok(low < 1.5);
    assert.ok(high > 4.0);
  });

  it('flags high-entropy tokens in added diff lines', () => {
    const token = 'K8vQm2nXp9Lr4sT7wYcB1dF6hJ0aZ3eRu';
    const files = [
      { path: 'src/secret.ts', status: 'M', insertions: 1, deletions: 0, binary: false },
    ];
    const diffs = {
      'src/secret.ts': `+const apiKey = "${token}";\n`,
    };
    const hints = analyzeRisks(files, diffs);
    assert.ok(
      hints.some((h) => h.code === 'high-entropy-secret' && h.severity === 'high'),
      JSON.stringify(hints, null, 2),
    );
  });

  it('does not flag low-entropy long runs', () => {
    const files = [
      { path: 'src/pad.ts', status: 'M', insertions: 1, deletions: 0, binary: false },
    ];
    const diffs = {
      'src/pad.ts': '+const pad = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";\n',
    };
    const hints = analyzeRisks(files, diffs);
    assert.ok(!hints.some((h) => h.code === 'high-entropy-secret'));
  });
});

describe('config riskAllowlist', () => {
  it('loads riskAllowlist from yaml', () => {
    const parsed = parseSimpleYaml(`
outDir: .agent-receipt/receipts
riskAllowlist:
  - package-json-change
  - "*:docs/**"
`);
    assert.deepEqual(parsed.riskAllowlist, ['package-json-change', '*:docs/**']);
  });
});

describe('capture --uncommitted + index + history --json + allowlist', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-v05-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# v05\n');
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.agent-receipt/\n');
    git(dir, ['add', 'README.md', '.gitignore']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    // Commit config so the tree is clean for dirty-watch tests
    git(dir, ['add', '.agent-receipt.yml']);
    git(dir, ['commit', '-m', 'agent-receipt init']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('detects dirty tree helpers', () => {
    assert.equal(isDirty(dir), false);
    writeFileSync(join(dir, 'wip.txt'), 'hello dirty\n');
    assert.equal(isDirty(dir), true);
    const fp = dirtyFingerprint(dir);
    assert.ok(fp.length > 0);
    const files = getWorkingTreeFiles(dir);
    assert.ok(files.some((f) => f.path === 'wip.txt'));
  });

  it('capture --uncommitted labels snapshot and updates index', () => {
    const out = cli(dir, [
      'capture',
      '--uncommitted',
      '--agent',
      'dirty-bot',
      '--message',
      'wip snapshot',
      '--out',
      'dirty.md',
    ]);
    assert.match(out, /Wrote receipt/);
    assert.match(out, /uncommitted/);
    const md = readFileSync(join(dir, 'dirty.md'), 'utf8');
    assert.match(md, /uncommitted/);
    assert.match(md, /working tree/);
    assert.match(md, /wip\.txt/);
    assert.match(md, /Snapshot.*uncommitted/s);

    const idxPath = join(dir, INDEX_REL);
    assert.ok(existsSync(idxPath), 'index.json should exist');
    const idx = loadIndex(dir);
    assert.ok(idx.receipts.length >= 1);
    assert.equal(idx.receipts[0].uncommitted, true);
    assert.equal(idx.receipts[0].agent, 'dirty-bot');
  });

  it('history --json reads the index', () => {
    const out = cli(dir, ['history', '--json', '--limit', '5']);
    const rows = JSON.parse(out);
    assert.ok(Array.isArray(rows));
    assert.ok(rows.length >= 1);
    assert.ok(rows[0].timestamp || rows[0].path);
    assert.equal(rows[0].uncommitted, true);
  });

  it('history text table shows [uncommitted] badge from index', () => {
    const out = cli(dir, ['history', '--limit', '5']);
    assert.match(out, /Recent receipts/);
    assert.match(out, /\[uncommitted\]/);
    assert.match(out, /dirty-bot|wip snapshot/);
  });

  it('riskAllowlist suppresses package-json-change via config', () => {
    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      `outDir: .agent-receipt/receipts
defaultAgent: agent
defaultCommits: 1
fullDiffs: false
ignore:
  - node_modules/**
  - dist/**
  - coverage/**
riskAllowlist:
  - package-json-change
`,
    );
    const cfg = loadConfig(dir);
    assert.deepEqual(cfg.riskAllowlist, ['package-json-change']);

    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'x', version: '1.0.0' }, null, 2) + '\n',
    );
    git(dir, ['add', 'package.json']);
    git(dir, ['commit', '-m', 'add package']);
    const out = cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'allow',
      '--message',
      'pkg',
      '--out',
      'allow.md',
    ]);
    assert.match(out, /riskAllowlist active/);
    const md = readFileSync(join(dir, 'allow.md'), 'utf8');
    assert.doesNotMatch(md, /package-json-change/);
  });

  it('clampInterval still works', () => {
    assert.equal(clampInterval(undefined), 5);
  });
});

describe('watch dirty tree --once', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-watch-dirty-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# watch dirty\n');
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.agent-receipt/\n');
    git(dir, ['add', 'README.md', '.gitignore']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    git(dir, ['add', '.agent-receipt.yml']);
    git(dir, ['commit', '-m', 'agent-receipt init']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('captures uncommitted when dirty tree changes', async () => {
    const child = spawn(
      process.execPath,
      [
        bin,
        'watch',
        '--once',
        '--interval',
        '1',
        '--agent',
        'dirty-watch',
        '--message',
        'from-dirty-watch',
      ],
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
      const t = setTimeout(
        () => reject(new Error('watch did not start: ' + stdout + stderr)),
        8000,
      );
      const check = () => {
        if (/baseline:/.test(stdout) && /dirty tree/.test(stdout)) {
          clearTimeout(t);
          resolve(true);
        }
      };
      child.stdout.on('data', check);
      check();
    });

    writeFileSync(join(dir, 'dirty-watched.txt'), 'from dirty watch\n');

    const code = await new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('watch --once dirty did not exit: ' + stdout + stderr));
      }, 15000);
      child.on('close', (c) => {
        clearTimeout(t);
        resolve(c);
      });
    });

    assert.equal(code, 0, stdout + stderr);
    assert.match(stdout, /DIRTY|uncommitted|Wrote receipt/);
    const receipts = readdirSync(join(dir, '.agent-receipt', 'receipts')).filter((f) =>
      f.endsWith('.md'),
    );
    assert.ok(receipts.length >= 1);
    const md = readFileSync(
      join(dir, '.agent-receipt', 'receipts', receipts.sort().at(-1)),
      'utf8',
    );
    assert.match(md, /uncommitted|dirty-watched/);
    assert.ok(existsSync(join(dir, '.agent-receipt', 'index.json')));
  });

  it('--commits-only ignores dirty-only changes until a commit', async () => {
    const child = spawn(
      process.execPath,
      [
        bin,
        'watch',
        '--once',
        '--commits-only',
        '--interval',
        '1',
        '--agent',
        'commits-only',
      ],
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
      const t = setTimeout(
        () => reject(new Error('watch did not start: ' + stdout + stderr)),
        8000,
      );
      const check = () => {
        if (/commits only/.test(stdout) || /baseline:/.test(stdout)) {
          clearTimeout(t);
          resolve(true);
        }
      };
      child.stdout.on('data', check);
      check();
    });

    // Dirty-only should NOT trigger with --commits-only
    writeFileSync(join(dir, 'should-not-trigger-alone.txt'), 'nope\n');
    await new Promise((r) => setTimeout(r, 2500));
    assert.ok(!/Wrote receipt/.test(stdout), 'dirty should not capture with --commits-only yet: ' + stdout);

    writeFileSync(join(dir, 'commit-trigger.txt'), 'yes\n');
    git(dir, ['add', 'commit-trigger.txt']);
    git(dir, ['commit', '-m', 'commits-only trigger']);

    const code = await new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('commits-only watch did not exit: ' + stdout + stderr));
      }, 15000);
      child.on('close', (c) => {
        clearTimeout(t);
        resolve(c);
      });
    });
    assert.equal(code, 0, stdout + stderr);
    assert.match(stdout, /HEAD|Wrote receipt/);
  });
});
