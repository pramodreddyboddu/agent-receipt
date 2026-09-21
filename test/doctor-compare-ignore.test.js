import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  pathMatchesGlob,
  filterIgnored,
  isIgnoredPath,
} from '../dist/lib/ignore.js';
import { parseSimpleYaml, loadConfig, validateConfig } from '../dist/lib/config.js';
import { runDoctorChecks } from '../dist/commands/doctor.js';
import { parseReceiptGlance } from '../dist/commands/compare.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args, env = {}) {
  return execFileSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...env },
  });
}

function cliFail(cwd, args) {
  try {
    cli(cwd, args);
    return { ok: true, out: '', code: 0 };
  } catch (err) {
    return {
      ok: false,
      out: String(err.stdout || ''),
      err: String(err.stderr || err.message || err),
      code: err.status ?? 1,
    };
  }
}

describe('ignore globs', () => {
  it('matches directory and basename patterns', () => {
    assert.equal(pathMatchesGlob('dist/app.js', 'dist/**'), true);
    assert.equal(pathMatchesGlob('dist', 'dist/**'), true);
    assert.equal(pathMatchesGlob('src/app.js', 'dist/**'), false);
    assert.equal(pathMatchesGlob('node_modules/x/y.js', 'node_modules'), true);
    assert.equal(pathMatchesGlob('coverage/lcov.info', 'coverage/**'), true);
    assert.equal(pathMatchesGlob('yarn.lock', '*.lock'), true);
    assert.equal(pathMatchesGlob('pkg/yarn.lock', '*.lock'), true);
    assert.equal(pathMatchesGlob('package-lock.json', 'package-lock.json'), true);
  });

  it('filterIgnored splits kept vs ignored', () => {
    const files = [
      { path: 'src/a.ts' },
      { path: 'dist/bundle.js' },
      { path: 'coverage/out.html' },
      { path: 'README.md' },
    ];
    const { kept, ignored } = filterIgnored(files, [
      'dist/**',
      'coverage/**',
      'node_modules/**',
    ]);
    assert.deepEqual(
      kept.map((f) => f.path),
      ['src/a.ts', 'README.md'],
    );
    assert.equal(ignored.length, 2);
  });

  it('parseSimpleYaml reads ignore lists', () => {
    const parsed = parseSimpleYaml(`
outDir: .agent-receipt/receipts
ignore:
  - dist/**
  - "*.lock"
fullDiffs: false
`);
    assert.deepEqual(parsed.ignore, ['dist/**', '*.lock']);
    assert.equal(parsed.fullDiffs, false);
  });
});

describe('doctor', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-doctor-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# doctor fixture\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('runDoctorChecks reports pass for node/git/repo', () => {
    const checks = runDoctorChecks(dir);
    const byName = Object.fromEntries(checks.map((c) => [c.name, c]));
    assert.equal(byName.node.status, 'pass');
    assert.equal(byName.git.status, 'pass');
    assert.equal(byName.repo.status, 'pass');
    assert.ok(['warn', 'pass'].includes(byName.config.status));
    assert.ok(['warn', 'pass', 'info'].includes(byName.hooks.status));
  });

  it('cli doctor exits 0 in a healthy repo after init', () => {
    cli(dir, ['init']);
    const out = cli(dir, ['doctor']);
    assert.match(out, /doctor/);
    assert.match(out, /\[PASS\].*node/i);
    assert.match(out, /\[PASS\].*git/i);
    assert.match(out, /\[PASS\].*repo/i);
    assert.match(out, /\[PASS\].*config/i);
    assert.match(out, /Ready/);
  });

  it('cli doctor fails outside git repo', () => {
    const bare = mkdtempSync(join(tmpdir(), 'agent-receipt-doctor-bare-'));
    try {
      const r = cliFail(bare, ['doctor']);
      assert.equal(r.ok, false);
      assert.equal(r.code, 1);
      assert.match(r.out + r.err, /FAIL/i);
      assert.match(r.out + r.err, /not a git repository/i);
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });

  it('doctor passes hooks after install-hooks', () => {
    cli(dir, ['install-hooks']);
    const out = cli(dir, ['doctor']);
    assert.match(out, /\[PASS\].*hooks/i);
    cli(dir, ['uninstall-hooks']);
  });
});

describe('compare + capture ignore', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-compare-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# compare fixture\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('capture honors ignore globs for dist noise', () => {
    mkdirSync(join(dir, 'dist'), { recursive: true });
    writeFileSync(join(dir, 'dist', 'bundle.js'), 'console.log("noise")\n');
    writeFileSync(join(dir, 'app.js'), 'export const x = 1\n');
    git(dir, ['add', '.']);
    git(dir, ['commit', '-m', 'add app + dist']);

    const out = cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'test',
      '--message',
      'with-dist',
      '--out',
      'r1.md',
      '--json',
    ]);
    assert.match(out, /Wrote receipt/);
    assert.match(out, /ignored/i);
    const md = readFileSync(join(dir, 'r1.md'), 'utf8');
    assert.doesNotMatch(md, /dist\/bundle\.js/);
    assert.match(md, /app\.js/);
    const json = JSON.parse(readFileSync(join(dir, 'r1.json'), 'utf8'));
    assert.ok(json.files.every((f) => !f.path.startsWith('dist/')));
    assert.match(md, /1\.0\.4/);
  });

  it('compare shows file deltas between two receipts', () => {
    writeFileSync(join(dir, 'extra.ts'), 'export {}\n');
    git(dir, ['add', 'extra.ts']);
    git(dir, ['commit', '-m', 'add extra']);
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'test',
      '--message',
      'second',
      '--out',
      'r2.md',
    ]);

    const out = cli(dir, ['compare', 'r2.md', 'r1.md']);
    assert.match(out, /Receipt compare/);
    assert.match(out, /Session/);
    assert.match(out, /Files/);
    // extra.ts only in newer
    assert.match(out, /\+ extra\.ts|\+ `?extra\.ts/);
  });

  it('compare with no args uses last vs previous under outDir', () => {
    cli(dir, ['capture', '--commits', '1', '--message', 'out1']);
    // tiny pause not needed — different filenames via timestamp; force second
    cli(dir, ['capture', '--commits', '1', '--message', 'out2']);
    const out = cli(dir, ['compare']);
    assert.match(out, /Receipt compare/);
    assert.match(out, /\.agent-receipt\/receipts\//);
  });

  it('diff alias works', () => {
    const out = cli(dir, ['diff', 'r2.md', 'r1.md']);
    assert.match(out, /Receipt compare/);
  });

  it('parseReceiptGlance extracts files and risks', () => {
    const g = parseReceiptGlance(join(dir, 'r1.md'));
    assert.ok(g.files.includes('app.js'));
    assert.ok(g.head);
    assert.equal(g.agent, 'test');
  });

  it('help doctor shows topic', () => {
    const out = cli(dir, ['help', 'doctor']);
    assert.match(out, /environment health check/i);
    assert.match(out, /Node\.js >= 20/);
  });

  it('validateConfig catches bad defaultCommits', () => {
    const problems = validateConfig({
      outDir: 'x',
      defaultAgent: 'a',
      defaultCommits: 0,
      fullDiffs: false,
      ignore: [],
    });
    assert.ok(problems.some((p) => /defaultCommits/.test(p)));
  });

  it('loadConfig returns default ignore list', () => {
    const bare = mkdtempSync(join(tmpdir(), 'agent-receipt-cfg-'));
    try {
      const cfg = loadConfig(bare);
      assert.ok(cfg.ignore.includes('dist/**'));
      assert.ok(isIgnoredPath('dist/x.js', cfg.ignore));
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });
});
