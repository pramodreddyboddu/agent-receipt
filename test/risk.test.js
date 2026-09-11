import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRisks, summarizeRisks } from '../dist/lib/risk.js';

describe('analyzeRisks', () => {
  it('flags secret-looking paths', () => {
    const hints = analyzeRisks([
      { path: '.env', status: 'A', insertions: 3, deletions: 0, binary: false },
      { path: 'src/index.ts', status: 'M', insertions: 1, deletions: 1, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'secret-looking-path'));
  });

  it('flags lockfile deletion', () => {
    const hints = analyzeRisks([
      {
        path: 'package-lock.json',
        status: 'D',
        insertions: 0,
        deletions: 900,
        binary: false,
      },
    ]);
    assert.ok(hints.some((h) => h.code === 'lockfile-deletion'));
  });

  it('flags CI workflow deletion', () => {
    const hints = analyzeRisks([
      {
        path: '.github/workflows/ci.yml',
        status: 'D',
        insertions: 0,
        deletions: 40,
        binary: false,
      },
    ]);
    assert.ok(hints.some((h) => h.code === 'ci-deletion' && h.severity === 'high'));
  });

  it('flags binary changes', () => {
    const hints = analyzeRisks([
      { path: 'assets/logo.png', status: 'A', insertions: 0, deletions: 0, binary: true },
    ]);
    assert.ok(hints.some((h) => h.code === 'binary-change'));
  });

  it('flags dependency manifest and auth paths', () => {
    const hints = analyzeRisks([
      { path: 'package.json', status: 'M', insertions: 2, deletions: 1, binary: false },
      { path: 'Cargo.toml', status: 'M', insertions: 1, deletions: 0, binary: false },
      { path: 'src/auth/login.ts', status: 'M', insertions: 5, deletions: 2, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'package-json-change'));
    assert.ok(hints.some((h) => h.code === 'dependency-manifest'));
    assert.ok(hints.some((h) => h.code === 'auth-path'));
  });

  it('flags large file diffs', () => {
    const hints = analyzeRisks([
      { path: 'big.ts', status: 'M', insertions: 300, deletions: 200, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'large-file-diff'));
  });

  it('flags broad change sets', () => {
    const files = Array.from({ length: 25 }, (_, i) => ({
      path: `f${i}.ts`,
      status: 'M',
      insertions: 1,
      deletions: 0,
      binary: false,
    }));
    const hints = analyzeRisks(files);
    assert.ok(hints.some((h) => h.code === 'broad-change'));
  });

  it('returns empty for clean text changes', () => {
    const hints = analyzeRisks([
      { path: 'README.md', status: 'M', insertions: 2, deletions: 1, binary: false },
    ]);
    assert.equal(hints.length, 0);
  });

  it('summarizeRisks rolls up severities', () => {
    const hints = analyzeRisks([
      { path: '.env', status: 'A', insertions: 1, deletions: 0, binary: false },
      { path: 'package.json', status: 'M', insertions: 1, deletions: 0, binary: false },
    ]);
    const sum = summarizeRisks(hints);
    assert.ok(sum.high >= 1);
    assert.ok(sum.total >= 2);
    assert.equal(sum.maxSeverity, 'high');
  });
});
