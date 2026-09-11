import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRisks } from '../dist/lib/risk.js';

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

  it('returns empty for clean text changes', () => {
    const hints = analyzeRisks([
      { path: 'README.md', status: 'M', insertions: 2, deletions: 1, binary: false },
    ]);
    assert.equal(hints.length, 0);
  });
});
