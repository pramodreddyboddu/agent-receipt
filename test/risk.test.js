import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeRisks,
  summarizeRisks,
  parseFailOn,
  meetsFailOn,
  sortRisks,
} from '../dist/lib/risk.js';

describe('analyzeRisks', () => {
  it('flags .env commits as high env-file', () => {
    const hints = analyzeRisks([
      { path: '.env', status: 'A', insertions: 3, deletions: 0, binary: false },
      { path: 'src/index.ts', status: 'M', insertions: 1, deletions: 1, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'env-file' && h.severity === 'high'));
  });

  it('treats .env.example as low env-template, not high', () => {
    const hints = analyzeRisks([
      { path: '.env.example', status: 'A', insertions: 4, deletions: 0, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'env-template' && h.severity === 'low'));
    assert.ok(!hints.some((h) => h.code === 'env-file'));
  });

  it('does not flag auth source paths (false-positive trim)', () => {
    const hints = analyzeRisks([
      { path: 'src/auth/login.ts', status: 'M', insertions: 5, deletions: 2, binary: false },
      { path: 'lib/session.ts', status: 'M', insertions: 1, deletions: 0, binary: false },
    ]);
    assert.ok(!hints.some((h) => h.code === 'auth-path' || h.code === 'auth-secret-file'));
    assert.equal(hints.length, 0);
  });

  it('flags secret-store filenames, not source', () => {
    const hints = analyzeRisks([
      { path: 'config/tokens.json', status: 'A', insertions: 2, deletions: 0, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'auth-secret-file'));
  });

  it('does not flag id_rsa.pub as a private key', () => {
    const hints = analyzeRisks([
      { path: 'id_rsa.pub', status: 'A', insertions: 1, deletions: 0, binary: false },
    ]);
    assert.ok(!hints.some((h) => h.code === 'secret-looking-path'));
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

  it('flags non-media binary as medium; images as low', () => {
    const bin = analyzeRisks([
      { path: 'vendor/tool.bin', status: 'A', insertions: 0, deletions: 0, binary: true },
    ]);
    assert.ok(bin.some((h) => h.code === 'binary-change' && h.severity === 'medium'));
    const img = analyzeRisks([
      { path: 'assets/logo.png', status: 'A', insertions: 0, deletions: 0, binary: true },
    ]);
    assert.ok(img.some((h) => h.code === 'binary-change' && h.severity === 'low'));
  });

  it('flags dependency manifest and package.json', () => {
    const hints = analyzeRisks([
      { path: 'package.json', status: 'M', insertions: 2, deletions: 1, binary: false },
      { path: 'Cargo.toml', status: 'M', insertions: 1, deletions: 0, binary: false },
    ]);
    assert.ok(hints.some((h) => h.code === 'package-json-change'));
    assert.ok(hints.some((h) => h.code === 'dependency-manifest'));
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

  it('flags AWS access key ids in diffs', () => {
    const files = [
      { path: 'src/config.ts', status: 'M', insertions: 2, deletions: 0, binary: false },
    ];
    const diffs = {
      'src/config.ts':
        '+const k = "AKIAIOSFODNN7EXAMPLE";\n',
    };
    const hints = analyzeRisks(files, diffs);
    assert.ok(hints.some((h) => h.code === 'aws-access-key' && h.severity === 'high'));
  });

  it('flags private key blocks in diffs', () => {
    const files = [
      { path: 'oops.pem', status: 'A', insertions: 4, deletions: 0, binary: false },
    ];
    const diffs = {
      'oops.pem':
        '-----BEGIN OPENSSH PRIVATE KEY-----\n' +
        'fake-not-a-real-key\n' +
        '-----END OPENSSH PRIVATE KEY-----\n',
    };
    const hints = analyzeRisks(files, diffs);
    assert.ok(hints.some((h) => h.code === 'private-key-block' && h.severity === 'high'));
  });

  it('sorts high before medium before low', () => {
    const hints = analyzeRisks([
      { path: '.env', status: 'A', insertions: 1, deletions: 0, binary: false },
      { path: 'package.json', status: 'M', insertions: 1, deletions: 0, binary: false },
      { path: 'yarn.lock', status: 'M', insertions: 2, deletions: 1, binary: false },
    ]);
    const sorted = sortRisks(hints);
    const ranks = { high: 0, medium: 1, low: 2 };
    for (let i = 1; i < sorted.length; i++) {
      assert.ok(ranks[sorted[i - 1].severity] <= ranks[sorted[i].severity]);
    }
    assert.equal(sorted[0].severity, 'high');
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

describe('fail-on helpers', () => {
  it('parseFailOn: bare true is high; rejects junk', () => {
    assert.equal(parseFailOn(true), 'high');
    assert.equal(parseFailOn('high'), 'high');
    assert.equal(parseFailOn('medium'), 'medium');
    assert.equal(parseFailOn('LOW'), 'low');
    assert.equal(parseFailOn(undefined), undefined);
    assert.throws(() => parseFailOn('nope'), /fail-on/);
  });

  it('meetsFailOn ranks high > medium > low', () => {
    assert.equal(meetsFailOn('high', 'high'), true);
    assert.equal(meetsFailOn('medium', 'high'), false);
    assert.equal(meetsFailOn('medium', 'medium'), true);
    assert.equal(meetsFailOn('high', 'medium'), true);
    assert.equal(meetsFailOn(null, 'high'), false);
    assert.equal(meetsFailOn('low', 'low'), true);
    assert.equal(meetsFailOn('low', 'high'), false);
  });
});
