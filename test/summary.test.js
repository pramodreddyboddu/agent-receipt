import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  summarizeNotableChanges,
  formatDiffStatTable,
} from '../dist/lib/summary.js';
import { formatMarkdown } from '../dist/lib/receipt.js';

describe('summary + risk table', () => {
  it('summarizes package / lockfile / workflow changes', () => {
    const notable = summarizeNotableChanges([
      { path: 'package.json', status: 'M', insertions: 3, deletions: 1, binary: false },
      { path: 'package-lock.json', status: 'M', insertions: 10, deletions: 2, binary: false },
      {
        path: '.github/workflows/ci.yml',
        status: 'A',
        insertions: 20,
        deletions: 0,
        binary: false,
      },
      { path: 'src/a.ts', status: 'M', insertions: 1, deletions: 1, binary: false },
    ]);
    assert.equal(notable.length, 3);
    assert.ok(notable.some((n) => n.kind === 'package'));
    assert.ok(notable.some((n) => n.kind === 'lockfile'));
    assert.ok(notable.some((n) => n.kind === 'workflow'));
  });

  it('formats a diff-stat style overview', () => {
    const lines = formatDiffStatTable([
      { path: 'a.ts', status: 'M', insertions: 3, deletions: 1, binary: false },
      { path: 'b.bin', status: 'A', insertions: 0, deletions: 0, binary: true },
    ]);
    const text = lines.join('\n');
    assert.match(text, /a\.ts/);
    assert.match(text, /2 files changed/);
    assert.match(text, /Bin/);
  });

  it('markdown includes risk table and notable section', () => {
    const md = formatMarkdown(
      {
        version: '0.2.0',
        timestamp: '2026-09-11T00:00:00.000Z',
        branch: 'main',
        head: 'abc',
        remote: null,
        rangeLabel: 'HEAD~1..HEAD',
        base: 'def',
        files: [
          {
            path: 'package.json',
            status: 'M',
            insertions: 2,
            deletions: 0,
            binary: false,
          },
        ],
        commits: [],
        diffs: {},
        risks: [
          {
            severity: 'medium',
            code: 'package-json-change',
            message: 'package.json changed: package.json (+2/-0)',
            path: 'package.json',
          },
        ],
        cwd: '/tmp/x',
      },
      { full: false, diffStat: true, topRisks: 10 },
    );
    assert.match(md, /> \*\*TL;DR\*\*/);
    assert.match(md, /## What to review/);
    assert.match(md, /## Notable changes/);
    assert.match(md, /## Diff stat/);
    assert.match(md, /## Risk findings/);
    assert.match(md, /package-json-change/);
    assert.match(md, /\| Sev \|/);
  });
});
