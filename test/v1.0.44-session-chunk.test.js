/**
 * v1.0.44 — human session tree is written in chunks.
 * A large tree must not join every line into one string.
 * Small trees keep the previous line shape. --json stays one object.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendHashFooter } from '../dist/lib/hash.js';
import {
  SESSION_TREE_CHUNK_BYTES,
  SESSION_TREE_EMBED_MAX_BYTES,
  formatSessionTree,
  writeSessionTree,
} from '../dist/lib/link.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];

after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function keep(dir) {
  dirs.push(dir);
  return dir;
}

function cli(cwd, args) {
  const r = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: 20000,
  });
  return { code: r.status === null ? 1 : r.status, out: r.stdout || '', err: r.stderr || '' };
}

/** Minimal 1.0.28 writer header so the session scanner accepts the receipt. */
function linkEraBody(fieldLines) {
  const fields = {};
  for (const line of fieldLines) {
    const match = line.match(/^- \*\*([^*]+)\*\*: (.*)$/);
    if (match) fields[match[1]] = match[2];
  }
  const timestamp = fields.Timestamp || '2026-10-13T00:00:00.000Z';
  const lines = [
    '# Agent Receipt',
    '',
    `> **TL;DR** ci · ${timestamp} · main @ abcdef012345 · 0 files · +0/\u22120 · risk none`,
    '',
    '## What to review',
    '',
    '_Nothing flagged. Skim the file list if this session should have been a no-op._',
    '',
    '## Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    '| Files | 0 |',
    '| Lines | +0 / \u22120 |',
    '| Commits | 0 |',
    '| Risk | none |',
    '',
    '## Session',
    '',
    '- **Version**: 1.0.28',
    `- **Timestamp**: ${timestamp}`,
    '- **Branch**: `main`',
    '- **HEAD**: `abcdef0123456789abcdef0123456789abcdef01`',
    '- **Range**: `HEAD~0..HEAD` (`abcdef012345` \u2192 HEAD)',
  ];
  for (const label of ['Id', 'Agent', 'Session', 'Parent', 'Host']) {
    if (fields[label]) lines.push(`- **${label}**: ${fields[label]}`);
  }
  lines.push('- **Workspace**: `/tmp`', '', '## Files changed', '', '_No file changes in range._', '');
  return lines.join('\n');
}

function seal(body) {
  return appendHashFooter(body.endsWith('\n') ? body : `${body}\n`);
}

function receipt(partial) {
  return {
    parent: null,
    agent: 'parent',
    verified: true,
    exitCode: 0,
    orphan: false,
    cycle: false,
    warnings: [],
    timestamp: '2026-10-13T00:00:00.000Z',
    status: 'pass',
    path: '/no/such/receipt.md',
    ...partial,
  };
}

const PARENT_SHA = 'ab'.repeat(32);

function smallTree() {
  const nodes = [
    receipt({ id: 'r-aaaaaaaaaaaaaaaa', agent: 'parent' }),
    receipt({
      id: 'r-bbbbbbbbbbbbbbbb',
      parent: PARENT_SHA,
      agent: 'child',
      verified: false,
      exitCode: 2,
      status: 'fail',
      warnings: ['parent-unverified'],
      timestamp: '2026-10-13T00:00:01.000Z',
    }),
    receipt({
      id: 'r-cccccccccccccccc',
      parent: 'r-0000000000000000',
      agent: null,
      orphan: true,
      cycle: true,
      timestamp: null,
    }),
  ];
  const aliasToId = new Map([
    ['r-aaaaaaaaaaaaaaaa', 'r-aaaaaaaaaaaaaaaa'],
    [PARENT_SHA, 'r-aaaaaaaaaaaaaaaa'],
    ['r-bbbbbbbbbbbbbbbb', 'r-bbbbbbbbbbbbbbbb'],
    ['r-cccccccccccccccc', 'r-cccccccccccccccc'],
  ]);
  const provenance = new Map([
    [
      'r-aaaaaaaaaaaaaaaa',
      { originalFingerprint: 'aa', resignedBy: 'bb', signedBy: 'cc' },
    ],
  ]);
  const text = [
    'session demo-sess',
    '3 receipt(s)',
    '',
    '- r-aaaaaaaaaaaaaaaa  pass  exit 0  agent=parent  2026-10-13T00:00:00.000Z  verified  originalFingerprint=aa  resignedBy=bb  signedBy=cc',
    '  - r-bbbbbbbbbbbbbbbb  fail  exit 2  agent=child  2026-10-13T00:00:01.000Z  unverified  warnings=parent-unverified',
    '- r-cccccccccccccccc  pass  exit 0  agent=(none)  (no timestamp)  verified  orphan  cycle',
  ].join('\n');
  return { nodes, aliasToId, provenance, text };
}

describe('v1.0.44 chunked session tree', () => {
  it('keeps the small parent/child shape, including indent, exit, orphan, and cycle', () => {
    const { nodes, aliasToId, provenance, text } = smallTree();
    assert.equal(formatSessionTree('demo-sess', nodes, aliasToId, provenance), text);
    assert.equal(
      formatSessionTree('demo-sess', nodes, aliasToId, provenance, SESSION_TREE_EMBED_MAX_BYTES),
      text,
    );
    assert.equal(text.includes('session tree truncated'), false);

    const chunks = [];
    writeSessionTree('demo-sess', nodes, aliasToId, provenance, (chunk) => chunks.push(chunk), 2);
    assert.ok(chunks.length > 1);
    assert.equal(chunks.join(''), `${text}\n`);
    for (const chunk of chunks) {
      assert.ok(chunk.length < text.length);
      assert.equal(chunk.endsWith('\n'), true);
    }
  });

  it('caps the report embed instead of throwing, and leaves a small tree unchanged', () => {
    const { nodes, aliasToId, provenance } = smallTree();
    const capped = formatSessionTree('demo-sess', nodes, aliasToId, provenance, 80);
    assert.equal(
      capped,
      [
        'session demo-sess',
        '3 receipt(s)',
        '',
        'session tree truncated: 3 more line(s) omitted (cap 80 bytes)',
      ].join('\n'),
    );
    assert.ok(capped.length < 80 + 80);
  });

  it('streams a wide tree of 50000 nodes without one full-tree write', () => {
    const count = 50000;
    const nodes = new Array(count);
    for (let i = 0; i < count; i += 1) {
      nodes[i] = receipt({
        id: `r-${i.toString(16).padStart(16, '0')}`,
        agent: 'ci',
      });
    }
    const first = nodes[0].id;
    const last = nodes[count - 1].id;
    let writes = 0;
    let max = 0;
    let total = 0;
    let sawFirst = false;
    let sawLast = false;
    let bothInOne = false;
    writeSessionTree('big', nodes, undefined, undefined, (chunk) => {
      writes += 1;
      if (chunk.length > max) max = chunk.length;
      total += chunk.length;
      const hasFirst = chunk.includes(first);
      const hasLast = chunk.includes(last);
      if (hasFirst) sawFirst = true;
      if (hasLast) sawLast = true;
      if (hasFirst && hasLast) bothInOne = true;
    });
    assert.equal(bothInOne, false);
    assert.equal(sawFirst, true);
    assert.equal(sawLast, true);
    assert.ok(writes > 1);
    assert.ok(max < total);
    assert.ok(max <= SESSION_TREE_CHUNK_BYTES);
    assert.equal(writes, Math.ceil((count + 3) / 64));
  });

  it('streams a deep chain whose text is larger than one string', { timeout: 180000 }, () => {
    const depth = 18000;
    const nodes = new Array(depth);
    for (let i = 0; i < depth; i += 1) {
      const id = `r-${i.toString(16).padStart(16, '0')}`;
      nodes[i] = receipt({
        id,
        parent: i === 0 ? null : `r-${(i - 1).toString(16).padStart(16, '0')}`,
        agent: 'ci',
        timestamp: `2026-10-13T00:00:${String(i % 60).padStart(2, '0')}.000Z`,
      });
    }
    let writes = 0;
    let max = 0;
    let total = 0;
    writeSessionTree('deep', nodes, undefined, undefined, (chunk) => {
      writes += 1;
      if (chunk.length > max) max = chunk.length;
      total += chunk.length;
    });
    assert.ok(writes > 1);
    assert.ok(total > 256 * 1024 * 1024);
    assert.ok(max < 256 * 1024);
    assert.ok(max * 8 < total);

    const embedded = formatSessionTree('deep', nodes);
    assert.match(embedded, /^session deep\n18000 receipt\(s\)\n/);
    assert.match(embedded, /session tree truncated: \d+ more line\(s\) omitted/);
    assert.ok(embedded.length < SESSION_TREE_EMBED_MAX_BYTES + 200);
    assert.equal(embedded.includes(nodes[depth - 1].id), false);
  });

  it('prints the same small tree from the CLI and keeps --json as one object', () => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'agent-receipt-1044-')));
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    const rows = [
      {
        file: 'parent.md',
        fields: [
          '- **Id**: r-aaaaaaaaaaaaaaaa',
          '- **Timestamp**: 2026-10-13T00:00:00.000Z',
          '- **Agent**: parent',
          '- **Session**: sess-chunk',
        ],
      },
      {
        file: 'child.md',
        fields: [
          '- **Id**: r-bbbbbbbbbbbbbbbb',
          '- **Timestamp**: 2026-10-13T00:00:01.000Z',
          '- **Agent**: child',
          '- **Session**: sess-chunk',
          '- **Parent**: r-aaaaaaaaaaaaaaaa',
        ],
      },
      {
        file: 'orphan.md',
        fields: [
          '- **Id**: r-cccccccccccccccc',
          '- **Timestamp**: 2026-10-13T00:00:02.000Z',
          '- **Agent**: lonely',
          '- **Session**: sess-chunk',
          '- **Parent**: r-0000000000000000',
        ],
      },
    ];
    for (const row of rows) {
      writeFileSync(join(outDir, row.file), seal(linkEraBody(row.fields)));
    }

    const human = cli(dir, ['session', 'sess-chunk']);
    assert.equal(human.code, 0, human.err);
    assert.equal(
      human.out,
      [
        'session sess-chunk',
        '3 receipt(s)',
        '',
        '- r-aaaaaaaaaaaaaaaa  pass  exit 0  agent=parent  2026-10-13T00:00:00.000Z  verified',
        '  - r-bbbbbbbbbbbbbbbb  pass  exit 0  agent=child  2026-10-13T00:00:01.000Z  verified',
        '- r-cccccccccccccccc  pass  exit 0  agent=lonely  2026-10-13T00:00:02.000Z  verified  orphan',
        '',
      ].join('\n'),
    );

    const json = cli(dir, ['session', 'sess-chunk', '--json']);
    assert.equal(json.code, 0, json.err);
    const jsonLines = json.out.split('\n').filter((line) => line.length > 0);
    assert.equal(jsonLines.length, 1);
    const body = JSON.parse(jsonLines[0]);
    assert.equal(body.command, 'session');
    assert.equal(body.version, '1.0.55');
    assert.equal(body.ok, true);
    assert.equal(body.exitCode, 0);
    assert.equal(body.receipts.length, 3);
    const child = body.receipts.find((row) => row.id === 'r-bbbbbbbbbbbbbbbb');
    const orphan = body.receipts.find((row) => row.id === 'r-cccccccccccccccc');
    assert.equal(child.parent, 'r-aaaaaaaaaaaaaaaa');
    assert.equal(child.exitCode, 0);
    assert.equal(orphan.orphan, true);
    assert.equal(orphan.cycle, false);
    assert.equal(json.out.includes('\n{'), false);
  });

  it('wires the human command to the chunk writer, not one joined string', () => {
    const src = readFileSync(join(root, 'src', 'commands', 'session.ts'), 'utf8');
    assert.match(src, /writeSessionTree\(/);
    assert.doesNotMatch(src, /formatSessionTree/);
    assert.match(src, /console\.log\(JSON\.stringify\(report\)\)/);
    const report = readFileSync(join(root, 'src', 'commands', 'report.ts'), 'utf8');
    assert.match(report, /formatSessionTree\(/);
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.44\]/);
    assert.doesNotMatch(changelog, /Chunked output is left for a later cut/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.55');
    assert.equal(pkg.dependencies, undefined);
  });
});
