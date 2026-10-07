/**
 * v1.0.40 OTLP/JSON trace export.
 * File only. The receipt hash is checked before the write.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spanIdFor, traceIdFor } from '../dist/lib/otlp.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const AKIA = 'AKIAIOSFODNN7EXAMPLE';

after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function keep(dir) {
  dirs.push(dir);
  return dir;
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args) {
  const result = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { code: result.status ?? 1, out: result.stdout || '', err: result.stderr || '' };
}

function gitRepo() {
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1040-')));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# otlp\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  git(dir, ['remote', 'add', 'origin', 'https://github.com/example/repo.git']);
  assert.equal(cli(dir, ['init']).code, 0);
  return dir;
}

function parseJson(result) {
  assert.equal(result.code, 0, result.err + result.out);
  return JSON.parse(result.out);
}

function attr(span, key) {
  return span.attributes.find((item) => item.key === key);
}

function loadTrace(file) {
  const text = readFileSync(file, 'utf8');
  assert.equal(text.endsWith('\n'), true);
  const doc = JSON.parse(text);
  const spans = doc.resourceSpans[0].scopeSpans[0].spans;
  return { text, doc, spans };
}

function resourceAttr(doc, key) {
  return doc.resourceSpans[0].resource.attributes.find((item) => item.key === key);
}

describe('v1.0.40 OTLP export', () => {
  it('locks span ids to sha256(receiptSha:index)', () => {
    const sha = 'ab'.repeat(32);
    const id = createHash('sha256').update(`${sha}:0`).digest('hex').slice(0, 16);
    assert.equal(spanIdFor(sha, 0), id);
    assert.equal(traceIdFor(sha), sha.slice(0, 32));
    assert.match(id, /^[0-9a-f]{16}$/);
  });

  it('writes a redacted deterministic trace and rejects a bad format', () => {
    const dir = gitRepo();
    const transcript = join(dir, 'session.jsonl');
    writeFileSync(
      transcript,
      [
        JSON.stringify({
          type: 'assistant',
          message: {
            content: [{ type: 'tool_use', id: 'tu1', name: 'Bash', input: { command: `echo ${AKIA}` } }],
          },
        }),
        JSON.stringify({
          type: 'user',
          message: { content: [{ type: 'tool_result', tool_use_id: 'tu1', is_error: false }] },
        }),
        JSON.stringify({
          type: 'assistant',
          message: {
            content: [{ type: 'tool_use', id: 'tu2', name: 'Bash', input: { command: 'false' } }],
          },
        }),
        JSON.stringify({
          type: 'user',
          message: { content: [{ type: 'tool_result', tool_use_id: 'tu2', exit_code: 1 }] },
        }),
        JSON.stringify({
          type: 'assistant',
          message: {
            content: [{
              type: 'tool_use',
              id: 'tu3',
              name: 'mcp__github__create_issue',
              input: { title: 'hi' },
            }],
          },
        }),
        JSON.stringify({
          type: 'user',
          message: { content: [{ type: 'tool_result', tool_use_id: 'tu3', is_error: false }] },
        }),
      ].join('\n') + '\n',
    );
    const captured = parseJson(cli(dir, [
      'capture',
      '--json',
      '--commits',
      '1',
      '--agent',
      'cursor',
      '--adapter',
      'claude-code',
      '--transcript',
      transcript,
      '--host',
      AKIA,
    ]));
    assert.match(captured.sha256, /^[0-9a-f]{64}$/);
    const auditPath = join(dir, '.agent-receipt', 'audit.jsonl');
    const auditBefore = readFileSync(auditPath, 'utf8');

    const out = join(dir, 'trace.otlp.json');
    const again = join(dir, 'trace-again.otlp.json');
    const first = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', out]);
    assert.equal(first.code, 0, first.err + first.out);
    const second = cli(dir, ['export', '--format', 'otel', 'last', '--out', again]);
    assert.equal(second.code, 0, second.err + second.out);
    const upper = join(dir, 'trace-upper.otlp.json');
    const third = cli(dir, ['export', '--format', 'OTLP', captured.path, '--out', upper]);
    assert.equal(third.code, 0, third.err + third.out);
    const bytes = readFileSync(out);
    assert.deepEqual(bytes, readFileSync(again));
    assert.deepEqual(bytes, readFileSync(upper));
    const repeat = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', out]);
    assert.equal(repeat.code, 0, repeat.err + repeat.out);
    assert.deepEqual(bytes, readFileSync(out));
    assert.equal(readFileSync(auditPath, 'utf8'), auditBefore);

    const sibling = captured.path.replace(/\.md$/i, '.otlp.json');
    const bare = cli(dir, ['export', '--format', 'otlp', 'last']);
    assert.equal(bare.code, 0, bare.err + bare.out);
    assert.equal(existsSync(sibling), true);
    assert.deepEqual(readFileSync(sibling), bytes);

    const { text, doc, spans } = loadTrace(out);
    assert.equal(doc.resourceSpans.length, 1);
    assert.equal(doc.resourceSpans[0].scopeSpans.length, 1);
    assert.equal(doc.resourceSpans[0].scopeSpans[0].scope.name, 'agent-receipt');
    assert.equal(doc.resourceSpans[0].scopeSpans[0].scope.version, '1.0.40');
    assert.equal(resourceAttr(doc, 'service.name').value.stringValue, 'agent-receipt');
    assert.equal(resourceAttr(doc, 'service.version').value.stringValue, '1.0.40');
    assert.equal(resourceAttr(doc, 'host.name').value.stringValue, 'AKIA[REDACTED]');
    assert.equal(resourceAttr(doc, 'vcs.repository.url.full').value.stringValue, 'https://github.com/example/repo.git');
    assert.equal(text.includes(AKIA), false);
    assert.equal(text.includes('AKIA[REDACTED]'), true);
    assert.equal(first.out.includes(AKIA), false);

    const traceId = captured.sha256.slice(0, 32);
    assert.equal(traceIdFor(captured.sha256), traceId);
    assert.match(traceId, /^[0-9a-f]{32}$/);
    const root = spans.find((span) => span.name === 'agent.run');
    assert.ok(root);
    assert.equal(root.traceId, traceId);
    assert.equal(root.spanId, spanIdFor(captured.sha256, 0));
    assert.match(root.spanId, /^[0-9a-f]{16}$/);
    assert.equal(root.parentSpanId, '');
    assert.equal(root.kind, 'SPAN_KIND_INTERNAL');
    assert.equal(root.status.code, 'STATUS_CODE_OK');
    assert.equal(attr(root, 'agent_receipt.sha256').value.stringValue, captured.sha256);
    assert.equal(attr(root, 'agent_receipt.agent').value.stringValue, 'cursor');
    assert.equal(attr(root, 'gen_ai.agent.name').value.stringValue, 'cursor');
    assert.equal(attr(root, 'agent_receipt.adapter').value.stringValue, 'claude-code');
    assert.equal(attr(root, 'agent_receipt.signed').value.boolValue, false);
    assert.equal(attr(root, 'agent_receipt.index').value.intValue, '0');
    assert.match(attr(root, 'agent_receipt.risk').value.intValue, /^\d+$/);
    assert.match(attr(root, 'agent_receipt.hash_chain_position').value.intValue, /^[1-9]\d*$/);
    assert.equal(attr(root, 'host.name').value.stringValue, 'AKIA[REDACTED]');
    const stamp = readFileSync(captured.path, 'utf8').match(/^- \*\*Timestamp\*\*: (\S+)/m)[1];
    const nano = (BigInt(Date.parse(stamp)) * 1000000n).toString();
    assert.equal(root.startTimeUnixNano, nano);
    assert.equal(root.endTimeUnixNano, nano);

    for (const span of spans) {
      assert.equal(span.traceId, traceId);
      assert.match(span.spanId, /^[0-9a-f]{16}$/);
      assert.match(span.parentSpanId, /^$|^[0-9a-f]{16}$/);
      assert.match(span.startTimeUnixNano, /^\d+$/);
    }
    const children = spans.filter((span) => span.parentSpanId === root.spanId);
    assert.ok(children.length >= 3);
    for (const child of children) {
      assert.equal(child.startTimeUnixNano, root.startTimeUnixNano);
      assert.match(attr(child, 'agent_receipt.index').value.intValue, /^[1-9]\d*$/);
    }
    const failed = spans.find((span) => attr(span, 'process.command_line')?.value.stringValue === 'false');
    assert.ok(failed, spans.map((span) => span.name).join(','));
    assert.equal(failed.status.code, 'STATUS_CODE_ERROR');
    assert.match(failed.status.code, /ERROR/);
    assert.equal(attr(failed, 'agent_receipt.exit_code').value.intValue, '1');
    assert.equal(failed.spanId, spanIdFor(captured.sha256, Number(attr(failed, 'agent_receipt.index').value.intValue)));
    const mcp = spans.find((span) => span.name.includes('mcp:github/create_issue'));
    assert.ok(mcp);
    assert.equal(mcp.parentSpanId, root.spanId);
    assert.equal(attr(mcp, 'gen_ai.tool.name').value.stringValue.includes('mcp:github/create_issue'), true);

    const help = cli(dir, ['help', 'export']);
    assert.equal(help.code, 0, help.err);
    assert.match(help.out, /sidecar/);
    assert.match(help.out, /otlp/);
    assert.match(help.out, /always redacts/);
    assert.match(help.out, /--no-redact/);

    const blocked = join(dir, 'blocked.otlp.json');
    const noRedact = cli(dir, ['export', '--format', 'otlp', '--no-redact', '--out', blocked]);
    assert.equal(noRedact.code, 1);
    assert.equal(existsSync(blocked), false);
    assert.match(noRedact.err, /no-redact/);
    assert.match(noRedact.err, /always redacts/);

    const unknownOut = join(dir, 'unknown.html');
    const unknown = cli(dir, ['export', '--format', 'nope', '--out', unknownOut]);
    assert.equal(unknown.code, 1);
    assert.equal(existsSync(unknownOut), false);
    assert.match(unknown.err, /Unknown export format/);
    assert.equal(/<html/i.test(unknown.out), false);
  });

  it('exports a session tree and a session package as one trace', () => {
    const dir = gitRepo();
    const parent = parseJson(cli(dir, [
      'capture',
      '--json',
      '--commits',
      '1',
      '--agent',
      'cursor',
      '--session',
      's-otlp',
      '--host',
      'host-a',
    ]));
    const parentId = readFileSync(parent.path, 'utf8').match(/^- \*\*Id\*\*: (r-[0-9a-f]{16})\s*$/m)[1];
    writeFileSync(join(dir, 'second.txt'), 'second\n');
    git(dir, ['add', 'second.txt']);
    git(dir, ['commit', '-m', 'second']);
    const child = parseJson(cli(dir, [
      'capture',
      '--json',
      '--commits',
      '1',
      '--agent',
      'cursor',
      '--session',
      's-otlp',
      '--parent',
      parentId,
      '--host',
      'host-b',
    ]));
    const out = join(dir, 'session.otlp.json');
    const exported = cli(dir, ['export', '--format', 'otlp', '--session', 's-otlp', '--out', out]);
    assert.equal(exported.code, 0, exported.err + exported.out);
    const { doc, spans } = loadTrace(out);
    const runs = spans.filter((span) => span.name === 'agent.run');
    assert.equal(runs.length, 2);
    const root = runs.find((span) => span.spanId === spanIdFor(parent.sha256, 0));
    const nested = runs.find((span) => span.spanId === spanIdFor(child.sha256, 0));
    assert.ok(root);
    assert.ok(nested);
    assert.equal(root.parentSpanId, '');
    assert.equal(nested.parentSpanId, root.spanId);
    assert.equal(root.traceId, parent.sha256.slice(0, 32));
    assert.equal(nested.traceId, root.traceId);
    assert.notEqual(nested.traceId, child.sha256.slice(0, 32));
    assert.equal(resourceAttr(doc, 'host.name').value.stringValue, 'host-a');
    assert.equal(attr(root, 'host.name').value.stringValue, 'host-a');
    assert.equal(attr(nested, 'host.name').value.stringValue, 'host-b');
    for (const span of spans) assert.equal(span.traceId, root.traceId);

    const both = cli(dir, ['export', '--format', 'otlp', '--session', 's-otlp', parent.path, '--out', join(dir, 'both.otlp.json')]);
    assert.equal(both.code, 1);
    assert.equal(existsSync(join(dir, 'both.otlp.json')), false);
    assert.match(both.err, /--session does not take a path/);

    const packed = parseJson(cli(dir, ['session', 'export', 's-otlp', '--json']));
    assert.ok(packed.packagePath);
    const packedOut = join(dir, 'packed.otlp.json');
    const fromPackage = cli(dir, ['export', '--format', 'otlp', packed.packagePath, '--out', packedOut]);
    assert.equal(fromPackage.code, 0, fromPackage.err + fromPackage.out);
    const manifest = JSON.parse(readFileSync(join(packed.packagePath, 'session-manifest.json'), 'utf8'));
    const packagedRoot = manifest.receipts.find((row) => !row.parent);
    const packagedChild = manifest.receipts.find((row) => row.parent);
    assert.ok(packagedRoot);
    assert.ok(packagedChild);
    const packedTrace = loadTrace(packedOut);
    const packedRuns = packedTrace.spans.filter((span) => span.name === 'agent.run');
    const packedParent = packedRuns.find((span) => span.spanId === spanIdFor(packagedRoot.sha256, 0));
    const packedNested = packedRuns.find((span) => span.spanId === spanIdFor(packagedChild.sha256, 0));
    assert.ok(packedParent);
    assert.ok(packedNested);
    assert.equal(packedNested.parentSpanId, packedParent.spanId);
    assert.equal(packedParent.traceId, packagedRoot.sha256.slice(0, 32));
    assert.equal(packedNested.traceId, packedParent.traceId);
  });

  it('exits 2 on a tampered receipt and writes nothing', () => {
    const dir = gitRepo();
    const captured = parseJson(cli(dir, ['capture', '--json', '--commits', '1', '--agent', 'cursor']));
    let markdown = readFileSync(captured.path, 'utf8');
    const at = markdown.indexOf('## Integrity');
    assert.ok(at > 10);
    let index = at - 1;
    while (index > 0 && !/[A-Za-z]/.test(markdown[index])) index -= 1;
    const flipped = markdown[index] === 'a' ? 'b' : 'a';
    markdown = markdown.slice(0, index) + flipped + markdown.slice(index + 1);
    writeFileSync(captured.path, markdown);
    const out = join(dir, 'tampered.otlp.json');
    const result = cli(dir, ['export', '--format', 'otlp', captured.path, '--out', out]);
    assert.equal(result.code, 2);
    assert.match(result.err, /integrity|tamper|hash/i);
    assert.equal(existsSync(out), false);
    assert.equal(existsSync(captured.path.replace(/\.md$/i, '.otlp.json')), false);
    const names = readdirSync(dirname(captured.path));
    assert.equal(names.some((name) => name.includes('.tmp') || name.endsWith('.otlp.json')), false);
    assert.equal(result.out.includes('wrote'), false);
  });
});
