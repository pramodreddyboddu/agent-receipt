import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  redactSecretsInText,
  redactMarkdownBody,
  prepareRedactedBody,
} from '../dist/lib/redact.js';
import { markdownToHtml } from '../dist/lib/html.js';
import { appendHashFooter, verifyMarkdown } from '../dist/lib/hash.js';
import { countCommitsAhead, resolveRange } from '../dist/lib/git.js';

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

describe('redact helpers', () => {
  it('masks AWS / GitHub / Slack / PEM secrets', () => {
    const sample = [
      'key=AKIAIOSFODNN7EXAMPLE',
      'tok=ghp_abcdefghijklmnopqrstuvwxyz0123456789',
      'slack=xoxb-1234567890-abcdefghij',
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA',
      '-----END RSA PRIVATE KEY-----',
      'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    ].join('\n');
    const out = redactSecretsInText(sample);
    assert.match(out, /AKIA\[REDACTED\]/);
    assert.match(out, /ghp_\[REDACTED\]/);
    assert.match(out, /xox\[REDACTED\]/);
    assert.match(out, /\[REDACTED\]/);
    assert.doesNotMatch(out, /AKIAIOSFODNN7EXAMPLE/);
    assert.doesNotMatch(out, /ghp_abcdefghijklmnopqrstuvwxyz0123456789/);
  });

  it('redactMarkdownBody injects notice and still re-hashes cleanly', () => {
    const body = appendHashFooter(`# Agent Receipt

> **TL;DR** bot · demo

## Session

- **Agent**: bot

## Risk findings

| Sev | Code | Detail |
|-----|------|--------|
| high | \`aws-access-key\` | Found AKIAIOSFODNN7EXAMPLE in diff |

## Diff summaries

### \`a.js\`

\`\`\`diff
+ const k = 'AKIAIOSFODNN7EXAMPLE';
\`\`\`
`);
    const redacted = appendHashFooter(prepareRedactedBody(body));
    assert.match(redacted, /Redacted/);
    assert.match(redacted, /\[REDACTED/);
    assert.doesNotMatch(redacted, /AKIAIOSFODNN7EXAMPLE/);
    const v = verifyMarkdown(redacted);
    assert.equal(v.ok, true);
  });

  it('markdownToHtml produces self-contained document', () => {
    const md = appendHashFooter(`# Agent Receipt

> **TL;DR** demo

## Summary

| Metric | Value |
|--------|-------|
| Files | 1 |

- item one
`);
    const html = markdownToHtml(md, { title: 'Demo' });
    assert.match(html, /<!DOCTYPE html>/);
    assert.match(html, /<style>/);
    assert.match(html, /Agent Receipt/);
    assert.match(html, /Integrity SHA-256/);
    assert.doesNotMatch(html, /https?:\/\/.*\.css/);
  });
});

describe('wrap + export + base + redact CLI', () => {
  let dir;
  let mainSha;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-v06-'));
    git(dir, ['init', '-b', 'main']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# v06\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    mainSha = git(dir, ['rev-parse', 'HEAD']);
    cli(dir, ['init']);

    // feature branch with 2 commits ahead of main
    git(dir, ['checkout', '-b', 'feat/demo']);
    writeFileSync(join(dir, 'app.js'), 'console.log("a")\n');
    git(dir, ['add', 'app.js']);
    git(dir, ['commit', '-m', 'add app']);
    writeFileSync(join(dir, 'app.js'), 'console.log("b")\n');
    git(dir, ['add', 'app.js']);
    git(dir, ['commit', '-m', 'tweak app']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('version is 1.0.12', () => {
    const out = cli(dir, ['version']);
    assert.match(out, /1\.0\.12/);
  });

  it('help lists wrap and export', () => {
    const out = cli(dir, ['help']);
    assert.match(out, /\bwrap\b/);
    assert.match(out, /\bexport\b/);
    assert.match(out, /\bhtml\b/);
    const w = cli(dir, ['help', 'wrap']);
    assert.match(w, /end-of-session/);
    assert.match(w, /--fail-on/);
  });

  it('resolveRange --base reports commits ahead', () => {
    const ahead = countCommitsAhead(dir, 'main');
    assert.equal(ahead, 2);
    const range = resolveRange(dir, { base: 'main' });
    assert.match(range.label, /2 commits ahead of main/);
    assert.equal(range.commitsAhead, 2);
  });

  it('capture --base main shows commits ahead + files', () => {
    const out = cli(dir, [
      'capture',
      '--base',
      'main',
      '--agent',
      'base-bot',
      '--message',
      'vs main',
      '--out',
      'base-receipt.md',
    ]);
    assert.match(out, /Wrote receipt/);
    assert.match(out, /2 commit\(s\) ahead of main/);
    const md = readFileSync(join(dir, 'base-receipt.md'), 'utf8');
    assert.match(md, /2 commits ahead of main/);
    assert.match(md, /app\.js/);
    assert.match(md, /add app|tweak app/);
    const v = cli(dir, ['verify', 'base-receipt.md']);
    assert.match(v, /OK/);
  });

  it('wrap on clean tree captures and verifies', () => {
    const out = cli(dir, [
      'wrap',
      '--agent',
      'wrap-bot',
      '--message',
      'clean wrap',
      '--base',
      'main',
    ]);
    assert.match(out, /TL;DR/);
    assert.match(out, /path/);
    assert.match(out, /Wrote receipt/);
    assert.match(out, /OK — receipt integrity verified/);
    assert.match(out, /wrap-bot|clean wrap|commits ahead/);
  });

  it('wrap on dirty tree uses --uncommitted', () => {
    writeFileSync(join(dir, 'wip.txt'), 'dirty\n');
    const out = cli(dir, [
      'wrap',
      '--agent',
      'dirty-wrap',
      '--message',
      'dirty session',
    ]);
    assert.match(out, /uncommitted/);
    assert.match(out, /TL;DR/);
    assert.match(out, /OK — receipt integrity verified/);
    // clean up for later tests
    rmSync(join(dir, 'wip.txt'));
  });

  it('export / html writes self-contained HTML', () => {
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'html-bot',
      '--message',
      'for html',
    ]);
    const out = cli(dir, ['html', '--out', 'share.html']);
    assert.match(out, /Wrote html/);
    assert.ok(existsSync(join(dir, 'share.html')));
    const html = readFileSync(join(dir, 'share.html'), 'utf8');
    assert.match(html, /<!DOCTYPE html>/);
    assert.match(html, /<style>/);
    assert.match(html, /Agent Receipt/);
  });

  it('export --redact masks secrets and verify still works on md export', () => {
    writeFileSync(
      join(dir, 'leak.js'),
      "const k = 'AKIAIOSFODNN7EXAMPLE';\n",
    );
    git(dir, ['add', 'leak.js']);
    git(dir, ['commit', '-m', 'oops key']);

    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'secret-bot',
      '--message',
      'has secret',
      '--out',
      'secret.md',
    ]);
    const raw = readFileSync(join(dir, 'secret.md'), 'utf8');
    assert.match(raw, /AKIAIOSFODNN7EXAMPLE/);

    const out = cli(dir, [
      'export',
      'secret.md',
      '--format',
      'markdown',
      '--redact',
      '--out',
      'secret.redacted.md',
    ]);
    assert.match(out, /Wrote markdown/);
    assert.match(out, /Redacted/);
    const red = readFileSync(join(dir, 'secret.redacted.md'), 'utf8');
    assert.doesNotMatch(red, /AKIAIOSFODNN7EXAMPLE/);
    assert.match(red, /REDACTED/);
    const v = cli(dir, ['verify', 'secret.redacted.md']);
    assert.match(v, /OK/);

    const htmlOut = cli(dir, [
      'export',
      'secret.md',
      '--redact',
      '--out',
      'secret.html',
    ]);
    assert.match(htmlOut, /Wrote html/);
    const html = readFileSync(join(dir, 'secret.html'), 'utf8');
    assert.doesNotMatch(html, /AKIAIOSFODNN7EXAMPLE/);
    assert.match(html, /Redacted|REDACTED/i);
  });

  it('capture --redact writes masked receipt that verifies', () => {
    const out = cli(dir, [
      'capture',
      '--commits',
      '1',
      '--redact',
      '--agent',
      'redact-bot',
      '--out',
      'cap-redact.md',
    ]);
    assert.match(out, /redacted/i);
    const md = readFileSync(join(dir, 'cap-redact.md'), 'utf8');
    assert.match(md, /Redacted/);
    assert.doesNotMatch(md, /AKIAIOSFODNN7EXAMPLE/);
    const v = cli(dir, ['verify', 'cap-redact.md']);
    assert.match(v, /OK/);
  });

  it('wrap --fail-on high exits 2 when secrets present', () => {
    // --base forces commit-range wrap even if untracked receipt files dirty the tree
    const r = cliStatus(dir, [
      'wrap',
      '--agent',
      'fail-bot',
      '--message',
      'should fail',
      '--base',
      'main',
      '--fail-on',
      'high',
    ]);
    assert.equal(r.code, 2, `${r.out}\n${r.err}`);
    assert.match(r.out + r.err, /fail-on|Wrote receipt/i);
  });
});
