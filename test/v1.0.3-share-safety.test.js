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
  redactSecretsInText,
  redactMarkdownBody,
  prepareRedactedBody,
  isReceiptArtifactPath,
} from '../dist/lib/redact.js';
import { analyzeRisks } from '../dist/lib/risk.js';
import {
  appendHashFooter,
  verifyMarkdown,
  hasTrailingAfterIntegrity,
} from '../dist/lib/hash.js';
import { loadIndex, isInsideOutDir, updateIndexOnCapture } from '../dist/lib/receipt-index.js';

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

describe('redact: DATABASE_URL / credential URLs', () => {
  it('masks DATABASE_URL password while keeping API/AWS patterns', () => {
    const sample = [
      'API_KEY=sk_live_abcdefghijklmnopqrstuv',
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'DATABASE_URL=postgres://user:SuperSecretPass123!@host/db',
      'REDIS_URL=redis://:AnotherPass999@localhost:6379/0',
      'MONGO_URI=mongodb://admin:MongoPass!@cluster/db?authSource=admin',
      'https://example.com/x?password=QuerySecret99&x=1',
    ].join('\n');
    const out = redactSecretsInText(sample);
    assert.doesNotMatch(out, /SuperSecretPass123/);
    assert.doesNotMatch(out, /AnotherPass999/);
    assert.doesNotMatch(out, /MongoPass/);
    assert.doesNotMatch(out, /QuerySecret99/);
    assert.doesNotMatch(out, /sk_live_abcdefghijklmnopqrstuv/);
    assert.doesNotMatch(out, /wJalrXUtnFEMI/);
    assert.match(out, /API_KEY=\[REDACTED\]/);
    assert.match(out, /AWS_SECRET_ACCESS_KEY=\[REDACTED\]/);
    assert.match(out, /\[REDACTED\]/);
  });

  it('masks credential userinfo in bare connection URLs', () => {
    const out = redactSecretsInText(
      '+DATABASE_URL=postgres://user:SuperSecretPass123!@host/db\n',
    );
    assert.doesNotMatch(out, /SuperSecretPass123/);
  });
});

describe('redact: nested prior-receipt diffs', () => {
  it('isReceiptArtifactPath detects .agent-receipt paths', () => {
    assert.equal(isReceiptArtifactPath('.agent-receipt/receipts/r.md'), true);
    assert.equal(isReceiptArtifactPath('.agent-receipt/index.json'), true);
    assert.equal(isReceiptArtifactPath('src/app.ts'), false);
  });

  it('omits nested receipt body so truncated secrets do not re-embed', () => {
    const body = appendHashFooter(`# Agent Receipt

## Session

- **Agent**: bot

## Diff summaries

### \`.agent-receipt/receipts/old.md\`

\`\`\`diff
+| high | \`high-entropy-secret\` | High-entropy token: SuperSecretP… in .env |
+| DATABASE_URL=postgres://user:SuperSecretPass123!@host/db |
\`\`\`

### \`.env\`

\`\`\`diff
+API_KEY=sk_live_abcdefghijklmnopqrstuv
+DATABASE_URL=postgres://user:SuperSecretPass123!@host/db
\`\`\`
`);
    const redacted = appendHashFooter(prepareRedactedBody(body));
    assert.doesNotMatch(redacted, /SuperSecret/);
    assert.doesNotMatch(redacted, /sk_live_abcdefghijklmnopqrstuv/);
    assert.match(redacted, /nested receipt\/index body omitted/);
    assert.match(redacted, /Redacted/);
    const v = verifyMarkdown(redacted);
    assert.equal(v.ok, true);
  });
});

describe('risk: receipt/index high-entropy noise', () => {
  it('does not flag high-entropy tokens inside .agent-receipt paths', () => {
    const token = 'K8vQm2nXp9Lr4sT7wYcB1dF6hJ0aZ3eRu';
    const path = '.agent-receipt/receipts/old.md';
    const hints = analyzeRisks(
      [{ path, status: 'A', insertions: 1, deletions: 0, binary: false }],
      { [path]: `+const apiKey = "${token}";\n` },
    );
    assert.ok(!hints.some((h) => h.code === 'high-entropy-secret'));
  });

  it('still flags high-entropy tokens in normal source paths', () => {
    const token = 'K8vQm2nXp9Lr4sT7wYcB1dF6hJ0aZ3eRu';
    const path = 'src/secret.ts';
    const hints = analyzeRisks(
      [{ path, status: 'M', insertions: 1, deletions: 0, binary: false }],
      { [path]: `+const apiKey = "${token}";\n` },
    );
    assert.ok(hints.some((h) => h.code === 'high-entropy-secret'));
  });

  it('skips pure hex digests even outside receipt paths', () => {
    // Mixed-case hex of length 64 can exceed entropy threshold
    const digest = 'ABCDEF0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcd';
    const path = 'docs/note.md';
    const hints = analyzeRisks(
      [{ path, status: 'M', insertions: 1, deletions: 0, binary: false }],
      { [path]: `+hash ${digest}\n` },
    );
    assert.ok(!hints.some((h) => h.code === 'high-entropy-secret'));
  });
});

describe('verify: trailing after Integrity', () => {
  it('hasTrailingAfterIntegrity detects appends; verify still OK with warn flag', () => {
    const sealed = appendHashFooter(`# Agent Receipt

## Session

- **Agent**: bot
`);
    assert.equal(hasTrailingAfterIntegrity(sealed), false);
    const withTrail = sealed + '\n\n## Notes\n\nSomeone appended this.\n';
    assert.equal(hasTrailingAfterIntegrity(withTrail), true);
    const v = verifyMarkdown(withTrail);
    assert.equal(v.ok, true);
    assert.equal(v.trailingIgnored, true);
  });
});

describe('index: out-of-outDir --out does not become newest', () => {
  let dir;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'agent-receipt-v103-'));
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# v103\n');
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.agent-receipt/\n');
    git(dir, ['add', 'README.md', '.gitignore']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    git(dir, ['add', '.agent-receipt.yml']);
    git(dir, ['commit', '-m', 'init agent-receipt']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('version is 1.0.25', () => {
    const out = cli(dir, ['version']);
    assert.match(out, /1\.0\.25/);
  });

  it('isInsideOutDir distinguishes --out paths', () => {
    assert.equal(
      isInsideOutDir(dir, join(dir, '.agent-receipt/receipts/a.md')),
      true,
    );
    assert.equal(isInsideOutDir(dir, join(dir, 'share.md')), false);
  });

  it('history newest stays on outDir after --out outside capture', () => {
    cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'inside',
      '--message',
      'in-outDir',
    ]);
    const idxBefore = loadIndex(dir);
    assert.ok(idxBefore.receipts.length >= 1);
    const newestBefore = idxBefore.receipts[0].path;

    writeFileSync(join(dir, 'README.md'), '# v103\n\nedit\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'edit']);

    const out = cli(dir, [
      'capture',
      '--commits',
      '1',
      '--agent',
      'outside',
      '--message',
      'out-of-dir',
      '--out',
      'share-outside.md',
    ]);
    assert.match(out, /Wrote receipt/);
    assert.match(out, /index unchanged|outside outDir/i);
    assert.ok(existsSync(join(dir, 'share-outside.md')));

    const idx = loadIndex(dir);
    assert.equal(idx.receipts[0].path, newestBefore);
    assert.ok(!idx.receipts.some((r) => String(r.path).includes('share-outside')));
    assert.notEqual(idx.receipts[0].agent, 'outside');

    const hist = cli(dir, ['history', '--limit', '1']);
    assert.match(hist, /in-outDir|inside/);
    assert.doesNotMatch(hist, /out-of-dir/);
  });

  it('capture --redact masks DATABASE_URL password in committed .env', () => {
    writeFileSync(
      join(dir, '.env'),
      [
        'API_KEY=sk_live_abcdefghijklmnopqrstuv',
        'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'DATABASE_URL=postgres://user:SuperSecretPass123!@host/db',
        '',
      ].join('\n'),
    );
    git(dir, ['add', '.env']);
    git(dir, ['commit', '-m', 'add env with db url']);

    const r = cliStatus(dir, [
      'capture',
      '--commits',
      '1',
      '--redact',
      '--agent',
      'redact-bot',
      '--out',
      'cap-db-redact.md',
    ]);
    // may exit 2 on fail-on default? capture without fail-on should be 0
    assert.equal(r.code, 0, r.out + r.err);
    const md = readFileSync(join(dir, 'cap-db-redact.md'), 'utf8');
    assert.doesNotMatch(md, /SuperSecretPass123/);
    assert.doesNotMatch(md, /sk_live_abcdefghijklmnopqrstuv/);
    assert.match(md, /\[REDACTED/);
    const v = cli(dir, ['verify', 'cap-db-redact.md']);
    assert.match(v, /OK/);
  });

  it('verify warns when trailing content follows Integrity', () => {
    const sealed = appendHashFooter(`# Agent Receipt

## Session

- **Agent**: trail
`);
    writeFileSync(
      join(dir, 'trail.md'),
      sealed + '\n\n## Extra\n\nappended note\n',
      'utf8',
    );
    const out = cli(dir, ['verify', 'trail.md']);
    assert.match(out, /OK/);
    assert.match(out, /trailing content after ## Integrity is ignored/i);
  });
});
