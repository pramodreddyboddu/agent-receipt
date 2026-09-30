import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { appendHashFooter } from '../dist/lib/hash.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const LINK_ENV = [
  'AGENT_RECEIPT_SESSION',
  'AGENT_RECEIPT_PARENT',
  'AGENT_RECEIPT_AGENT',
  'AGENT_RECEIPT_HOST',
];

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function spawnEnv(extra = {}) {
  const env = { ...process.env, NO_COLOR: '1' };
  for (const key of LINK_ENV) delete env[key];
  for (const [key, value] of Object.entries(extra)) {
    if (value === undefined || value === null) delete env[key];
    else env[key] = value;
  }
  return env;
}

function cliResult(cwd, args, extraEnv) {
  const r = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: spawnEnv(extraEnv),
    timeout: 20000,
  });
  return { code: r.status === null ? 1 : r.status, out: r.stdout || '', err: r.stderr || '' };
}

function cli(cwd, args, extraEnv) {
  const r = cliResult(cwd, args, extraEnv);
  if (r.code !== 0) throw new Error(`exit ${r.code}\n${r.out}\n${r.err}`);
  return r.out;
}

function parseJson(out) {
  return JSON.parse(out);
}

function field(md, label) {
  const prefix = `- **${label}**:`;
  for (const line of md.split('\n')) {
    if (!line.startsWith(prefix)) continue;
    const value = line.slice(prefix.length).trim().replace(/^`|`$/g, '');
    return value || null;
  }
  return null;
}

function latestReceipt(dir) {
  const body = parseJson(cli(dir, ['last', '--json']));
  return { path: body.path, md: readFileSync(body.path, 'utf8') };
}

describe('v1.0.28 multi-agent receipt linking', () => {
  const dirs = [];
  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1028-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# link\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function commitFile(dir, name, content) {
    writeFileSync(join(dir, name), content);
    git(dir, ['add', name]);
    git(dir, ['commit', '-m', name]);
  }

  it('documents 1.0.28, linking, and no new runtime dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.28\]/);
    assert.match(changelog, /Landed on main directly after 1\.0\.26/);
    assert.match(changelog, /was not stacked on #39/);
    assert.doesNotMatch(changelog.split('## [1.0.26]')[0], /Stacked on 1\.0\.26 \(auto-prune, PR #39\)/);
    assert.match(changelog, /cross-host session merge/);
    assert.match(changelog, /signed session manifest/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /npm Trusted Publishing/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.28');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.28');
    assert.equal(lock.packages[''].version, '1.0.28');
    assert.equal(lock.packages[''].dependencies, undefined);
    assert.match(readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8'), /1\.0\.28/);
    const help = cli(root, ['help', 'session']);
    assert.match(help, /session <id>/);
    assert.match(help, /orphan/);
    assert.match(cli(root, ['help', 'share']), /--include-host/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /Linking multi-agent runs/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /Linking multi-agent runs/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.28/);
    assert.match(mirror, /ci-link-1028/);
    for (const name of readdirSync(join(root, '.github', 'workflows'))) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /ci-link-1028/);
      assert.doesNotMatch(live, /v1\.0\.28/);
    }
  });

  it('escapes quotes in prove --html and sets img-src none', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'quote\n');
    const wrapped = cliResult(dir, ['wrap', '--agent', 'ci', '--message', "it's a receipt"]);
    assert.equal(wrapped.code, 0, wrapped.err);
    const proved = cliResult(dir, ['prove', '--html']);
    assert.equal(proved.code, 0, proved.err);
    const htmlPath = proved.out.match(/html: (.+\.prove\.html)/)[1].trim();
    const html = readFileSync(htmlPath, 'utf8');
    assert.match(html, /it&#39;s a receipt/);
    assert.doesNotMatch(html, /it's a receipt/);
    assert.match(html, /default-src 'none'/);
    assert.match(html, /style-src 'unsafe-inline'/);
    assert.match(html, /img-src 'none'/);
  });

  it('lets flags win over env and records env when no flag is set', () => {
    const dir = initRepo();
    commitFile(dir, 'a.txt', 'a\n');
    const flagged = cliResult(
      dir,
      ['capture', '--session', 'flag-sess', '--agent', 'flag-agent', '--message', 'flagged'],
      { AGENT_RECEIPT_SESSION: 'env-sess', AGENT_RECEIPT_AGENT: 'env-agent' },
    );
    assert.equal(flagged.code, 0, flagged.err);
    const flaggedMd = latestReceipt(dir).md;
    assert.equal(field(flaggedMd, 'Session'), 'flag-sess');
    assert.equal(field(flaggedMd, 'Agent'), 'flag-agent');
    assert.match(field(flaggedMd, 'Id'), /^r-[0-9a-f]{16}$/);
    assert.equal(field(flaggedMd, 'Host'), null);

    commitFile(dir, 'b.txt', 'b\n');
    const parentHash = 'ab'.repeat(32);
    const fromEnv = cliResult(dir, ['capture', '--message', 'from-env'], {
      AGENT_RECEIPT_SESSION: 'env-sess',
      AGENT_RECEIPT_AGENT: 'env-agent',
      AGENT_RECEIPT_PARENT: parentHash,
    });
    assert.equal(fromEnv.code, 0, fromEnv.err);
    const envMd = latestReceipt(dir).md;
    assert.equal(field(envMd, 'Session'), 'env-sess');
    assert.equal(field(envMd, 'Agent'), 'env-agent');
    assert.equal(field(envMd, 'Parent'), parentHash);
    assert.equal(field(envMd, 'Host'), null);
  });

  it('rejects invalid link values before writing', () => {
    const dir = initRepo();
    for (const [args, needle] of [
      [['capture', '--session', 'bad/id', '--message', 'x'], /Invalid session/],
      [['capture', '--session', 'has space', '--message', 'x'], /Invalid session/],
      [['capture', '--session', '..', '--message', 'x'], /Invalid session/],
      [['capture', '--session'], /--session requires a value/],
      [['capture', '--agent', 'bad/id', '--message', 'x'], /Invalid agent/],
      [['capture', '--parent', '../secret', '--message', 'x'], /--parent must not contain/],
      [['capture', '--host', 'bad/host', '--message', 'x'], /Invalid host/],
      [['watch', '--once', '--session', 'bad/id'], /Invalid session/],
    ]) {
      const before = existsSync(join(dir, '.agent-receipt', 'receipts'))
        ? readdirSync(join(dir, '.agent-receipt', 'receipts'))
        : [];
      const bad = cliResult(dir, args);
      assert.equal(bad.code, 1, `${args.join(' ')}\n${bad.out}\n${bad.err}`);
      assert.match(bad.err, needle, bad.err);
      const after = existsSync(join(dir, '.agent-receipt', 'receipts'))
        ? readdirSync(join(dir, '.agent-receipt', 'receipts'))
        : [];
      assert.deepEqual(after, before);
    }
  });

  it('links a nested wrap and leaves the default wrap unchanged', () => {
    const dir = initRepo();
    commitFile(dir, 'parent.txt', 'parent\n');
    const nested = cliResult(dir, [
      'wrap',
      '--link',
      '--session',
      'new',
      '--agent',
      'parent',
      '--message',
      'p',
      '--',
      process.execPath,
      bin,
      'wrap',
      '--cwd',
      dir,
      '--agent',
      'child',
      '--message',
      'c',
    ]);
    assert.equal(nested.code, 0, nested.out + nested.err);
    const files = readdirSync(join(dir, '.agent-receipt', 'receipts')).filter((name) =>
      name.endsWith('.md') && !name.endsWith('.prove.md'),
    );
    assert.equal(files.length, 2);
    for (const name of files) {
      const checked = cliResult(dir, ['verify', join(dir, '.agent-receipt', 'receipts', name)]);
      assert.equal(checked.code, 0, checked.out + checked.err);
    }
    const bodies = files.map((name) =>
      readFileSync(join(dir, '.agent-receipt', 'receipts', name), 'utf8'),
    );
    const parentMd = bodies.find((md) => field(md, 'Agent') === 'parent');
    const childMd = bodies.find((md) => field(md, 'Agent') === 'child');
    assert.ok(parentMd && childMd);
    const session = field(parentMd, 'Session');
    assert.match(session, /^s-[0-9a-f]{16}$/);
    assert.equal(field(childMd, 'Session'), session);
    assert.equal(field(childMd, 'Parent'), field(parentMd, 'Id'));
    assert.equal(field(parentMd, 'Parent'), null);
    assert.doesNotMatch(parentMd, /\*\*Session\*\*: new/);
    const tree = parseJson(cli(dir, ['session', session, '--json']));
    assert.equal(tree.ok, true);
    assert.equal(tree.exitCode, 0);
    assert.equal(tree.receipts.length, 2);
    const child = tree.receipts.find((row) => row.agent === 'child');
    const parent = tree.receipts.find((row) => row.agent === 'parent');
    assert.equal(child.parent, parent.id);
    assert.equal(child.verified, true);
    assert.equal(parent.parent, null);
    assert.equal(child.orphan, false);
    assert.equal(child.cycle, false);
    const human = cli(dir, ['session', session]);
    assert.match(human, new RegExp(parent.id));
    assert.match(human, /agent=child/);
    assert.match(human, /verified/);

    const marker = join(dir, 'child-ran.txt');
    commitFile(dir, 'plain.txt', 'plain\n');
    const plain = cliResult(dir, [
      'wrap',
      '--agent',
      'ci',
      '--message',
      'nolink',
      '--',
      process.execPath,
      '-e',
      `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x')`,
    ]);
    assert.equal(plain.code, 0, plain.err);
    assert.equal(existsSync(marker), false);
    const plainMd = latestReceipt(dir).md;
    assert.equal(field(plainMd, 'Id'), null);
    assert.equal(field(plainMd, 'Session'), null);
    assert.equal(field(plainMd, 'Parent'), null);
    assert.equal(field(plainMd, 'Host'), null);
    assert.equal(cliResult(dir, ['verify']).code, 0);
    const plainProve = parseJson(cli(dir, ['prove', '--json']));
    assert.equal('session' in plainProve, false);
    assert.equal('parent' in plainProve, false);
    assert.equal('parentVerified' in plainProve, false);

    const noisy = cliResult(dir, [
      'wrap',
      '--link',
      '--session',
      'child-exit',
      '--agent',
      'parent',
      '--message',
      'exit',
      '--',
      process.execPath,
      '-e',
      'process.exit(3)',
    ]);
    assert.equal(noisy.code, 0, noisy.err);
    assert.match(noisy.out + noisy.err, /child exit 3/);
  });

  it('breaks verify when a link field is tampered and still verifies an old receipt', () => {
    const dir = initRepo();
    commitFile(dir, 'old.txt', 'old\n');
    assert.equal(cliResult(dir, ['wrap', '--agent', 'ci', '--message', 'old']).code, 0);
    const old = latestReceipt(dir);
    assert.equal(field(old.md, 'Session'), null);
    assert.equal(cliResult(dir, ['verify', old.path]).code, 0);

    commitFile(dir, 'new.txt', 'new\n');
    assert.equal(
      cliResult(dir, ['wrap', '--session', 'sess-tamper', '--agent', 'ci', '--message', 'linked']).code,
      0,
    );
    const linked = latestReceipt(dir);
    const tampered = linked.md.replace('sess-tamper', 'sess-tampEr');
    writeFileSync(linked.path, tampered);
    const verified = cliResult(dir, ['verify', linked.path]);
    assert.equal(verified.code, 2);
    assert.match(verified.out + verified.err, /tampered|mismatch|FAIL/i);
  });

  it('resolves a local parent path to that receipt id', () => {
    const dir = initRepo();
    commitFile(dir, 'p.txt', 'p\n');
    assert.equal(
      cliResult(dir, ['wrap', '--link', '--session', 'path-sess', '--agent', 'parent', '--message', 'p']).code,
      0,
    );
    const parent = latestReceipt(dir);
    commitFile(dir, 'c.txt', 'c\n');
    assert.equal(
      cliResult(dir, [
        'wrap',
        '--session',
        'path-sess',
        '--parent',
        parent.path,
        '--agent',
        'child',
        '--message',
        'c',
      ]).code,
      0,
    );
    const child = latestReceipt(dir);
    assert.equal(field(child.md, 'Parent'), field(parent.md, 'Id'));
    const proved = cliResult(dir, ['prove', child.path]);
    assert.equal(proved.code, 0, proved.err);
    assert.match(proved.out, /session: path-sess/);
    assert.match(proved.out, new RegExp(`parent: ${field(parent.md, 'Id')}`));
    assert.match(proved.out, /parent verify: yes/);
    assert.doesNotMatch(proved.out, /hq-host-label/);
    const html = cliResult(dir, ['prove', '--html', child.path]);
    assert.equal(html.code, 0, html.err);
    const htmlPath = html.out.match(/html: (.+\.prove\.html)/)[1].trim();
    const page = readFileSync(htmlPath, 'utf8');
    assert.match(page, /path-sess/);
    assert.match(page, /Parent verify/);
    assert.match(page, />yes</);
    const json = parseJson(cli(dir, ['prove', child.path, '--json']));
    assert.equal(json.session, 'path-sess');
    assert.equal(json.parent, field(parent.md, 'Id'));
    assert.equal(json.parentVerified, true);
    assert.equal(json.exitCode, 0);
  });

  it('flags cycles and orphans and exits 1 when a session receipt fails verify', () => {
    const dir = initRepo();
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    const seal = (body) => appendHashFooter(body.endsWith('\n') ? body : `${body}\n`);
    writeFileSync(
      join(outDir, 'receipt-cycle-a.md'),
      seal(`## Session

- **Id**: r-aaaaaaaaaaaaaaaa
- **Timestamp**: 2026-09-29T00:00:00.000Z
- **Agent**: cycle-a
- **Session**: sess-cycle
- **Parent**: r-bbbbbbbbbbbbbbbb
`),
    );
    writeFileSync(
      join(outDir, 'receipt-cycle-b.md'),
      seal(`## Session

- **Id**: r-bbbbbbbbbbbbbbbb
- **Timestamp**: 2026-09-29T00:00:01.000Z
- **Agent**: cycle-b
- **Session**: sess-cycle
- **Parent**: r-aaaaaaaaaaaaaaaa
`),
    );
    const cycle = parseJson(cli(dir, ['session', 'sess-cycle', '--json']));
    assert.equal(cycle.exitCode, 0);
    assert.equal(cycle.receipts.length, 2);
    assert.equal(cycle.receipts.every((row) => row.cycle === true && row.orphan === false && row.verified === true), true);
    const cycleHuman = cli(dir, ['session', 'sess-cycle']);
    assert.match(cycleHuman, /cycle/);

    writeFileSync(
      join(outDir, 'receipt-orphan.md'),
      seal(`## Session

- **Id**: r-cccccccccccccccc
- **Timestamp**: 2026-09-29T00:00:02.000Z
- **Agent**: lonely
- **Session**: sess-orphan
- **Parent**: r-0000000000000000
`),
    );
    const orphan = parseJson(cli(dir, ['session', 'sess-orphan', '--json']));
    assert.equal(orphan.exitCode, 0);
    assert.equal(orphan.receipts[0].orphan, true);
    assert.equal(orphan.receipts[0].cycle, false);
    assert.equal(orphan.receipts[0].verified, true);
    assert.equal(orphan.receipts[0].exitCode, 0);
    assert.match(cli(dir, ['session', 'sess-orphan']), /orphan/);

    writeFileSync(
      join(outDir, 'receipt-other.md'),
      seal(`## Session

- **Id**: r-dddddddddddddddd
- **Timestamp**: 2026-09-29T00:00:03.000Z
- **Agent**: other
- **Session**: sess-other
- **Parent**: r-aaaaaaaaaaaaaaaa
`),
    );
    const other = parseJson(cli(dir, ['session', 'sess-other', '--json']));
    assert.equal(other.receipts[0].orphan, false);

    const brokenPath = join(outDir, 'receipt-orphan.md');
    writeFileSync(brokenPath, readFileSync(brokenPath, 'utf8').replace('lonely', 'lonelier'));
    const failed = cliResult(dir, ['session', 'sess-orphan', '--json']);
    assert.equal(failed.code, 1);
    const failedBody = parseJson(failed.out);
    assert.equal(failedBody.ok, false);
    assert.equal(failedBody.exitCode, 1);
    assert.equal(failedBody.receipts[0].verified, false);
    assert.equal(failedBody.receipts[0].exitCode, 2);

    const empty = cliResult(dir, ['session', 'missing-sess', '--json']);
    assert.equal(empty.code, 1);
    const emptyBody = parseJson(empty.out);
    assert.deepEqual(emptyBody.receipts, []);
    assert.equal(emptyBody.exitCode, 1);
    assert.equal(emptyBody.session, 'missing-sess');
    const emptyHuman = cliResult(dir, ['session', 'missing-sess']);
    assert.equal(emptyHuman.code, 1);
    assert.match(emptyHuman.err, /no receipts in session missing-sess/);
  });

  it('masks host on share, keeps it on capture --redact, and hides it from prove', () => {
    const dir = initRepo();
    commitFile(dir, 'host.txt', 'host\n');
    const parentHash = 'cd'.repeat(32);
    const captured = cliResult(dir, [
      'capture',
      '--host',
      'hq-host-label',
      '--session',
      'sess-share',
      '--agent',
      'ci',
      '--parent',
      parentHash,
      '--message',
      'hosted',
    ]);
    assert.equal(captured.code, 0, captured.err);
    const source = latestReceipt(dir);
    assert.equal(field(source.md, 'Host'), 'hq-host-label');
    assert.equal(field(source.md, 'Session'), 'sess-share');
    assert.equal(field(source.md, 'Parent'), parentHash);

    const shared = cliResult(dir, ['share', '--md', 'shared.md']);
    assert.equal(shared.code, 0, shared.err);
    const html = readFileSync(source.path.replace(/\.md$/i, '.html'), 'utf8');
    const md = readFileSync(join(dir, 'shared.md'), 'utf8');
    for (const body of [html, md]) {
      assert.match(body, /sess-share/);
      assert.match(body, new RegExp(parentHash));
      assert.match(body, /\[REDACTED\]/);
      assert.doesNotMatch(body, /hq-host-label/);
    }
    const opened = cliResult(dir, [
      'share',
      '--include-host',
      '--out',
      'opened.html',
      '--md',
      'opened.md',
    ]);
    assert.equal(opened.code, 0, opened.err);
    assert.match(readFileSync(join(dir, 'opened.html'), 'utf8'), /hq-host-label/);
    assert.match(readFileSync(join(dir, 'opened.md'), 'utf8'), /hq-host-label/);

    const proved = cliResult(dir, ['prove', source.path]);
    assert.equal(proved.code, 0, proved.err);
    assert.match(proved.out, /session: sess-share/);
    assert.match(proved.out, /parent verify: not local/);
    assert.doesNotMatch(proved.out, /hq-host-label/);

    commitFile(dir, 'redact.txt', 'redact\n');
    const redacted = cliResult(dir, [
      'capture',
      '--redact',
      '--host',
      'hq-host-label',
      '--session',
      'sess-redact',
      '--agent',
      'ci',
      '--message',
      'kept',
    ]);
    assert.equal(redacted.code, 0, redacted.err);
    const kept = latestReceipt(dir).md;
    assert.equal(field(kept, 'Host'), 'hq-host-label');
    assert.equal(cliResult(dir, ['verify']).code, 0);
  });

  it('reports linking as doctor INFO, including under --strict', () => {
    const dir = initRepo();
    const soft = parseJson(cli(dir, ['doctor', '--json']));
    const row = soft.checks.find((check) => check.id === 'link');
    assert.ok(row);
    assert.equal(row.status, 'info');
    assert.match(row.detail, /wrap --link/);
    const hard = cliResult(dir, ['doctor', '--strict', '--json']);
    const hardBody = parseJson(hard.out);
    assert.equal(hardBody.checks.find((check) => check.id === 'link').status, 'info');
  });
});
