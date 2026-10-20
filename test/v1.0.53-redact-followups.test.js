/**
 * v1.0.53 — Release QA follow-ups from v1.0.52.
 * Verify and attest mask secret-shaped paths, non-standard RSA runs are
 * not split, share --json exposes relativePath for the example action,
 * and verify fails closed on trailing content.
 */
import { describe, it, after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendHashFooter } from '../dist/lib/hash.js';
import {
  maskJwtTokens,
  publishRedactedReceipt,
  redactMarkdownBody,
  redactSecretsInText,
} from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const RSA_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];

after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function keep(dir) {
  dirs.push(dir);
  return dir;
}

function b64url(text) {
  return Buffer.from(text).toString('base64url');
}

function jwtFor(alg, signature) {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'qa' }));
  return `${header}.${payload}.${signature}`;
}

/** `marker` sits after `at`. `joiner` is `/` or `+` inside a signature of `length`. */
function markedSig(length, at, marker, joiner) {
  const glued = joiner === '+' ? `+${marker}/src` : `/${marker}/src`;
  assert.ok(at + glued.length <= length, `${marker} does not fit in ${length}`);
  return `${'A'.repeat(at)}${glued}${'B'.repeat(length - at - glued.length)}`;
}

function assertSigGone(text, pieces, label) {
  for (const piece of pieces) {
    assert.equal(text.includes(piece), false, `${label} kept ${piece.slice(0, 40)}`);
  }
}

function maskSurfaces(raw) {
  return [
    ['general', maskJwtTokens(raw, 'general')],
    ['strict', maskJwtTokens(raw, 'strict')],
    ['text', redactSecretsInText(raw)],
    ['markdown', redactMarkdownBody(raw)],
    ['publish', publishRedactedReceipt(raw)],
  ];
}

describe('v1.0.53 non-standard RSA signature lengths', () => {
  const cases = [
    [511, 342],
    [600, 512],
    [682, 512],
    [400, 342],
  ];

  for (const alg of RSA_ALGS) {
    for (const [length, at] of cases) {
      for (const joiner of ['/', '+']) {
        const marker = `M${length}${joiner === '/' ? 's' : 'p'}${alg}`;
        it(`masks ${alg} length ${length} with ${joiner} at ${at}`, () => {
          const sig = markedSig(length, at, marker, joiner);
          const token = jwtFor(alg, sig);
          const raw = `${token} tail`;
          for (const [label, out] of maskSurfaces(raw)) {
            assertSigGone(
              out,
              [marker, sig.slice(at, at + marker.length), token.split('.')[0]],
              `${alg} ${length} ${joiner} ${label}`,
            );
            assert.equal(out.includes('tail'), true, `${label} ate the trailer`);
          }
        });
      }
    }
  }

  it('still keeps a short path after an exact RSA signature', () => {
    const kept = [
      ['RS256', 342],
      ['PS256', 342],
      ['RS384', 512],
      ['PS384', 512],
      ['RS512', 683],
      ['PS512', 683],
    ];
    for (const [alg, length] of kept) {
      const slash = `${jwtFor(alg, 'A'.repeat(length))}/src/app.ts`;
      const plus = `${jwtFor(alg, 'A'.repeat(length))}+src/app.ts`;
      assert.equal(maskJwtTokens(slash), '[REDACTED]/src/app.ts', alg);
      assert.equal(maskJwtTokens(plus), '[REDACTED]+src/app.ts', alg);
      assert.equal(redactSecretsInText(slash), '[REDACTED]/src/app.ts', alg);
    }
  });

  it('scans a run of non-standard RSA tokens in well under ten seconds', () => {
    const sig = markedSig(511, 342, 'M511sRS256', '/');
    const unit = `${jwtFor('RS256', sig)} `;
    const input = unit.repeat(Math.ceil((256 * 1024) / unit.length));
    const started = Date.now();
    const out = redactSecretsInText(input);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 10000, `non-standard RSA scan took ${elapsed}ms`);
    assert.equal(out.includes('M511sRS256'), false);
  });
});

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args) {
  const result = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    maxBuffer: 32 * 1024 * 1024,
    timeout: 120000,
  });
  const extra = result.error ? result.error.message : '';
  return {
    code: result.status === null ? 1 : result.status,
    out: result.stdout || '',
    err: `${result.stderr || ''}${extra}`,
  };
}

function gitRepo(prefix) {
  const dir = keep(mkdtempSync(join(tmpdir(), prefix)));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# qa\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  const init = cli(dir, ['init']);
  assert.equal(init.code, 0, init.err + init.out);
  return dir;
}

function latestReceipt(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  const files = readdirSync(out)
    .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
    .map((name) => join(out, name));
  assert.ok(files.length > 0, 'expected a receipt');
  return files.sort()[files.length - 1];
}

describe('v1.0.53 RSA signatures on every redaction surface', () => {
  it('leaves no raw signature substring on receipt display, attest, share, html, and report', () => {
    const dir = gitRepo('ar1053-jwt-');
    const parts = [];
    const markers = [];
    const samples = [
      ['RS256', 511, 342, '/', 'M511sRS256'],
      ['PS256', 511, 342, '+', 'M511pPS256'],
      ['RS384', 600, 512, '/', 'M600sRS384'],
      ['PS384', 600, 512, '+', 'M600pPS384'],
      ['RS512', 682, 512, '/', 'M682sRS512'],
      ['PS512', 682, 512, '+', 'M682pPS512'],
      ['RS256', 400, 342, '/', 'M400sRS256'],
      ['PS512', 400, 342, '+', 'M400pPS512'],
    ];
    for (const [alg, length, at, joiner, marker] of samples) {
      markers.push(marker);
      const sig = markedSig(length, at, marker, joiner);
      parts.push(`${jwtFor(alg, sig)}+tail`);
    }
    const note = parts.join(' ');
    writeFileSync(join(dir, 'token.txt'), `${note}\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', note]).code, 0);

    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(markers[0]), true, 'stored receipt stays raw');

    function gone(text, label) {
      for (const piece of markers) {
        assert.equal(text.includes(piece), false, `${label} kept ${piece}`);
      }
    }

    for (const [label, args] of [
      ['history', ['history']],
      ['history --json', ['history', '--json']],
      ['show', ['show']],
      ['compare', ['compare']],
      ['last', ['last']],
      ['last --json', ['last', '--json']],
    ]) {
      const result = cli(dir, args);
      assert.equal(result.code, 0, `${label} ${result.err}`);
      gone(result.out + result.err, label);
    }

    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = cli(dir, ['attest', storedPath, '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    const attestPath = JSON.parse(created.out).path;
    const statement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(attestPath, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    gone(JSON.stringify(statement), 'attest');
    gone(created.out + created.err, 'attest stdout');

    const shared = cli(dir, ['share', storedPath]);
    assert.equal(shared.code, 0, shared.err + shared.out);
    gone(shared.out + shared.err, 'share');
    const shareHtml = storedPath.replace(/\.md$/i, '.html');
    gone(readFileSync(shareHtml, 'utf8'), 'share html');

    const htmlOut = join(dir, 'redacted-token.html');
    const html = cli(dir, ['html', storedPath, '--redact', '--out', htmlOut]);
    assert.equal(html.code, 0, html.err + html.out);
    gone(readFileSync(htmlOut, 'utf8'), 'html file');

    const reported = cli(dir, ['report', storedPath]);
    assert.equal(reported.code, 0, reported.err + reported.out);
    gone(reported.out + reported.err, 'report');
    const reportFile = readdirSync(join(dir, '.agent-receipt')).find((name) => name.endsWith('.report.html'));
    assert.ok(reportFile, 'report html');
    gone(readFileSync(join(dir, '.agent-receipt', reportFile), 'utf8'), 'report html');

    writeFileSync(join(dir, 'token.txt'), `${note}\nagain\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'edit token']);
    assert.equal(cli(dir, ['capture', '--redact', '--agent', 'cursor', '--message', note]).code, 0);
    gone(readFileSync(latestReceipt(dir), 'utf8'), 'redacted receipt');
  });
});

describe('v1.0.53 secret-shaped paths and the example action', () => {
  const secret = `ghp_${'b'.repeat(36)}`;
  let parent;
  let repo;

  before(() => {
    parent = keep(mkdtempSync(join(tmpdir(), 'ar1053-path-')));
    repo = join(parent, secret, 'repo');
    mkdirSync(repo, { recursive: true });
    git(repo, ['init', '-b', 'main']);
    git(repo, ['config', 'user.email', 'test@example.com']);
    git(repo, ['config', 'user.name', 'Test']);
    git(repo, ['config', 'commit.gpgsign', 'false']);
    writeFileSync(join(repo, 'README.md'), '# qa\n');
    git(repo, ['add', 'README.md']);
    git(repo, ['commit', '-m', 'initial']);
    assert.equal(cli(repo, ['init']).code, 0);
    assert.equal(cli(repo, ['capture', '--agent', 'cursor', '--message', 'one']).code, 0);
    assert.equal(cli(repo, ['keygen']).code, 0);
  });

  function blob(result) {
    return `${result.out}${result.err}`;
  }

  function assertMasked(result, label) {
    const text = blob(result);
    assert.equal(text.includes(secret), false, `${label} printed the raw directory`);
    assert.equal(text.includes('b'.repeat(36)), false, `${label} printed the token body`);
    assert.equal(text.includes('ghp_[REDACTED]'), true, `${label} did not mask the directory\n${text}`);
  }

  it('verify masks the repo path in plain output and JSON', () => {
    const receipt = latestReceipt(repo);
    const plain = cli(repo, ['verify', receipt]);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assertMasked(plain, 'verify');

    const json = cli(repo, ['verify', receipt, '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assertMasked(json, 'verify --json');
    const body = JSON.parse(json.out);
    assert.equal(body.verified, true);
    assert.equal(body.path.includes('ghp_[REDACTED]'), true);
    assert.equal(body.path.includes(secret), false);
    assert.equal(existsSync(body.path), false);
    assert.equal(existsSync(receipt), true);
  });

  it('attest masks wrote and JSON paths', () => {
    const receipt = latestReceipt(repo);
    const outName = 'qa-attest.intoto.jsonl';
    const created = cli(repo, ['attest', receipt, '--out', outName, '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    assertMasked(created, 'attest --json');
    const body = JSON.parse(created.out);
    assert.equal(body.path.includes('ghp_[REDACTED]'), true);
    assert.equal(body.path.endsWith(outName), true);
    assert.equal(existsSync(join(repo, outName)), true);
    assert.equal(existsSync(body.path), false);

    const plain = cli(repo, ['attest', receipt, '--out', 'qa-attest-plain.intoto.jsonl']);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assert.match(plain.out, /wrote /);
    assertMasked(plain, 'attest wrote');

    const checked = cli(repo, ['attest', '--verify', outName, '--json']);
    assert.equal(checked.code, 0, checked.err + checked.out);
    assertMasked(checked, 'attest --verify --json');
    const plainCheck = cli(repo, ['attest', '--verify', outName]);
    assert.equal(plainCheck.code, 0, plainCheck.err + plainCheck.out);
    assert.match(plainCheck.out, /OK /);
    assertMasked(plainCheck, 'attest --verify');
  });

  it('verify --package masks the package path', () => {
    const receipt = latestReceipt(repo);
    const packed = cli(repo, ['share', receipt, '--package', '--json']);
    assert.equal(packed.code, 0, packed.err + packed.out);
    assertMasked(packed, 'share --package --json');
    const gate = JSON.parse(packed.out);
    assert.equal(gate.packagePath.includes(secret), false);
    assert.equal(gate.packagePath.includes('ghp_[REDACTED]'), true);
    const realPack = receipt.replace(/\.md$/i, '.share');
    assert.equal(existsSync(realPack), true);
    const verified = cli(repo, ['verify', '--package', realPack]);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assertMasked(verified, 'verify --package');
    const vjson = cli(repo, ['verify', '--package', realPack, '--json']);
    assert.equal(vjson.code, 0, vjson.err + vjson.out);
    const body = JSON.parse(vjson.out);
    assert.equal(body.packagePath.includes(secret), false);
    assert.equal(body.path.includes(secret), false);
    assert.equal(body.htmlPath.includes('ghp_[REDACTED]'), true);
  });

  it('share --json relativePath verifies when the displayed path is masked', () => {
    const shared = cli(repo, ['share', '--json']);
    assert.equal(shared.code, 0, shared.err + shared.out);
    assertMasked(shared, 'share --json');
    const body = JSON.parse(shared.out);
    assert.equal(typeof body.relativePath, 'string');
    assert.equal(body.relativePath.includes(secret), false);
    assert.equal(body.relativePath.includes('[REDACTED]'), false);
    assert.equal(body.path.includes('ghp_[REDACTED]'), true);
    assert.equal(existsSync(join(repo, body.relativePath)), true);

    const action = readFileSync(join(root, 'examples/github/action.yml'), 'utf8');
    const gate = readFileSync(join(root, 'examples/github/pr-gate.yml'), 'utf8');
    assert.match(action, /relativePath/);
    assert.match(gate, /relativePath/);
    const picker = action.match(/node -e '([^']*relativePath[^']*)'/)[1];
    assert.match(gate, /node -e '([^']*relativePath[^']*)'/);
    const gateFile = join(repo, 'share-gate.json');
    writeFileSync(gateFile, shared.out);
    const picked = execFileSync(process.execPath, ['-e', picker, gateFile], { encoding: 'utf8' });
    assert.equal(picked, body.relativePath);
    const verified = cli(repo, ['verify', picked]);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assert.match(verified.out, /OK/);

    const stage = join(repo, 'stage');
    mkdirSync(stage, { recursive: true });
    const staged = execFileSync(
      process.execPath,
      [
        '-e',
        `const fs=require("fs"); const path=require("path"); const g=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); const rel=g&&typeof g.relativePath==="string"?g.relativePath:""; const raw=g&&typeof g.path==="string"?g.path:""; const src=rel&&rel.indexOf("[REDACTED]")<0&&fs.existsSync(rel)?rel:(raw&&raw.indexOf("[REDACTED]")<0?raw:""); if(!src||!fs.existsSync(src)){console.error("missing"); process.exit(1);} fs.copyFileSync(src, path.join(process.argv[2], path.basename(src))); process.stdout.write(path.basename(src));`,
        gateFile,
        stage,
      ],
      { cwd: repo, encoding: 'utf8' },
    );
    assert.equal(existsSync(join(stage, staged)), true);
    assert.equal(staged.includes(secret), false);
  });

  it('leaves last --path raw and a normal verify path usable', () => {
    const raw = cli(repo, ['last', '--path']);
    assert.equal(raw.code, 0, raw.err);
    assert.equal(raw.out.includes(secret), true);

    const dir = gitRepo('ar1053-plain-');
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'plain']).code, 0);
    const json = cli(dir, ['verify', '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    const body = JSON.parse(json.out);
    assert.equal(existsSync(body.path), true);
    assert.equal(Object.prototype.hasOwnProperty.call(body, 'relativePath'), false);
    const shared = cli(dir, ['share', '--json']);
    assert.equal(shared.code, 0, shared.err + shared.out);
    const shareBody = JSON.parse(shared.out);
    assert.equal(existsSync(shareBody.path), true);
    assert.equal(existsSync(join(dir, shareBody.relativePath)), true);
  });
});

describe('v1.0.53 trailing content fails verify', () => {
  it('fails closed on a SECURITY note and still passes whitespace-only trailing newlines', () => {
    const dir = gitRepo('ar1053-trail-');
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'trail']).code, 0);
    const receipt = latestReceipt(dir);
    const original = readFileSync(receipt, 'utf8');

    writeFileSync(receipt, `${original}\n`);
    let json = cli(dir, ['verify', receipt, '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assert.equal(JSON.parse(json.out).verified, true);
    assert.equal(JSON.parse(json.out).trailingIgnored, false);

    writeFileSync(receipt, `${original}\n\n`);
    let plain = cli(dir, ['verify', receipt]);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assert.match(plain.out, /OK/);

    writeFileSync(receipt, `${original}\n   \n`);
    json = cli(dir, ['verify', receipt, '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assert.equal(JSON.parse(json.out).ok, true);

    writeFileSync(receipt, `${original}\nSECURITY: do not trust this appended line\n`);
    plain = cli(dir, ['verify', receipt]);
    assert.equal(plain.code, 2, plain.out + plain.err);
    assert.match(plain.err, /trailing content after the last chained record/);
    assert.doesNotMatch(plain.out, /OK/);
    assert.doesNotMatch(plain.out + plain.err, /ignored by design/i);

    json = cli(dir, ['verify', receipt, '--json']);
    assert.equal(json.code, 2, json.err + json.out);
    const body = JSON.parse(json.out);
    assert.equal(body.ok, false);
    assert.equal(body.verified, false);
    assert.equal(body.exitCode, 2);
    assert.equal(body.trailingIgnored, true);
    assert.match(body.reason, /trailing content after the last chained record/);
    assert.equal(body.reason.includes('Hash mismatch'), false);
  });

  it('keeps hash mismatch as the reason when the body was edited', () => {
    const sealed = appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Agent**: trail\n');
    const edited = sealed.replace('trail', 'TRAIL') + '\nSECURITY: note\n';
    const dir = gitRepo('ar1053-tamper-');
    writeFileSync(join(dir, 'tamper.md'), edited);
    const json = cli(dir, ['verify', 'tamper.md', '--json']);
    assert.equal(json.code, 2, json.err + json.out);
    const body = JSON.parse(json.out);
    assert.match(body.reason, /Hash mismatch/);
    assert.equal(body.trailingIgnored, true);
    assert.equal(body.reason.includes('trailing content'), false);
  });
});
