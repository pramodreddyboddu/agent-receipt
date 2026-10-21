/**
 * v1.0.56 Release QA re-gate.
 * Attestations land beside the receipt. Short random extension tails are
 * masked without a digit rule. Real checkout paths stay visible. The
 * example receipt picker resolves a receipts root before a cwd-relative path.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendHashFooter } from '../dist/lib/hash.js';
import { maskJwtTokens, redactSecretsInText } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const RSA_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
const SPOTS = [342, 512, 683];
const TRAILER = '\u0001';

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

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
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

function assertNoRawTail(text, tail, label) {
  const residue = text.split('[REDACTED]').join('');
  assert.equal(residue.includes(tail), false, `${label} kept ${tail}`);
  for (let n = 3; n <= tail.length; n += 1) {
    for (let i = 0; i + n <= tail.length; i += 1) {
      const window = tail.slice(i, i + n);
      assert.equal(residue.includes(window), false, `${label} kept ${window}`);
    }
  }
}

function inSegmentTail(path) {
  const dot = path.lastIndexOf('.');
  const slash = path.lastIndexOf('/');
  return dot > slash ? path.slice(0, dot) : path;
}

/** One `*` per path segment. Enough for the README and help attest globs. */
function filesMatching(dir, pattern) {
  const parts = pattern.split('/').filter((part) => part.length > 0);
  let current = [dir];
  for (const part of parts) {
    const star = part.indexOf('*');
    const next = [];
    for (const base of current) {
      let names = [];
      try {
        names = readdirSync(base);
      } catch {
        names = [];
      }
      for (const name of names) {
        let ok = name === part;
        if (star >= 0) {
          const pre = part.slice(0, star);
          const post = part.slice(star + 1);
          ok = name.startsWith(pre) && name.endsWith(post) && !name.slice(pre.length, name.length - post.length).includes('/');
        }
        if (ok) next.push(join(base, name));
      }
    }
    current = next;
  }
  return current.filter((file) => {
    try {
      return statSync(file).isFile();
    } catch {
      return false;
    }
  });
}

describe('v1.0.56 attest writes beside the receipt', () => {
  it('attest, attest last, and export --format intoto match the README and help glob', () => {
    const dir = gitRepo('ar1056-attest-');
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'attest location']).code, 0);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const receipt = latestReceipt(dir);
    const stem = receipt.slice(0, -3);
    const expected = `${stem}.intoto.jsonl`;

    function assertBeside(result, label) {
      assert.equal(result.code, 0, `${label} ${result.err}${result.out}`);
      const body = JSON.parse(result.out);
      assert.equal(body.path, expected, label);
      assert.equal(dirname(body.path), dirname(receipt), label);
      assert.equal(existsSync(body.path), true, label);
    }

    assertBeside(cli(dir, ['attest', receipt, '--json']), 'attest <receipt>');
    assertBeside(cli(dir, ['attest', 'last', '--json']), 'attest last');
    assertBeside(cli(dir, ['export', '--format', 'intoto', '--json']), 'export --format intoto');

    const loose = readdirSync(join(dir, '.agent-receipt')).filter((name) => name.endsWith('.intoto.jsonl'));
    assert.deepEqual(loose, []);

    const sub = join(dir, 'nested', 'src');
    mkdirSync(sub, { recursive: true });
    assertBeside(cli(sub, ['attest', 'last', '--json']), 'attest last from a subdirectory');

    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const readmeGlob = readme.match(/attest --verify (\.agent-receipt\/receipts\/\*\.intoto\.jsonl)/);
    assert.ok(readmeGlob, 'README attest --verify glob');
    const help = cli(root, ['help', 'attest']);
    assert.equal(help.code, 0, help.err);
    const helpExample = help.out.match(/attest --verify (\.agent-receipt\/receipts\/receipt\.intoto\.jsonl)/);
    assert.ok(helpExample, 'help attest --verify example');
    const helpGlob = helpExample[1].replace(/receipt\.intoto\.jsonl$/, '*.intoto.jsonl');

    for (const pattern of [readmeGlob[1], helpGlob]) {
      const hits = filesMatching(dir, pattern);
      assert.ok(hits.includes(expected), `${pattern} missed ${expected} (${hits.join(', ')})`);
    }
    const verified = cli(dir, ['attest', '--verify', expected, '--json']);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assert.equal(JSON.parse(verified.out).ok, true);
  });
});

describe('v1.0.56 mixed-case extension tails do not use the digit rule', () => {
  const leaks = ['/Ahs.ts', '/Qow.md', '/hnw/x.ts'];
  const kept = [
    '/ab.ts',
    '/a/b.js',
    '/App.md',
    '/README.md',
    '/src/app.ts',
    '+/src/app.ts',
    '/src/index',
    '/bin/run',
    '/home/runner/work/a/b.ts',
    '/scripts/deploy.sh',
    '/src/components/Button.tsx',
    '/src/utilities/format.ts',
  ];

  it('masks /Ahs.ts, /Qow.md, and /hnw/x.ts and keeps real paths', () => {
    for (const path of leaks) {
      const tail = inSegmentTail(path);
      assert.equal(/\d/.test(path), false, `${path} must not rely on the digit rule`);
      assert.ok(tail.length >= 3 && tail.length <= 7, tail);
    }
    for (const alg of RSA_ALGS) {
      for (const at of SPOTS) {
        for (const path of leaks) {
          const tail = inSegmentTail(path);
          const token = jwtFor(alg, `${'A'.repeat(at)}${tail}`);
          for (const mode of ['general', 'strict']) {
            const out = maskJwtTokens(`${token}${path.slice(tail.length)}${TRAILER}`, mode);
            assertNoRawTail(out, tail, `${alg} ${at} ${mode} ${path}`);
            assert.equal(out.includes('A'.repeat(8)), false, `${path} leaked signature`);
            assert.equal(out.includes(TRAILER), true, `${path} ate the trailer`);
          }
          const text = redactSecretsInText(`${token}${path.slice(tail.length)}${TRAILER}`);
          assertNoRawTail(text, tail, `${alg} ${at} text ${path}`);
        }
        const token = jwtFor(alg, 'A'.repeat(at));
        for (const path of kept) {
          for (const mode of ['general', 'strict']) {
            const out = maskJwtTokens(`${token}${path}${TRAILER}`, mode);
            assert.equal(out, `[REDACTED]${path}${TRAILER}`, `${alg} ${at} ${mode} ${path}`);
          }
          const text = redactSecretsInText(`${token}${path}${TRAILER}`);
          assert.equal(text, `[REDACTED]${path}${TRAILER}`, `${alg} ${at} text ${path}`);
          assert.equal(text.includes('A'.repeat(8)), false, `${path} leaked signature`);
        }
      }
    }
  });
});

describe('v1.0.56 receipt picker prefers the receipts root', () => {
  it('does not let a cwd-relative file shadow the root receipt', () => {
    const action = readFileSync(join(root, 'examples/github/action.yml'), 'utf8');
    const picker = action.match(/node -e '([^']*relativePath[^']*)'/)[1];
    assert.ok(picker, 'action receipt picker');
    assert.equal(picker.includes('else if(fs.existsSync(path.resolve(candidate)))'), false);

    const outer = keep(mkdtempSync(join(tmpdir(), 'ar1056-pick-')));
    const receipts = join(outer, '.agent-receipt', 'receipts');
    mkdirSync(receipts, { recursive: true });
    const receipt = join(receipts, 'plain.md');
    writeFileSync(
      receipt,
      appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Agent**: qa\n\nouter\n'),
    );
    const nested = join(outer, 'nested');
    mkdirSync(join(nested, '.agent-receipt', 'receipts'), { recursive: true });
    writeFileSync(join(nested, '.agent-receipt.yml'), 'outDir: elsewhere\n');
    const decoy = join(nested, '.agent-receipt', 'receipts', 'plain.md');
    writeFileSync(decoy, 'decoy\n');

    const shared = cli(nested, ['share', receipt, '--json']);
    assert.equal(shared.code, 0, shared.err + shared.out);
    const body = JSON.parse(shared.out);
    assert.equal(existsSync(join(nested, body.relativePath)), true, 'decoy occupies the cwd-relative path');
    assert.equal(readFileSync(join(nested, body.relativePath), 'utf8').includes('decoy'), true);

    const gateFile = join(outer, 'gate.json');
    writeFileSync(gateFile, shared.out);
    const picked = execFileSync(process.execPath, ['-e', picker, gateFile], {
      cwd: nested,
      encoding: 'utf8',
    }).trim();
    assert.equal(resolve(nested, picked), resolve(receipt), picked);
    assert.notEqual(resolve(nested, picked), resolve(decoy));
    const verified = cli(nested, ['verify', picked]);
    assert.equal(verified.code, 0, verified.err + verified.out);

    const looseDir = join(nested, 'notes');
    mkdirSync(looseDir, { recursive: true });
    writeFileSync(join(looseDir, 'loose.md'), 'loose\n');
    const looseGate = join(outer, 'loose-gate.json');
    writeFileSync(
      looseGate,
      JSON.stringify({ relativePath: 'notes/loose.md', path: 'notes/loose.md', ok: true, exitCode: 0 }),
    );
    const loosePicked = execFileSync(process.execPath, ['-e', picker, looseGate], {
      cwd: nested,
      encoding: 'utf8',
    }).trim();
    assert.equal(resolve(nested, loosePicked), join(looseDir, 'loose.md'), loosePicked);
  });
});
