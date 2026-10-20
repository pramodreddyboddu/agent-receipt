/**
 * v1.0.52 — Release QA follow-ups from v1.0.51.
 * RSA splits use the longest length the segment reaches, ES256K and Ed448
 * have signature lengths, kid-only and whitespace headers are masked, and
 * a secret-shaped directory in the repo path is masked on display.
 */
import { describe, it, after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
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
import {
  maskJwtTokens,
  publishRedactedReceipt,
  redactMarkdownBody,
  redactSecretsInText,
} from '../dist/lib/redact.js';

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

function b64url(text) {
  return Buffer.from(text).toString('base64url');
}

function jwtFor(alg, signature) {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'qa' }));
  return `${header}.${payload}.${signature}`;
}

/** `marker` sits after `at`, inside a path-shaped tail, in a signature of `length`. */
function interiorSig(length, at, marker) {
  const glued = `/${marker}/src`;
  assert.ok(at + glued.length <= length, `${marker} does not fit in ${length}`);
  return `${'A'.repeat(at)}${glued}${'B'.repeat(length - at - glued.length)}`;
}

function assertSigGone(text, pieces, label) {
  for (const piece of pieces) {
    assert.equal(text.includes(piece), false, `${label} kept ${piece.slice(0, 32)}`);
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

describe('v1.0.52 RSA longest signature length', () => {
  const joiners = ['+', '/', '_', '='];
  const cases = [
    ['RS256', 342, null, 'Qa2048edge'],
    ['PS256', 342, null, 'Qa2048psxx'],
    ['RS256', 512, 342, 'QaLeak512xx'],
    ['PS384', 512, 342, 'QaLeak512ps'],
    ['RS512', 683, 342, 'QaLeak683xx'],
    ['PS512', 683, 512, 'QaLeak512in'],
    ['RS256', 683, 512, 'Qa4096at512'],
  ];

  for (const [alg, length, cut, marker] of cases) {
    const sig = cut === null
      ? `${marker}${'E'.repeat(length - marker.length)}`
      : interiorSig(length, cut, marker);
    const token = jwtFor(alg, sig);

    for (const joiner of joiners) {
      it(`masks ${alg} ${length} before ${JSON.stringify(joiner)} with no raw signature`, () => {
        const raw = `${token}${joiner}more-text`;
        for (const [label, out] of maskSurfaces(raw)) {
          assertSigGone(out, [marker, sig.slice(0, 24), token.split('.')[0]], `${alg} ${label}`);
        }
      });
    }
  }

  it('masks a 684-character RSA-4096 signature that ends with =', () => {
    const marker = 'QaPad684xxx';
    const body = interiorSig(683, 342, marker);
    const sig = `${body}=`;
    assert.equal(sig.length, 684);
    const raw = `${jwtFor('RS512', sig)}+afterpad`;
    for (const [label, out] of maskSurfaces(raw)) {
      assertSigGone(out, [marker, 'A'.repeat(24)], label);
      assert.equal(out.includes('+afterpad'), true, `${label} ate the trailer`);
    }
  });

  it('masks a realistic std-base64 RSA signature followed by + / _ =', () => {
    const sizes = [
      ['RS256', 256, 344],
      ['PS256', 384, 512],
      ['RS512', 512, 684],
    ];
    for (const [alg, bytes, chars] of sizes) {
      const sig = Buffer.alloc(bytes, 0xfb).toString('base64');
      assert.equal(sig.length, chars, alg);
      const piece = sig.slice(0, 16);
      for (const joiner of joiners) {
        const raw = `${jwtFor(alg, sig)}${joiner}std-tail`;
        for (const [label, out] of maskSurfaces(raw)) {
          assertSigGone(out, [piece], `${alg} ${joiner} ${label}`);
        }
      }
    }
  });

  it('still keeps a clear path at the exact RSA length', () => {
    const kept = [
      ['RS256', 342],
      ['PS256', 342],
      ['RS384', 512],
      ['PS384', 512],
      ['RS512', 683],
      ['PS512', 683],
    ];
    for (const [alg, length] of kept) {
      const raw = `${jwtFor(alg, 'A'.repeat(length))}/src/app.ts`;
      for (const mode of ['general', 'strict']) {
        assert.equal(maskJwtTokens(raw, mode), '[REDACTED]/src/app.ts', `${alg} ${mode}`);
      }
    }
  });
});

describe('v1.0.52 ES256K and Ed448 lengths', () => {
  it('keeps a clear path on an ES256K base64url signature', () => {
    const raw = `${jwtFor('ES256K', 'A'.repeat(86))}/src/app.ts`;
    for (const mode of ['general', 'strict']) {
      assert.equal(maskJwtTokens(raw, mode), '[REDACTED]/src/app.ts', mode);
    }
  });

  it('masks an ES256K standard-base64 signature and its == padding', () => {
    const sig = Buffer.alloc(64, 0xfb).toString('base64');
    assert.equal(sig.length, 88);
    assert.equal(sig.endsWith('=='), true);
    const raw = `${jwtFor('ES256K', sig)}+es256k-tail`;
    for (const [label, out] of maskSurfaces(raw)) {
      assertSigGone(out, [sig.slice(0, 16)], label);
    }
    const padded = `${jwtFor('ES256K', 'A'.repeat(86))}==tail`;
    assert.equal(maskJwtTokens(padded), '[REDACTED]tail');
  });

  it('keeps a clear path on Ed448 and does not split it at 86', () => {
    const kept = `${jwtFor('EdDSA', 'D'.repeat(152))}/src/app.ts`;
    assert.equal(maskJwtTokens(kept), '[REDACTED]/src/app.ts');
    assert.equal(maskJwtTokens(`${jwtFor('EdDSA', 'A'.repeat(86))}/src/app.ts`), '[REDACTED]/src/app.ts');

    const marker = 'QaEd448leak';
    const sig = interiorSig(152, 86, marker);
    const raw = `${jwtFor('EdDSA', sig)}+ed448-tail`;
    for (const [label, out] of maskSurfaces(raw)) {
      assertSigGone(out, [marker], label);
    }
  });

  it('keeps =text after Ed448 because 152 is 0 mod 4', () => {
    const token = jwtFor('EdDSA', 'D'.repeat(152));
    assert.equal(maskJwtTokens(`${token}=text`), '[REDACTED]=text');
    assert.equal(maskJwtTokens(`${token}==text`), '[REDACTED]==text');
    const std = Buffer.alloc(114, 0xfb).toString('base64');
    const url = Buffer.alloc(114, 0xfb).toString('base64url');
    assert.equal(std.length, 152);
    assert.equal(url.length, 152);
    assert.equal(std.includes('='), false);
    const raw = `${jwtFor('EdDSA', std)}/src/app.ts`;
    for (const [label, out] of maskSurfaces(raw)) {
      assertSigGone(out, [std.slice(0, 16)], label);
    }
  });
});

describe('v1.0.52 unusual JWT headers', () => {
  function tokenFrom(headerText, signature) {
    const payload = b64url(JSON.stringify({ sub: 'qa' }));
    return `${b64url(headerText)}.${payload}.${signature}`;
  }

  it('masks a kid-only header in general and strict mode', () => {
    const raw = tokenFrom('{"kid":"device-1"}', 'A'.repeat(43));
    for (const mode of ['general', 'strict']) {
      const out = maskJwtTokens(raw, mode);
      assert.equal(out, '[REDACTED]', mode);
      assert.equal(out.includes('device-1'), false, mode);
    }
    const glued = `${raw}/src/app.ts`;
    assert.equal(maskJwtTokens(glued, 'strict'), '[REDACTED].ts');
    assert.equal(maskJwtTokens(glued, 'general'), '[REDACTED].ts');
  });

  it('uses alg when it comes after kid and keeps a matching path', () => {
    const raw = `${tokenFrom('{"kid":"device-1","alg":"HS256"}', 'A'.repeat(43))}/src/app.ts`;
    for (const mode of ['general', 'strict']) {
      assert.equal(maskJwtTokens(raw, mode), '[REDACTED]/src/app.ts', mode);
    }
  });

  it('masks whitespace JSON headers and still uses alg for the split', () => {
    const headers = [
      '{ "alg": "HS256" }',
      '{  "alg": "HS256"}',
      '{\n"alg":"HS256"\n}',
      '{\r"alg":"HS256"\r}',
      '{\t"alg":"HS256"\t}',
    ];
    const prefixes = ['eyA', 'eyA', 'ewo', 'ew0', 'ewk'];
    headers.forEach((header, i) => {
      const encoded = b64url(header);
      assert.equal(encoded.startsWith(prefixes[i]), true, header);
      const raw = `${tokenFrom(header, 'A'.repeat(43))}/src/app.ts`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(raw, mode);
        assert.equal(out, '[REDACTED]/src/app.ts', `${header} ${mode} ${out}`);
      }
    });
  });

  it('masks a spaced header after a long eyA- run', () => {
    const token = tokenFrom('{ "alg": "none" }', '');
    assert.equal(b64url('{ "alg": "none" }').startsWith('eyA'), true);
    const raw = `${'eyA-'.repeat(30)}${token}`;
    for (const mode of ['general', 'strict']) {
      const out = maskJwtTokens(raw, mode);
      assert.equal(out.includes(token.split('.')[0]), false, mode);
      assert.equal(out.includes('[REDACTED]'), true, mode);
    }
  });

  it('leaves non-JWT base64 and typ-only strict tokens alone', () => {
    const untouched = [
      'eyJsee.the.docs',
      'version 1.2.3 and 10.20.30',
      tokenFrom('{ "note": "hello" }', 'A'.repeat(43)),
      'eyAaaa.bbbb.cccc',
      `${b64url('hello world!!')}.${b64url('not a header')}.${b64url('still text')}`,
      tokenFrom('{ "kid": "" }', 'A'.repeat(43)),
      tokenFrom('{"kid":1,"note":"hello"}', 'A'.repeat(43)),
    ];
    for (const raw of untouched) {
      assert.equal(maskJwtTokens(raw, 'general'), raw, raw.slice(0, 40));
      assert.equal(maskJwtTokens(raw, 'strict'), raw, raw.slice(0, 40));
      assert.equal(redactSecretsInText(raw), raw, raw.slice(0, 40));
    }

    const typOnly = tokenFrom('{"typ":"JWT"}', 'A'.repeat(43));
    assert.equal(maskJwtTokens(typOnly, 'general'), '[REDACTED]');
    assert.equal(maskJwtTokens(typOnly, 'strict'), typOnly);

    const emptyKidTyp = tokenFrom('{"kid":"","typ":"JWT"}', 'A'.repeat(43));
    assert.equal(maskJwtTokens(emptyKidTyp, 'general'), '[REDACTED]');
    assert.equal(maskJwtTokens(emptyKidTyp, 'strict'), emptyKidTyp);
  });

  it('scans a mixed header-prefix run in well under five seconds', () => {
    const unit = 'eyA-eyJ-ewo-ew0-ewk-';
    const input = unit.repeat(Math.ceil((1.5 * 1024 * 1024) / unit.length)) + '.payload.sig';
    const started = Date.now();
    const out = redactSecretsInText(input);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 5000, `mixed header scan took ${elapsed}ms`);
    assert.equal(out.includes('[REDACTED]'), false);
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

describe('v1.0.52 RSA signatures on every redaction surface', () => {
  it('leaves no raw signature substring on receipt display, attest, share, html, and report', () => {
    const dir = gitRepo('ar1052-jwt-');
    const marker = 'QaLeak512xx';
    const sig = interiorSig(512, 342, marker);
    const rs = jwtFor('RS256', sig);
    const ps = jwtFor('PS256', sig);
    const long = interiorSig(683, 342, 'QaLeak683xx');
    const at512 = interiorSig(683, 512, 'QaLeak512in');
    const edge = `${'Qa2048edge'}${'E'.repeat(342 - 'Qa2048edge'.length)}`;
    const parts = [
      `${rs}+more512`,
      `${ps}/more512`,
      `${jwtFor('RS512', long)}_more683`,
      `${jwtFor('RS512', `${long}=`)}=morepad`,
      `${jwtFor('PS512', at512)}+moreat`,
    ];
    for (const joiner of ['+', '/', '_', '=']) {
      parts.push(`${jwtFor('RS256', edge)}${joiner}tail2048`);
    }
    const note = parts.join(' ');
    const markers = ['QaLeak512xx', 'QaLeak683xx', 'QaLeak512in', 'Qa2048edge'];

    writeFileSync(join(dir, 'token.txt'), `${note}\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', note]).code, 0);

    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(marker), true, 'stored receipt stays raw');

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
      gone(result.out, label);
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

describe('v1.0.52 secret-shaped repo path', () => {
  const secret = `ghp_${'b'.repeat(36)}`;
  let parent;
  let repo;
  let bare;

  before(() => {
    parent = keep(mkdtempSync(join(tmpdir(), 'ar1052-path-')));
    repo = join(parent, secret, 'repo');
    bare = join(parent, secret, 'not-a-repo');
    mkdirSync(repo, { recursive: true });
    mkdirSync(bare, { recursive: true });
    git(repo, ['init', '-b', 'main']);
    git(repo, ['config', 'user.email', 'test@example.com']);
    git(repo, ['config', 'user.name', 'Test']);
    git(repo, ['config', 'commit.gpgsign', 'false']);
    writeFileSync(join(repo, 'README.md'), '# qa\n');
    git(repo, ['add', 'README.md']);
    git(repo, ['commit', '-m', 'initial']);
    assert.equal(cli(repo, ['init']).code, 0);
    assert.equal(cli(repo, ['capture', '--agent', 'cursor', '--message', 'one']).code, 0);
    writeFileSync(join(repo, 'README.md'), '# qa\n\nnext\n');
    git(repo, ['add', 'README.md']);
    git(repo, ['commit', '-m', 'second']);
    assert.equal(cli(repo, ['capture', '--agent', 'cursor', '--message', 'two']).code, 0);
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

  it('compare masks the repo path', () => {
    const result = cli(repo, ['compare']);
    assert.equal(result.code, 0, result.err + result.out);
    assertMasked(result, 'compare');
  });

  it('prove masks the repo path in plain output, JSON, and the page', () => {
    const plain = cli(repo, ['prove']);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assertMasked(plain, 'prove');

    const receipt = latestReceipt(repo);
    const json = cli(repo, ['prove', '--page', '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assertMasked(json, 'prove --json');
    const body = JSON.parse(json.out);
    assert.equal(body.path.includes('ghp_[REDACTED]'), true);
    assert.equal(body.pagePath.includes('ghp_[REDACTED]'), true);
    const page = readFileSync(receipt.replace(/\.md$/i, '.prove.md'), 'utf8');
    assert.equal(page.includes(secret), false);
    assert.equal(page.includes('ghp_[REDACTED]'), true);
  });

  it('doctor masks the repo path in plain output and JSON details', () => {
    const plain = cli(repo, ['doctor']);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assertMasked(plain, 'doctor');

    const json = cli(repo, ['doctor', '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assert.equal(blob(json).includes(secret), false, 'doctor json');
    assert.equal(blob(json).includes('b'.repeat(36)), false);

    const bareJson = cli(bare, ['doctor', '--json']);
    assert.equal(bareJson.code, 1, bareJson.out);
    assertMasked(bareJson, 'doctor json outside a repo');
  });

  it('audit masks the repo path in plain output and JSON', () => {
    const plain = cli(repo, ['audit']);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assertMasked(plain, 'audit');
    const json = cli(repo, ['audit', '--verify', '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assertMasked(json, 'audit --json');
    const log = readFileSync(join(repo, '.agent-receipt', 'audit.jsonl'), 'utf8');
    assert.equal(log.includes(secret), false);
    assert.equal(log.includes('ghp_[REDACTED]'), false);
  });

  it('log masks the repo path in plain output and JSON', () => {
    const plain = cli(repo, ['log']);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assertMasked(plain, 'log');
    const json = cli(repo, ['log', '--verify', '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assertMasked(json, 'log --json');
  });

  it('share masks the repo path in plain output, JSON, and the written HTML', () => {
    const receipt = latestReceipt(repo);
    const plain = cli(repo, ['share', receipt]);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assertMasked(plain, 'share');
    const html = readFileSync(receipt.replace(/\.md$/i, '.html'), 'utf8');
    assert.equal(html.includes(secret), false);
    assert.equal(html.includes('ghp_[REDACTED]'), true);

    const json = cli(repo, ['share', receipt, '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    assertMasked(json, 'share --json');
    const body = JSON.parse(json.out);
    assert.equal(body.path.includes('ghp_[REDACTED]'), true);
    assert.equal(body.htmlPath.includes('ghp_[REDACTED]'), true);
  });

  it('html masks the repo path in plain output', () => {
    const receipt = latestReceipt(repo);
    const out = join(repo, 'plain.html');
    const result = cli(repo, ['html', receipt, '--out', out]);
    assert.equal(result.code, 0, result.err + result.out);
    assertMasked(result, 'html');
  });

  it('report masks the repo path in plain output and JSON', () => {
    const receipt = latestReceipt(repo);
    const plain = cli(repo, ['report', receipt, '--out', join(repo, 'path-report.html')]);
    assert.equal(plain.code, 0, plain.err + plain.out);
    assertMasked(plain, 'report');
    const page = readFileSync(join(repo, 'path-report.html'), 'utf8');
    assert.equal(page.includes(secret), false);

    const json = cli(repo, ['report', receipt, '--json', '--out', join(repo, 'path-report-json.html')]);
    assert.equal(json.code, 0, json.err + json.out);
    assertMasked(json, 'report --json');
    const body = JSON.parse(json.out);
    assert.equal(body.htmlPath.includes('ghp_[REDACTED]'), true);
  });

  it('leaves last --path raw', () => {
    const result = cli(repo, ['last', '--path']);
    assert.equal(result.code, 0, result.err);
    assert.equal(result.out.includes(secret), true);
  });
});
