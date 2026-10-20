/**
 * v1.0.54 — Release QA follow-ups from v1.0.53.
 * Subdirectory relativePath, gate schema relativePath, odd RSA runs,
 * and CR-only verify.
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
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  appendHashFooter,
  hasTrailingAfterIntegrity,
  verifyMarkdown,
} from '../dist/lib/hash.js';
import { maskJwtTokens, redactSecretsInText } from '../dist/lib/redact.js';

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

/** Odd-run tail that looks like a path and used to stay visible. */
function leakTail(len, joiner, kind) {
  const core = kind === 'upper'
    ? (joiner === '+' ? '+Ab/cdef' : '/Ab/cdef')
    : (joiner === '+' ? '+bcdefghi/src' : '/bcdefghi/src');
  assert.ok(core.length <= len, `${kind} ${joiner} core ${core.length} > ${len}`);
  const pad = kind === 'upper' ? 'B' : 'x';
  return core + pad.repeat(len - core.length);
}

function assertNoSignatureWindows(text, signature, at, label) {
  const start = Math.max(0, at - 7);
  for (let i = start; i + 8 <= signature.length; i += 1) {
    const window = signature.slice(i, i + 8);
    assert.equal(text.includes(window), false, `${label} kept ${window}`);
  }
}

describe('v1.0.54 odd RSA runs redact the whole tail', () => {
  const spots = [342, 512, 683];
  const tails = [8, 24, 48];

  for (const alg of RSA_ALGS) {
    for (const at of spots) {
      for (const joiner of ['/', '+']) {
        for (const len of tails) {
          for (const kind of ['upper', 'mixed']) {
            if (kind === 'mixed' && len < 13) continue;
            it(`masks ${alg} ${joiner} at ${at} tail ${len} ${kind}`, () => {
              const tail = leakTail(len, joiner, kind);
              assert.equal(tail.length, len);
              const signature = `${'A'.repeat(at)}${tail}`;
              const token = jwtFor(alg, signature);
              for (const mode of ['general', 'strict']) {
                const out = maskJwtTokens(`${token} tail`, mode);
                assertNoSignatureWindows(out, signature, at, `${alg} ${mode}`);
                assert.equal(out.includes(tail), false, `${mode} kept the tail`);
                assert.equal(out.includes(' tail'), true, `${mode} ate the trailer`);
              }
              const text = redactSecretsInText(`${token} tail`);
              assertNoSignatureWindows(text, signature, at, `${alg} text`);
            });
          }
        }
      }
    }
  }

  it('still keeps a clear path and a 48-character repeated path', () => {
    for (const [alg, length] of [['RS256', 342], ['PS384', 512], ['RS512', 683]]) {
      const token = jwtFor(alg, 'A'.repeat(length));
      assert.equal(maskJwtTokens(`${token}/src/app.ts`), '[REDACTED]/src/app.ts', alg);
      assert.equal(maskJwtTokens(`${token}+src/app.ts`), '[REDACTED]+src/app.ts', alg);
      assert.equal(maskJwtTokens(`${token}+/src/app.ts`), '[REDACTED]+/src/app.ts', alg);
      const keep = `/${'a'.repeat(46)}/`;
      assert.equal(keep.length, 48);
      assert.equal(maskJwtTokens(`${token}${keep}`), `[REDACTED]${keep}`, alg);
      const eat = `/${'b'.repeat(47)}/`;
      const eaten = maskJwtTokens(`${token}${eat}`);
      assert.equal(eaten.includes(eat), false, alg);
      assert.equal(eaten.includes('b'.repeat(8)), false, alg);
    }
  });
});

describe('v1.0.54 odd RSA runs on every redaction surface', () => {
  it('leaves no raw signature substring of 8 or more characters', () => {
    const dir = gitRepo('ar1054-jwt-');
    const samples = [
      ['RS256', 342, '/', 8, 'upper'],
      ['PS256', 342, '+', 24, 'mixed'],
      ['RS384', 512, '/', 48, 'upper'],
      ['PS384', 512, '+', 24, 'upper'],
      ['RS512', 683, '/', 16, 'mixed'],
      ['PS512', 683, '+', 48, 'mixed'],
    ];
    const signatures = [];
    const parts = [];
    for (const [alg, at, joiner, len, kind] of samples) {
      const tail = leakTail(len, joiner, kind);
      const signature = `${'A'.repeat(at)}${tail}`;
      signatures.push({ signature, at, tail });
      parts.push(jwtFor(alg, signature));
    }
    const note = parts.join(' ');
    writeFileSync(join(dir, 'token.txt'), `${note}\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', note]).code, 0);
    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(signatures[0].tail), true, 'stored receipt stays raw');

    function gone(text, label) {
      for (const { signature, at, tail } of signatures) {
        assertNoSignatureWindows(text, signature, at, label);
        assert.equal(text.includes(tail), false, `${label} kept ${tail.slice(0, 24)}`);
      }
    }

    const surfaces = [
      ['show', ['show', storedPath]],
      ['last', ['last']],
      ['last --json', ['last', '--json']],
      ['compare', ['compare']],
      ['share', ['share', storedPath]],
      ['share --json', ['share', storedPath, '--json']],
      ['prove', ['prove', storedPath]],
      ['prove --json', ['prove', storedPath, '--json']],
      ['verify', ['verify', storedPath]],
      ['verify --json', ['verify', storedPath, '--json']],
    ];
    for (const [label, args] of surfaces) {
      const result = cli(dir, args);
      assert.equal(result.code, 0, `${label} ${result.err}${result.out}`);
      gone(result.out + result.err, label);
    }
    const show = cli(dir, ['show', storedPath]);
    assert.match(show.out, /\[REDACTED\]/);

    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = cli(dir, ['attest', storedPath, '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    gone(created.out + created.err, 'attest --json');
    const attestPath = JSON.parse(created.out).path;
    const statement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(attestPath, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    gone(JSON.stringify(statement), 'attest statement');
    const plainAttest = cli(dir, ['attest', storedPath]);
    assert.equal(plainAttest.code, 0, plainAttest.err + plainAttest.out);
    gone(plainAttest.out + plainAttest.err, 'attest');

    const shareHtml = storedPath.replace(/\.md$/i, '.html');
    gone(readFileSync(shareHtml, 'utf8'), 'share html');
  });
});

describe('v1.0.54 share then verify from a subdirectory', () => {
  it('resolves relativePath from a nested directory and from the example picker', () => {
    const secret = `ghp_${'d'.repeat(36)}`;
    const parent = keep(mkdtempSync(join(tmpdir(), 'ar1054-sub-')));
    const dir = join(parent, secret, 'repo');
    mkdirSync(dir, { recursive: true });
    git(dir, ['init', '-b', 'main']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    git(dir, ['config', 'commit.gpgsign', 'false']);
    writeFileSync(join(dir, 'README.md'), '# qa\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    assert.equal(cli(dir, ['init']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'subdir']).code, 0);
    const receipt = latestReceipt(dir);
    const sub = join(dir, 'nested', 'deeper');
    mkdirSync(sub, { recursive: true });

    const shared = cli(sub, ['share', receipt, '--json']);
    assert.equal(shared.code, 0, shared.err + shared.out);
    const body = JSON.parse(shared.out);
    assert.equal(typeof body.relativePath, 'string');
    assert.equal(existsSync(join(dir, body.relativePath)), true);
    assert.equal(existsSync(join(sub, body.relativePath)), false);
    assert.equal(body.path.includes(secret), false);
    assert.equal(body.relativePath.includes(secret), false);

    const verified = cli(sub, ['verify', body.relativePath]);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assert.match(verified.out, /OK/);
    const shown = verified.out + verified.err;
    assert.equal(shown.includes(secret), false, shown);
    assert.equal(shown.includes('d'.repeat(36)), false, shown);

    const json = cli(sub, ['verify', body.relativePath, '--json']);
    assert.equal(json.code, 0, json.err + json.out);
    const gate = JSON.parse(json.out);
    assert.equal(gate.verified, true);
    assert.equal(gate.path.includes(secret), false);
    assert.equal(JSON.stringify(gate).includes(secret), false);

    const action = readFileSync(join(root, 'examples/github/action.yml'), 'utf8');
    const picker = action.match(/node -e '([^']*relativePath[^']*)'/)[1];
    assert.ok(picker, 'action picker');
    const gateFile = join(dir, 'share-gate.json');
    writeFileSync(gateFile, shared.out);
    const picked = execFileSync(process.execPath, ['-e', picker, gateFile], {
      cwd: sub,
      encoding: 'utf8',
    });
    assert.equal(existsSync(join(sub, picked)), true, picked);
    assert.equal(picked.includes(secret), false, picked);
    const pickedVerify = cli(sub, ['verify', picked]);
    assert.equal(pickedVerify.code, 0, pickedVerify.err + pickedVerify.out);

    const fromRoot = execFileSync(process.execPath, ['-e', picker, gateFile], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(fromRoot, body.relativePath);

    const pr = readFileSync(join(root, 'examples/github/pr-gate.yml'), 'utf8');
    const stageAt = pr.indexOf("          const fs = require('fs');");
    const stageEnd = pr.indexOf('\n          NODE', stageAt);
    assert.ok(stageAt > 0 && stageEnd > stageAt);
    const stageScript = pr.slice(stageAt, stageEnd).replace(/^ {10}/gm, '');
    const stage = join(dir, 'stage');
    mkdirSync(stage, { recursive: true });
    const staged = execFileSync(process.execPath, ['-', gateFile, stage], {
      cwd: sub,
      encoding: 'utf8',
      input: stageScript,
    });
    assert.match(staged, /staged /);
    assert.equal(existsSync(join(stage, staged.replace(/^staged\s+/, '').trim())), true);
  });

  it('resolves a receipt against the receipts root when not in git', () => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'ar1054-nogit-')));
    const receipts = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(receipts, { recursive: true });
    const receipt = join(receipts, 'plain.md');
    writeFileSync(
      receipt,
      appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Agent**: qa\n\nhello\n'),
    );
    const sub = join(dir, 'nested', 'deeper');
    mkdirSync(sub, { recursive: true });
    const rel = '.agent-receipt/receipts/plain.md';
    assert.equal(existsSync(join(sub, rel)), false);
    const verified = cli(sub, ['verify', rel]);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assert.match(verified.out, /OK/);
  });
});

function schemaTypes(schema) {
  if (!schema.type) return null;
  return Array.isArray(schema.type) ? schema.type : [schema.type];
}

function typeMatches(value, type) {
  if (type === 'null') return value === null;
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (type === 'integer') return typeof value === 'number' && Number.isInteger(value);
  if (type === 'number') return typeof value === 'number';
  if (type === 'string') return typeof value === 'string';
  if (type === 'boolean') return typeof value === 'boolean';
  return false;
}

function validateSchema(value, schema, path, errors) {
  if (schema.anyOf) {
    const nested = [];
    const ok = schema.anyOf.some((branch) => {
      const local = [];
      validateSchema(value, branch, path, local);
      if (local.length === 0) return true;
      nested.push(...local);
      return false;
    });
    if (!ok) errors.push(`${path} anyOf ${nested.join('; ')}`);
    return;
  }
  const types = schemaTypes(schema);
  if (types && !types.some((type) => typeMatches(value, type))) {
    errors.push(`${path} type ${types.join('|')}`);
    return;
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${path} enum`);
    return;
  }
  if (typeof value === 'string' && schema.pattern && !new RegExp(schema.pattern).test(value)) {
    errors.push(`${path} pattern`);
  }
  if (typeof value === 'number' && typeof schema.minimum === 'number' && value < schema.minimum) {
    errors.push(`${path} minimum`);
  }
  if (Array.isArray(value)) {
    if (schema.items) {
      value.forEach((item, index) => validateSchema(item, schema.items, `${path}[${index}]`, errors));
    }
    return;
  }
  if (value && typeof value === 'object' && schema.properties) {
    if (schema.required) {
      for (const key of schema.required) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) errors.push(`${path}.${key} required`);
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(schema.properties, key)) {
          errors.push(`${path}.${key} additional`);
        }
      }
    }
    for (const [key, prop] of Object.entries(schema.properties)) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        validateSchema(value[key], prop, `${path}.${key}`, errors);
      }
    }
  }
}

describe('v1.0.54 gate schema declares relativePath', () => {
  it('validates share and gate JSON against the shipped schema', () => {
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'gate.schema.json'), 'utf8'));
    assert.equal(schema.additionalProperties, false);
    assert.ok(schema.properties.relativePath);
    assert.deepEqual(schema.properties.relativePath.type, ['string', 'null']);
    assert.equal(schema.required.includes('relativePath'), false);

    const dir = gitRepo('ar1054-schema-');
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'schema']).code, 0);
    const wrapped = cli(dir, ['wrap', '--json']);
    assert.equal(wrapped.code, 0, wrapped.err + wrapped.out);
    const shared = cli(dir, ['share', '--json']);
    assert.equal(shared.code, 0, shared.err + shared.out);
    const verified = cli(dir, ['verify', '--json']);
    assert.equal(verified.code, 0, verified.err + verified.out);

    const shareBody = JSON.parse(shared.out);
    const wrapBody = JSON.parse(wrapped.out);
    const verifyBody = JSON.parse(verified.out);
    assert.equal(typeof shareBody.relativePath, 'string');
    assert.equal(Object.prototype.hasOwnProperty.call(wrapBody, 'relativePath'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(verifyBody, 'relativePath'), false);

    for (const [label, body] of [['share', shareBody], ['wrap', wrapBody], ['verify', verifyBody]]) {
      const errors = [];
      validateSchema(body, schema, label, errors);
      assert.deepEqual(errors, [], `${label} ${errors.join(', ')}`);
    }

    const v1052 = structuredClone(schema);
    delete v1052.properties.relativePath;
    const rejected = [];
    validateSchema(shareBody, v1052, 'v1.0.52', rejected);
    assert.ok(rejected.some((item) => item.includes('relativePath')), rejected.join(', '));
  });
});

describe('v1.0.54 CR-only and CRLF verify', () => {
  const sealed = appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Agent**: qa\n\nhello\n');

  it('verifies CR-only and CRLF the same way as LF', () => {
    assert.equal(verifyMarkdown(sealed).ok, true);
    const cr = sealed.replace(/\n/g, '\r');
    const crlf = sealed.replace(/\n/g, '\r\n');
    assert.equal(cr.includes('\n'), false);
    assert.equal(verifyMarkdown(cr).ok, true);
    assert.equal(hasTrailingAfterIntegrity(cr), false);
    assert.equal(verifyMarkdown(crlf).ok, true);
    assert.equal(hasTrailingAfterIntegrity(crlf), false);

    const lone = appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Message**: pre\rmid\n\nhello\n');
    assert.equal(verifyMarkdown(lone).ok, true);
    assert.equal(verifyMarkdown(lone.replace(/\r/g, '')).ok, false);
  });

  it('keeps the trailing-content fail-closed rule for CR-only and CRLF', () => {
    const dir = keep(mkdtempSync(join(tmpdir(), 'ar1054-cr-')));
    const receipt = join(dir, 'receipt.md');
    const cr = sealed.replace(/\n/g, '\r');
    const crlf = sealed.replace(/\n/g, '\r\n');

    function check(text, code, trailing) {
      writeFileSync(receipt, text);
      const result = cli(dir, ['verify', receipt, '--json']);
      assert.equal(result.code, code, result.err + result.out);
      const body = JSON.parse(result.out);
      assert.equal(body.trailingIgnored, trailing);
      assert.equal(body.verified, code === 0);
      if (code === 2) {
        assert.match(body.reason, /trailing content after the last chained record/);
        assert.equal(body.reason.includes('Hash mismatch'), false);
      }
    }

    check(cr, 0, false);
    check(crlf, 0, false);
    check(`${cr}\r \t\r`, 0, false);
    check(`${crlf}\r\n \t\r\n`, 0, false);
    check(`${cr}\rnot a footer\r`, 2, true);
    check(`${crlf}\r\nnot a footer\r\n`, 2, true);
    check(`${cr}\u00A0`, 2, true);
    check(`${crlf}\u00A0`, 2, true);
    check(`${sealed}\u2028`, 2, true);
    check(`${sealed}\uFEFF`, 2, true);
  });
});
