/**
 * v1.0.61 — v1.0.60 Release QA follow-ups.
 * A low-entropy key body in a lone mid-body hunk is redacted with no findings.
 * A base64url or glued-path line does not end a truncated PEM block early.
 * Real paths after a JWT stay visible. Word-like random humps do not.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { maskJwtTokens, redactSecretsInText } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LINE64 = ALPHABET.slice(0, 64);
const NOTE = 'note: keep this visible';
const IDENT = 'thisIsAVeryLongCamelCaseIdentifierName';
const TRAILER = '\u0001';
const RSA_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
const SIG_SPOTS = [
  ['HS256', 43],
  ['HS384', 64],
  ['HS512', 86],
  ['ES256', 86],
  ['ES256K', 86],
  ['EdDSA', 86],
  ['EdDSA', 152],
  ['ES384', 128],
  ['ES512', 176],
  ['RS256', 342],
  ['RS256', 512],
  ['RS256', 683],
  ['PS256', 342],
  ['PS512', 512],
];

function b64url(text) {
  return Buffer.from(text).toString('base64url');
}

function jwtFor(alg, signature) {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'qa' }));
  return `${header}.${payload}.${signature}`;
}

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(1664525, state) + 1013904223) >>> 0;
    return state;
  };
}

function block(lines) {
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n`;
}

/** Standard-base64 signature of `len` with `+` and `/` inside the body. */
function mixedSig(len) {
  assert.ok(len >= 8);
  let body = '';
  while (body.length < len) body += ALPHABET;
  const chars = body.slice(0, len).split('');
  chars[3] = '+';
  chars[7] = '/';
  const sig = chars.join('');
  assert.equal(sig.length, len);
  assert.equal(sig.includes('+'), true);
  assert.equal(sig.includes('/'), true);
  return sig;
}

function loneHunk(path, lines) {
  return [
    `diff --git a/${path} b/${path}`,
    `--- a/${path}`,
    `+++ b/${path}`,
    ...lines,
    '',
  ].join('\n');
}

describe('v1.0.61 a low-entropy lone mid-body hunk is redacted', () => {
  const low = 'A'.repeat(64);
  const skewed = `Abcdefgh${'A'.repeat(56)}`;
  const edited = `${'A'.repeat(63)}B`;
  const ordinary = ['+hello', '-removed ordinary line', NOTE, IDENT];

  function hunk(body, context) {
    return loneHunk('key.pem', [
      `@@ -8,3 +8,4 @@ ${context}`,
      ` ${body}`,
      `-${body}`,
      `+${edited}`,
      '+hello',
      '-removed ordinary line',
      NOTE,
      IDENT,
    ]);
  }

  for (const body of [low, skewed]) {
    it(`redacts ${body.slice(0, 8)}… with no findings and keeps ordinary lines`, () => {
      const raw = hunk(body, body);
      assert.equal(raw.includes('PRIVATE KEY-----'), false);
      assert.equal(raw.includes('secret-looking-path'), false);
      assert.equal(raw.includes('high-entropy-secret'), false);
      const out = redactSecretsInText(raw);
      assert.equal(out.includes(body), false);
      assert.equal(out.includes(edited), false);
      assert.equal(out.includes('@@ -8,3 +8,4 @@ [REDACTED]'), true);
      assert.equal(out.includes(' [REDACTED]'), true);
      assert.equal(out.includes('-[REDACTED]'), true);
      assert.equal(out.includes('+[REDACTED]'), true);
      assert.equal(out.includes('--- a/key.pem'), true);
      assert.equal(out.includes('+++ b/key.pem'), true);
      for (const line of ordinary) assert.equal(out.includes(line), true, line);
    });
  }

  it('redacts a findings-free hunk the same way a findings table does', () => {
    const diff = hunk(low, low);
    const findings = [
      '| high | `secret-looking-path` | Secret-looking path (key / cert material): key.pem |',
      '',
    ].join('\n');
    const bare = redactSecretsInText(diff);
    const withFindings = redactSecretsInText(`${findings}${diff}`);
    assert.equal(bare.includes(low), false);
    assert.equal(withFindings.includes(low), false);
    assert.equal(bare.includes(edited), false);
    assert.equal(withFindings.includes(edited), false);
    assert.equal(bare.includes('@@ -8,3 +8,4 @@ [REDACTED]'), true);
    assert.equal(withFindings.includes('@@ -8,3 +8,4 @@ [REDACTED]'), true);
    assert.equal(bare.includes('+hello'), true);
    assert.equal(withFindings.includes('+hello'), true);
  });

  it('leaves a high-entropy bare key.pem hunk raw and keeps a readme line', () => {
    const high = LINE64;
    const readme = `R${'A'.repeat(63)}`;
    assert.equal(readme.length, 64);
    const diff = [
      loneHunk('key.pem', [
        `@@ -12,1 +12,1 @@ ${high}`,
        ` ${high}`,
        '+hello',
      ]).trimEnd(),
      loneHunk('readme.md', [
        '@@ -1 +1 @@',
        ` ${readme}`,
      ]).trimEnd(),
      '',
    ].join('\n');
    const out = redactSecretsInText(diff);
    assert.equal(out.includes(high), true);
    assert.equal(out.includes(readme), true);
    assert.equal(out.includes('+hello'), true);
    assert.equal(out.includes('--- a/key.pem'), true);
    assert.equal(out.includes('--- a/readme.md'), true);
  });
});

describe('v1.0.61 a dash, underscore, or glued path does not end a PEM block', () => {
  const body = 'B'.repeat(64);
  const later = 'C'.repeat(64);
  const tail = 'E'.repeat(64);
  const glued = [
    `${'C'.repeat(40)}/src/app.ts`,
    `${'C'.repeat(20)}src/App.tsx${'C'.repeat(24)}`,
    `./src/app.ts${'D'.repeat(52)}`,
    `${'-'.repeat(0)}${'C'.repeat(63)}-`.replace(/^/, ''),
  ];
  const edges = [
    `-${'C'.repeat(63)}`,
    `${'C'.repeat(63)}-`,
    `_${'C'.repeat(63)}`,
    `${'C'.repeat(63)}_`,
    `${'C'.repeat(20)}-${'C'.repeat(43)}`,
    `${'C'.repeat(20)}_${'C'.repeat(43)}`,
    'Ab-_'.repeat(16),
    ...glued.slice(0, 3),
  ];

  for (const bad of edges) {
    it(`redacts through ${JSON.stringify(bad.slice(0, 24))}`, () => {
      assert.ok(bad.length >= 16);
      const out = redactSecretsInText(block([body, bad, later, tail, 'Next']));
      assert.equal(out.includes(body), false, 'first body');
      assert.equal(out.includes(bad), false, 'bridge');
      assert.equal(out.includes(later), false, 'later body');
      assert.equal(out.includes(tail), false, 'tail body');
      assert.equal(out.includes('Next'), true);
      assert.equal(out.includes('[REDACTED]'), true);
    });
  }

  for (const stop of ['/src/app.ts', '/src/components/Button.tsx', 'hello world', 'note: done']) {
    it(`stops at ${JSON.stringify(stop)} and keeps that line`, () => {
      const out = redactSecretsInText(block([body, stop, tail, 'Next']));
      assert.equal(out.includes(body), false);
      assert.equal(out.includes(stop), true);
      assert.equal(out.includes(tail), true);
      assert.equal(out.includes('Next'), true);
    });
  }

  it('keeps snake_case after a gap and after a resumed body line', () => {
    const snake = 'user_profile_settings_name';
    const gap = redactSecretsInText(block([LINE64, '', snake, 'Next']));
    assert.equal(gap.includes(snake), true);
    assert.equal(gap.includes(LINE64), false);
    assert.equal(gap.includes('Next'), true);
    const wide = redactSecretsInText(block([LINE64, '', LINE64, snake, 'Next']));
    assert.equal(wide.includes(snake), true);
    assert.equal(wide.includes(LINE64), false);
    assert.equal(wide.includes('Next'), true);
    const hex = redactSecretsInText(block([LINE64, '', IDENT, `${'ab'.repeat(24)}`, 'Next']));
    assert.equal(hex.includes(IDENT), true);
    assert.equal(hex.includes('ab'.repeat(24)), true);
  });
});

describe('v1.0.61 real paths after a JWT stay visible', () => {
  const paths = ['./src/app.ts', 'src/App.tsx', 'app/src/index.ts'];
  const masked = ['/Src.ts', '/App.ts', '/Bin.ts', '/App.md'];

  function check(alg, signature, path, stay) {
    const token = jwtFor(alg, signature);
    const raw = `${token}${path}${TRAILER}`;
    for (const mode of ['general', 'strict']) {
      const out = maskJwtTokens(raw, mode);
      const label = `${alg} ${signature.length} ${mode} ${path}`;
      assert.equal(out.includes(signature.slice(0, 12)), false, `${label} signature`);
      assert.equal(out.includes(TRAILER), true, label);
      if (stay) {
        assert.equal(out.includes(path), true, label);
        assert.equal(out.startsWith('[REDACTED]'), true, label);
      } else {
        assert.equal(out.includes(path), false, label);
        const stem = path.slice(0, path.lastIndexOf('.'));
        assert.equal(out.includes(stem), false, `${label} stem`);
      }
    }
  }

  it('keeps the three path shapes for standard-base64 signatures', () => {
    for (const [alg, len] of SIG_SPOTS) {
      const signature = mixedSig(len);
      for (const path of paths) check(alg, signature, path, true);
      for (const path of masked) check(alg, signature, path, false);
    }
  });

  it('keeps unslashed paths after a non-RSA all-A signature', () => {
    for (const [alg, len] of [['HS256', 43], ['HS384', 64], ['ES256', 86], ['EdDSA', 86], ['EdDSA', 152]]) {
      const signature = 'A'.repeat(len);
      for (const path of paths) check(alg, signature, path, true);
      for (const path of masked) check(alg, signature, path, false);
    }
  });

  it('does not split Ed448 at the Ed25519 length', () => {
    const signature = `${'A'.repeat(86)}/${'B'.repeat(65)}`;
    assert.equal(signature.length, 152);
    const raw = `${jwtFor('EdDSA', signature)}${TRAILER}`;
    const out = maskJwtTokens(raw);
    assert.equal(out.includes('A'.repeat(8)), false);
    assert.equal(out.includes('B'.repeat(8)), false);
    assert.equal(out.includes(TRAILER), true);
  });
});

describe('v1.0.61 word-like humps stay redacted and real identifiers stay', () => {
  const kept = `
getUserProfileById fetchAccountBalance handleWebSocketMsg dockerComposeFile webpackDevServer kubeletConfigPath
getUserProfileSettingsNow veryLongCamelCaseIdentifier parseJSONResponse HTTPServerConfig IdentifierValue16
renderReportHtml decodeJwtPayload parseYamlDocument uncommittedBadge canonicalizedBody
activePolicyRefs adapterBackupDir addEventListener addTrustedFingerprint allocateRelPaths
allowShareReceipt allowedHostValue createPersonalSite fetchUserSettings handleIncomingMessage
loadKubernetesConfig openDatabaseConnection parseConfigDocument readEnvironmentFile renderHtmlReport
saveUserPreferences sendWebSocketFrame startBackgroundWorker stopBackgroundWorker updateAccountBalance
validateUserSession writeAuditRecord dockerComposeService kubernetesDeployment postgresConnection
redisCacheClient webpackDevMiddleware eslintConfigPath typescriptProject getCustomerOrderById
fetchInvoiceDetails handlePaymentWebhook createCheckoutSession listRepositoryFiles readPackageManifest
writeCoverageReport computeFileChecksum normalizeRequestPath resolveModuleSpecifier formatErrorMessage
parseCommandArguments buildDependencyGraph collectTestResults publishReleaseNotes verifySignatureBlock
loadServiceAccount rotateSigningKey storeRefreshToken clearSessionCookie applySecurityPolicy
checkPermissionSet grantAccessToken revokeAccessToken renderDashboardView toggleFeatureFlag
indexedDBOpenRequest cryptoRandomUUID atobBase64Decode calculationResult graphqlResolverFn
downwardAPIVolume bulkheadIsolation
`.trim().split(/\s+/);
  const masked = ['encodeURIComponent', 'decodeURIComponent', 'abcDe12fghijklmn'];

  it('keeps 78 real identifiers after a gap and redacts them after a resumed body', () => {
    assert.equal(kept.length, 78);
    assert.equal(new Set(kept).size, 78);
    for (const name of kept) assert.ok(name.length >= 16, name);
    let eaten = 0;
    for (const name of kept) {
      const gap = redactSecretsInText(block([LINE64, '', name, 'Next']));
      if (!gap.includes(name) || gap.includes(LINE64) || !gap.includes('Next')) eaten += 1;
      const wide = redactSecretsInText(block([LINE64, '', LINE64, name, 'Next']));
      assert.equal(wide.includes(name), false, `wide ${name}`);
      assert.equal(wide.includes('Next'), true, `wide ${name}`);
      assert.equal(wide.includes(LINE64), false, `wide ${name}`);
    }
    assert.equal(eaten, 0);
    for (const name of masked) {
      const gap = redactSecretsInText(block([LINE64, '', name, 'Next']));
      assert.equal(gap.includes(name), false, name);
      assert.equal(gap.includes('Next'), true, name);
    }
  });

  it('seeded word-like camelCase humps stay redacted', () => {
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    const vowels = new Set(['a', 'e', 'i', 'o', 'u', 'y', 'w']);
    const next = lcg(0x1061a11);
    const hump = () => {
      const len = 2 + (next() % 7);
      let word = letters[next() % 26];
      let run = vowels.has(word) ? 0 : 1;
      while (word.length < len) {
        let ch = letters[next() % 26];
        const consonant = !vowels.has(ch);
        if (consonant && run >= 4) ch = 'a';
        word += ch;
        run = vowels.has(ch) ? 0 : run + 1;
      }
      if (word.length >= 5 && ![...word].some((ch) => vowels.has(ch))) {
        word = `${word.slice(0, word.length - 1)}a`;
      }
      return word;
    };
    let keptLines = 0;
    let drawn = 0;
    while (drawn < 2048) {
      const parts = [];
      let line = '';
      while (line.length < 16) {
        const word = hump();
        parts.push(word);
        const chunk = parts.length === 1 ? word : word[0].toUpperCase() + word.slice(1);
        line += chunk;
      }
      if (line.length > 19) continue;
      drawn += 1;
      assert.ok(parts.length >= 2, line);
      const out = redactSecretsInText(block([LINE64, '', line, 'Next']));
      if (out.includes(line)) keptLines += 1;
      assert.equal(out.includes(LINE64), false, line);
      assert.equal(out.includes('Next'), true, line);
    }
    assert.equal(drawn, 2048);
    assert.equal(keptLines, 0);
  });
});

describe('v1.0.61 changelog', () => {
  it('lists the v1.0.60 Release QA follow-ups without overclaiming', () => {
    const note = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    const entry = note.slice(note.indexOf('## [1.0.61]'), note.indexOf('## [1.0.60]'));
    assert.match(entry, /v1\.0\.60 Release QA follow-ups/);
    assert.match(entry, /low-entropy/);
    assert.match(entry, /findings/);
    assert.match(entry, /PEM/);
    assert.match(entry, /\.\/src\/app\.ts/);
    assert.match(entry, /src\/App\.tsx/);
    assert.match(entry, /app\/src\/index\.ts/);
    assert.match(entry, /word-like/);
    assert.match(entry, /npm publish, which is on hold/);
    assert.match(entry, /1\.0\.61/);
    assert.match(entry, /does not publish to npm/);
    assert.match(entry, /not a certificate authority/);
  });
});
