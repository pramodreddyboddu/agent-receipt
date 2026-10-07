import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createPublicKey, generateKeyPairSync, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import { createServer } from 'node:http';
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCertificate } from '../dist/lib/sigstore/x509.js';
import { BUNDLE_MEDIA_TYPE, canonicalIntotoBody } from '../dist/lib/sigstore/keyless.js';
import { buildCheckpoint, leafHash, logIdForKey, signEntryTimestamp } from '../dist/lib/sigstore/tlog.js';
import { redactSecretsInText } from '../dist/lib/redact.js';
import { redactArgsValue } from '../dist/lib/adapters/parse-common.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const ISS = 'https://token.actions.githubusercontent.com';
const AKIA = 'AKIAIOSFODNN7EXAMPLE';
const FILE_SUB = 'https://github.com/file/actor';
const ENV_SUB = 'https://github.com/env/actor';
const ACTIONS_SUB = 'https://github.com/actions/actor';
const FILE_MARKER = 'token-file-marker-1033';
const ENV_MARKER = 'token-env-marker-1033';
const ACTIONS_MARKER = 'token-actions-marker-1033';
const EXPIRED_MARKER = 'token-expired-marker-1033';
const REQUEST_TOKEN = 'actions-request-token-1033';

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

function cli(cwd, args, extra = {}) {
  const env = { ...process.env, NO_COLOR: '1' };
  delete env.SIGSTORE_ID_TOKEN;
  delete env.ACTIONS_ID_TOKEN_REQUEST_URL;
  delete env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  delete env.AGENT_RECEIPT_SIGSTORE_TIMEOUT_MS;
  Object.assign(env, extra.env || {});
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...args], {
      cwd,
      env,
      timeout: extra.timeout,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
    });
    child.on('close', (code, signal) => {
      resolve({ code: code ?? 1, out, err, signal });
    });
    child.on('error', (error) => {
      resolve({ code: 1, out, err: `${err}${error.message}`, signal: null });
    });
    if (extra.input !== undefined) child.stdin.end(extra.input);
    else child.stdin.end();
  });
}

async function gitRepo() {
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1033-')));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# keyless\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  assert.equal((await cli(dir, ['init'])).code, 0);
  return dir;
}

function listFiles(dir) {
  const out = [];
  const walk = (current) => {
    for (const name of readdirSync(current)) {
      const abs = join(current, name);
      const st = statSync(abs);
      if (st.isDirectory()) walk(abs);
      else if (st.isFile()) out.push(relative(dir, abs));
    }
  };
  walk(dir);
  return out.sort();
}

function treeText(dir) {
  return listFiles(dir).map((rel) => readFileSync(join(dir, rel), 'utf8')).join('\n');
}

function jwt(sub, marker, exp) {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({
    sub,
    iss: ISS,
    aud: 'sigstore',
    exp: exp ?? Math.floor(Date.now() / 1000) + 600,
  })).toString('base64url');
  return `${header}.${body}.${marker}`;
}

function wideWindow() {
  return {
    notBefore: new Date(Date.now() - 3 * 86400000),
    notAfter: new Date(Date.now() + 30 * 86400000),
  };
}

const window = wideWindow();
const rootKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const intermediateKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const rekorKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const otherKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

function caCert(key, subject, issuer, signer) {
  return buildCertificate({
    subjectCn: subject,
    issuerCn: issuer,
    publicKey: key.publicKey,
    signer,
    notBefore: window.notBefore,
    notAfter: window.notAfter,
    isCa: true,
  });
}

const rootDer = caCert(rootKey, 'test-root', 'test-root', rootKey.privateKey);
const intDer = caCert(intermediateKey, 'test-intermediate', 'test-root', rootKey.privateKey);
const otherDer = caCert(otherKey, 'other-root', 'other-root', otherKey.privateKey);
const logId = logIdForKey(rekorKey.publicKey);

function trustedRoot(certs) {
  const spki = rekorKey.publicKey.export({ type: 'spki', format: 'der' });
  return {
    mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
    certificateAuthorities: [{
      certChain: { certificates: certs.map((der) => ({ rawBytes: der.toString('base64') })) },
    }],
    tlogs: [{
      baseUrl: 'https://rekor.test.local',
      hashAlgorithm: 'SHA2_256',
      publicKey: { rawBytes: Buffer.from(spki).toString('base64') },
      logId: { keyId: logId.toString('base64') },
    }],
  };
}

const trustDir = keep(mkdtempSync(join(tmpdir(), 'ar1033-trust-')));
const trustPath = join(trustDir, 'trusted_root.json');
const otherTrustPath = join(trustDir, 'other_root.json');
writeFileSync(trustPath, JSON.stringify(trustedRoot([intDer, rootDer])));
writeFileSync(otherTrustPath, JSON.stringify(trustedRoot([otherDer])));

function startMock(options = {}) {
  const state = {
    fulcioStatus: 0,
    rekorStatus: 0,
    hang: false,
    notBefore: window.notBefore,
    notAfter: window.notAfter,
    integratedTime: Math.floor(Date.now() / 1000),
    actionsToken: jwt(ACTIONS_SUB, ACTIONS_MARKER),
    fulcioHits: 0,
    rekorHits: 0,
    tokens: [],
    actionsUrls: [],
    actionsAuth: [],
    ...options,
  };
  const sockets = new Set();
  const server = createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/actions/token') {
      state.actionsUrls.push(url.pathname + url.search);
      state.actionsAuth.push(req.headers.authorization || '');
      if (url.searchParams.get('audience') !== 'sigstore') {
        res.writeHead(400);
        res.end('audience');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ value: state.actionsToken }));
      return;
    }
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let doc = {};
      try {
        doc = raw ? JSON.parse(raw) : {};
      } catch {
        res.writeHead(400);
        res.end('bad json');
        return;
      }
      if (url.pathname === '/api/v2/signingCert') {
        state.fulcioHits += 1;
        const token = doc.credentials && doc.credentials.oidcIdentityToken;
        if (typeof token === 'string') state.tokens.push(token);
        if (state.hang) return;
        if (state.fulcioStatus) {
          res.writeHead(state.fulcioStatus);
          res.end(typeof token === 'string' ? token : 'no');
          return;
        }
        let payload;
        try {
          payload = JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8'));
        } catch {
          res.writeHead(400);
          res.end('token');
          return;
        }
        const content = doc.publicKeyRequest && doc.publicKeyRequest.publicKey
          && doc.publicKeyRequest.publicKey.content;
        const pop = doc.publicKeyRequest && doc.publicKeyRequest.proofOfPossession;
        let pub;
        try {
          pub = createPublicKey({ key: Buffer.from(content, 'base64'), format: 'der', type: 'spki' });
          const ok = cryptoVerify('sha256', Buffer.from(String(payload.sub), 'utf8'), pub, Buffer.from(pop, 'base64'));
          if (!ok) throw new Error('pop');
        } catch {
          res.writeHead(400);
          res.end('pop');
          return;
        }
        const leaf = buildCertificate({
          subjectCn: 'leaf',
          issuerCn: 'test-intermediate',
          publicKey: pub,
          signer: intermediateKey.privateKey,
          notBefore: state.notBefore,
          notAfter: state.notAfter,
          isCa: false,
          sanUri: String(payload.sub),
          oidcIssuer: String(payload.iss || ''),
        });
        const pem = new X509Certificate(leaf).toString();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ signedCertificateEmbeddedSct: { chain: { certificates: [pem] } } }));
        return;
      }
      if (url.pathname === '/api/v1/log/entries') {
        state.rekorHits += 1;
        if (state.rekorStatus) {
          res.writeHead(state.rekorStatus);
          res.end('rekor-down');
          return;
        }
        const envelope = doc.spec && doc.spec.content && doc.spec.content.envelope;
        const sig = envelope.signatures[0];
        const canonical = canonicalIntotoBody(envelope.payload, envelope.payloadType, sig.sig, sig.publicKey);
        const set = signEntryTimestamp(rekorKey.privateKey, canonical, state.integratedTime, 0, logId);
        const rootHash = leafHash(canonical);
        const checkpoint = buildCheckpoint('rekor.test.local', 1, rootHash, logId, rekorKey.privateKey);
        const entry = {
          body: canonical.toString('base64'),
          integratedTime: state.integratedTime,
          logID: logId.toString('hex'),
          logIndex: 0,
          verification: {
            signedEntryTimestamp: set.toString('base64'),
            inclusionProof: {
              logIndex: 0,
              treeSize: 1,
              rootHash: rootHash.toString('hex'),
              hashes: [],
              checkpoint,
            },
          },
        };
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ '0000': entry }));
        return;
      }
      res.writeHead(404);
      res.end('no');
    });
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        state,
        url: `http://127.0.0.1:${port}`,
        close() {
          for (const socket of sockets) socket.destroy();
          return new Promise((done) => server.close(() => done()));
        },
      });
    });
  });
}

function tokenFile(token) {
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1033-jwt-')));
  const file = join(dir, 'oidc.jwt');
  writeFileSync(file, `${token}\n`);
  return file;
}

async function capturedRepo() {
  const dir = await gitRepo();
  writeFileSync(join(dir, 'README.md'), '# keyless\n\nchanged\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'change']);
  const captured = await cli(dir, ['capture', '--agent', 'cursor', '--message', 'keyless run']);
  assert.equal(captured.code, 0, captured.err + captured.out);
  return dir;
}

function signArgs(mock, extra = []) {
  return [
    'attest', 'last', '--keyless', '--json',
    '--fulcio-url', mock.url,
    '--rekor-url', mock.url,
    ...extra,
  ];
}

function verifyArgs(bundle, extra = []) {
  return [
    'attest', '--verify', bundle, '--json',
    '--trusted-root', trustPath,
    '--certificate-oidc-issuer', ISS,
    ...extra,
  ];
}

function assertNoMarker(dir, result, markers) {
  const blob = `${result.out}\n${result.err}\n${treeText(dir)}`;
  for (const marker of markers) {
    assert.equal(blob.includes(marker), false, marker);
  }
  assert.equal(blob.includes('BEGIN PRIVATE KEY'), false);
  assert.equal(blob.includes('BEGIN EC PRIVATE KEY'), false);
}

describe('v1.0.39 keyless signing', { concurrency: 1 }, () => {
  it('redacts dictionary passphrases and leaves prose alone', () => {
    const contents = redactArgsValue({
      contents: 'password: "correct horse battery staple"\n',
      new_string: 'const cfg = {"password":"hunter2"};\n',
      keyboard: 'layout',
      note: 'the password is not a secret word',
    });
    assert.equal(contents.contents.includes('horse'), false);
    assert.match(contents.contents, /password: "\[REDACTED\]"/);
    assert.equal(contents.new_string.includes('hunter2'), false);
    assert.match(contents.new_string, /"password":"\[REDACTED\]"/);
    assert.equal(contents.keyboard, 'layout');
    assert.equal(contents.note, 'the password is not a secret word');
    assert.equal(redactSecretsInText('rotate the database password tomorrow'), 'rotate the database password tomorrow');
    assert.equal(redactSecretsInText('compass: north'), 'compass: north');
    assert.equal(redactSecretsInText('passport: A1234567'), 'passport: A1234567');
    assert.match(redactSecretsInText('password: see the docs'), /password: \[REDACTED\] the docs/);
    assert.match(redactSecretsInText('const password = "ab"'), /password = "\[REDACTED\]"/);
    assert.equal(redactSecretsInText('password: correct horse battery staple please stop').includes('horse'), false);
    assert.match(redactSecretsInText('password: correct horse battery staple please stop'), /please stop/);
  });

  it('redacts a secret in an attestation subject filename and still verifies', async () => {
    const dir = await gitRepo();
    const name = `notes-${AKIA}.txt`;
    writeFileSync(join(dir, name), 'notes\n');
    git(dir, ['add', name]);
    git(dir, ['commit', '-m', 'notes']);
    assert.equal((await cli(dir, ['capture', '--agent', 'cursor'])).code, 0);
    assert.equal((await cli(dir, ['keygen'])).code, 0);
    const created = await cli(dir, ['attest', '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    const report = JSON.parse(created.out);
    const statement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(report.path, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    assert.equal(JSON.stringify(statement).includes(AKIA), false);
    assert.ok(statement.subject.some((subject) => subject.name === `notes-AKIA[REDACTED].txt`));
    const verified = await cli(dir, ['attest', '--verify', report.path, '--json']);
    assert.equal(verified.code, 0, verified.err + verified.out);
    const body = JSON.parse(verified.out);
    assert.equal(body.ok, true);
    assert.equal(body.subjectsOk, true);
    assert.equal(body.hashChainOk, true);
  });

  it('signs and verifies a bundle offline', async () => {
    const mock = await startMock();
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, FILE_MARKER));
      const before = listFiles(dir);
      const created = await cli(dir, signArgs(mock, ['--identity-token', file]));
      assert.equal(created.code, 0, created.err + created.out);
      const report = JSON.parse(created.out);
      assert.equal(report.ok, true);
      assert.equal(report.command, 'attest');
      assert.equal(report.version, '1.0.39');
      assert.equal(report.keyless, true);
      assert.equal(report.signed, true);
      assert.equal(report.certificateIdentity, FILE_SUB);
      assert.equal(report.certificateIssuer, ISS);
      assert.equal(typeof report.integratedTime, 'number');
      assert.equal(typeof report.logIndex, 'number');
      assert.ok(report.bundlePath.endsWith('.sigstore.json'));
      assert.ok(report.path.endsWith('.intoto.jsonl'));
      const bundle = JSON.parse(readFileSync(report.bundlePath, 'utf8'));
      assert.equal(bundle.mediaType, BUNDLE_MEDIA_TYPE);
      assert.equal(bundle.verificationMaterial.tlogEntries.length, 1);
      assert.ok(bundle.verificationMaterial.certificate.rawBytes);
      assert.equal(bundle.dsseEnvelope.payloadType, 'application/vnd.in-toto+json');
      assert.equal(bundle.dsseEnvelope.signatures.length, 1);
      assert.equal(readFileSync(report.bundlePath, 'utf8').endsWith('\n'), true);
      assertNoMarker(dir, created, [FILE_MARKER, ENV_MARKER, ACTIONS_MARKER]);
      assert.equal(mock.state.tokens.some((token) => token.includes(FILE_MARKER)), true);
      const human = await cli(dir, [
        'attest', '--verify', report.bundlePath,
        '--trusted-root', trustPath,
        '--certificate-identity', FILE_SUB,
        '--certificate-oidc-issuer', ISS,
      ]);
      assert.equal(human.code, 0, human.err + human.out);
      assert.match(human.out, /keyless/);
      assert.match(human.out, new RegExp(FILE_SUB.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      const verified = await cli(dir, verifyArgs(report.bundlePath, ['--certificate-identity', FILE_SUB]));
      assert.equal(verified.code, 0, verified.err + verified.out);
      const body = JSON.parse(verified.out);
      assert.equal(body.command, 'attest-verify');
      assert.equal(body.keyless, true);
      assert.equal(body.ok, true);
      assert.equal(body.certificateIdentity, FILE_SUB);
      assert.equal(body.certificateIssuer, ISS);
      assert.equal(body.subjectsOk, true);
      assert.equal(body.hashChainOk, true);
      assert.equal(typeof body.integratedTime, 'number');
      const jsonl = await cli(dir, ['attest', '--verify', report.path, '--json']);
      assert.equal(jsonl.code, 2, jsonl.out);
      assert.match(jsonl.out, /\.sigstore\.json/);
      assert.ok(listFiles(dir).length > before.length);
    } finally {
      await mock.close();
    }
  });

  it('prefers the token file, then env, then Actions audience sigstore', async () => {
    const mock = await startMock();
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, FILE_MARKER));
      const env = {
        SIGSTORE_ID_TOKEN: jwt(ENV_SUB, ENV_MARKER),
        ACTIONS_ID_TOKEN_REQUEST_URL: `${mock.url}/actions/token`,
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUEST_TOKEN,
      };
      const fromFile = await cli(dir, signArgs(mock, ['--identity-token', file]), { env });
      assert.equal(fromFile.code, 0, fromFile.err + fromFile.out);
      const fileReport = JSON.parse(fromFile.out);
      assert.equal(fileReport.certificateIdentity, FILE_SUB);
      assert.equal(mock.state.actionsUrls.length, 0);
      assert.equal(mock.state.tokens.at(-1).includes(FILE_MARKER), true);
      assert.equal(mock.state.tokens.at(-1).includes(ENV_MARKER), false);

      const fromEnv = await cli(dir, signArgs(mock), { env });
      assert.equal(fromEnv.code, 0, fromEnv.err + fromEnv.out);
      assert.equal(JSON.parse(fromEnv.out).certificateIdentity, ENV_SUB);
      assert.equal(mock.state.actionsUrls.length, 0);

      const fromActions = await cli(dir, signArgs(mock), {
        env: {
          ACTIONS_ID_TOKEN_REQUEST_URL: `${mock.url}/actions/token`,
          ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUEST_TOKEN,
        },
      });
      assert.equal(fromActions.code, 0, fromActions.err + fromActions.out);
      assert.equal(JSON.parse(fromActions.out).certificateIdentity, ACTIONS_SUB);
      assert.equal(mock.state.actionsUrls.at(-1).includes('audience=sigstore'), true);
      assert.equal(mock.state.actionsAuth.at(-1), `Bearer ${REQUEST_TOKEN}`);
      const bundle = readFileSync(JSON.parse(fromActions.out).bundlePath, 'utf8');
      assert.equal(bundle.includes(REQUEST_TOKEN), false);
      assert.equal(bundle.includes(ACTIONS_MARKER), false);
      assertNoMarker(dir, fromActions, [FILE_MARKER, ENV_MARKER, ACTIONS_MARKER, REQUEST_TOKEN]);
    } finally {
      await mock.close();
    }
  });

  it('reads --identity-token - from stdin', async () => {
    const mock = await startMock();
    try {
      const dir = await capturedRepo();
      const token = jwt(FILE_SUB, FILE_MARKER);
      const created = await cli(dir, signArgs(mock, ['--identity-token', '-']), { input: `${token}\n` });
      assert.equal(created.code, 0, created.err + created.out);
      assert.equal(JSON.parse(created.out).certificateIdentity, FILE_SUB);
      assertNoMarker(dir, created, [FILE_MARKER]);
    } finally {
      await mock.close();
    }
  });

  it('fails closed on identity, issuer, regexp, chain, time, and tamper', async () => {
    const mock = await startMock();
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, FILE_MARKER));
      const created = await cli(dir, signArgs(mock, ['--identity-token', file]));
      assert.equal(created.code, 0, created.err + created.out);
      const bundle = JSON.parse(created.out).bundlePath;
      const missing = await cli(dir, ['attest', '--verify', bundle, '--json', '--trusted-root', trustPath]);
      assert.equal(missing.code, 1, missing.out);
      assert.match(missing.out, /certificate-identity/);
      const noIssuer = await cli(dir, [
        'attest', '--verify', bundle, '--json', '--trusted-root', trustPath,
        '--certificate-identity', FILE_SUB,
      ]);
      assert.equal(noIssuer.code, 1, noIssuer.out);
      assert.match(noIssuer.out, /certificate-oidc-issuer/);
      const wrongId = await cli(dir, verifyArgs(bundle, ['--certificate-identity', 'https://github.com/other/actor']));
      assert.equal(wrongId.code, 2, wrongId.out);
      assert.match(wrongId.out, /identity does not match/);
      const wrongIss = await cli(dir, [
        'attest', '--verify', bundle, '--json', '--trusted-root', trustPath,
        '--certificate-identity', FILE_SUB,
        '--certificate-oidc-issuer', 'https://issuer.example',
      ]);
      assert.equal(wrongIss.code, 2, wrongIss.out);
      assert.match(wrongIss.out, /issuer does not match/);
      const badRe = await cli(dir, verifyArgs(bundle, ['--certificate-identity-regexp', 'https://github.com/nope/.*']));
      assert.equal(badRe.code, 2, badRe.out);
      assert.match(badRe.out, /identity does not match/);
      const goodRe = await cli(dir, verifyArgs(bundle, ['--certificate-identity-regexp', 'https://github.com/file/.*']));
      assert.equal(goodRe.code, 0, goodRe.err + goodRe.out);
      const untrusted = await cli(dir, [
        'attest', '--verify', bundle, '--json',
        '--trusted-root', otherTrustPath,
        '--certificate-identity', FILE_SUB,
        '--certificate-oidc-issuer', ISS,
      ]);
      assert.equal(untrusted.code, 2, untrusted.out);
      assert.match(untrusted.out, /does not chain/);
      for (const field of ['payload', 'sig', 'set']) {
        const doc = JSON.parse(readFileSync(bundle, 'utf8'));
        if (field === 'payload') {
          const buf = Buffer.from(doc.dsseEnvelope.payload, 'base64');
          buf[0] ^= 0xff;
          doc.dsseEnvelope.payload = buf.toString('base64');
        } else if (field === 'sig') {
          const buf = Buffer.from(doc.dsseEnvelope.signatures[0].sig, 'base64');
          buf[0] ^= 0xff;
          doc.dsseEnvelope.signatures[0].sig = buf.toString('base64');
        } else {
          const set = doc.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp;
          const buf = Buffer.from(set, 'base64');
          buf[0] ^= 0xff;
          doc.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp = buf.toString('base64');
        }
        const tampered = join(dir, `tamper-${field}.sigstore.json`);
        writeFileSync(tampered, `${JSON.stringify(doc)}\n`);
        const failed = await cli(dir, verifyArgs(tampered, ['--certificate-identity', FILE_SUB]));
        assert.equal(failed.code, 2, `${field} ${failed.out}`);
        assert.equal(failed.out.includes(FILE_MARKER), false);
      }
    } finally {
      await mock.close();
    }
  });

  it('rejects a certificate that was not valid at the integrated time', async () => {
    const mock = await startMock({
      notBefore: new Date(Date.now() - 2 * 86400000),
      notAfter: new Date(Date.now() - 86400000),
      integratedTime: Math.floor(Date.now() / 1000),
    });
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, FILE_MARKER));
      const created = await cli(dir, signArgs(mock, ['--identity-token', file]));
      assert.equal(created.code, 0, created.err + created.out);
      const bundle = JSON.parse(created.out).bundlePath;
      const verified = await cli(dir, verifyArgs(bundle, ['--certificate-identity', FILE_SUB]));
      assert.equal(verified.code, 2, verified.out);
      assert.match(verified.out, /not valid at the Rekor integrated time/);
    } finally {
      await mock.close();
    }
  });

  it('writes nothing when Fulcio or Rekor fails, the token is expired, or flags conflict', async () => {
    const mock = await startMock({ fulcioStatus: 500 });
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, FILE_MARKER));
      const before = listFiles(dir);
      const fulcio = await cli(dir, signArgs(mock, ['--identity-token', file]));
      assert.equal(fulcio.code, 1, fulcio.out + fulcio.err);
      assert.match(fulcio.out, /HTTP 500/);
      assert.deepEqual(listFiles(dir), before);
      assertNoMarker(dir, fulcio, [FILE_MARKER]);
    } finally {
      await mock.close();
    }

    const rekor = await startMock({ rekorStatus: 502 });
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, FILE_MARKER));
      const before = listFiles(dir);
      const failed = await cli(dir, signArgs(rekor, ['--identity-token', file]));
      assert.equal(failed.code, 1, failed.out + failed.err);
      assert.match(failed.out, /HTTP 502/);
      assert.deepEqual(listFiles(dir), before);
      assertNoMarker(dir, failed, [FILE_MARKER]);
    } finally {
      await rekor.close();
    }

    const expiredMock = await startMock();
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, EXPIRED_MARKER, Math.floor(Date.now() / 1000) - 120));
      const before = listFiles(dir);
      const expired = await cli(dir, signArgs(expiredMock, ['--identity-token', file]));
      assert.equal(expired.code, 1, expired.out + expired.err);
      assert.match(expired.out, /OIDC token is expired/);
      assert.equal(expiredMock.state.fulcioHits, 0);
      assert.deepEqual(listFiles(dir), before);
      assertNoMarker(dir, expired, [EXPIRED_MARKER]);
    } finally {
      await expiredMock.close();
    }

    const idle = await startMock();
    try {
      const dir = await capturedRepo();
      const before = listFiles(dir);
      const conflict = await cli(dir, ['attest', '--keyless', '--no-sign', '--json', '--fulcio-url', idle.url, '--rekor-url', idle.url, '--identity-token', tokenFile(jwt(FILE_SUB, FILE_MARKER))]);
      assert.equal(conflict.code, 1, conflict.out);
      assert.match(conflict.out, /conflicts with --no-sign/);
      const sessionDir = await gitRepo();
      writeFileSync(join(sessionDir, 'README.md'), '# s\n');
      git(sessionDir, ['add', 'README.md']);
      git(sessionDir, ['commit', '-m', 's']);
      assert.equal((await cli(sessionDir, ['capture', '--session', 'sess-1033', '--agent', 'cursor'])).code, 0);
      const sessionBefore = listFiles(sessionDir);
      const session = await cli(sessionDir, [
        'attest', '--session', 'sess-1033', '--keyless', '--json',
        '--fulcio-url', idle.url, '--rekor-url', idle.url,
        '--identity-token', tokenFile(jwt(FILE_SUB, FILE_MARKER)),
      ]);
      assert.equal(session.code, 1, session.out);
      assert.match(session.out, /signs one receipt/);
      assert.deepEqual(listFiles(sessionDir), sessionBefore);
      assert.deepEqual(listFiles(dir), before);
      assert.equal(idle.state.fulcioHits, 0);
      const missing = await cli(dir, ['attest', '--keyless', '--json', '--fulcio-url', idle.url, '--rekor-url', idle.url]);
      assert.equal(missing.code, 1, missing.out);
      assert.match(missing.out, /--identity-token/);
      assert.deepEqual(listFiles(dir), before);
    } finally {
      await idle.close();
    }
  });

  it('times out without writing a bundle', async () => {
    const mock = await startMock({ hang: true });
    try {
      const dir = await capturedRepo();
      const file = tokenFile(jwt(FILE_SUB, FILE_MARKER));
      const before = listFiles(dir);
      const failed = await cli(dir, signArgs(mock, ['--identity-token', file]), {
        env: { AGENT_RECEIPT_SIGSTORE_TIMEOUT_MS: '200' },
        timeout: 8000,
      });
      assert.equal(failed.signal, null);
      assert.equal(failed.code, 1, failed.out + failed.err);
      assert.match(failed.out + failed.err, /timed out contacting Fulcio/);
      assert.deepEqual(listFiles(dir), before);
      assertNoMarker(dir, failed, [FILE_MARKER]);
    } finally {
      await mock.close();
    }
  });

  it('documents 1.0.39 and keeps sign --keyless out of scope', async () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.39');
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.33\]/);
    assert.match(changelog, /attest --keyless/);
    const help = await cli(root, ['help', 'attest']);
    assert.equal(help.code, 0, help.err);
    assert.match(help.out, /--keyless/);
    assert.match(help.out, /certificate-oidc-issuer/);
    assert.match(help.out, /sign --keyless` is not a command/);
    const sign = await cli(root, ['help', 'sign']);
    assert.match(sign.out, /sign --keyless` is not supported/);
    const docs = readFileSync(join(root, 'docs', 'keyless.md'), 'utf8');
    assert.match(docs, /id-token: write/);
    assert.match(docs, /permissions:/);
    assert.match(docs, /documentation/);
  });
});
