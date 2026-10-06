import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dssePae, DSSE_PAYLOAD_TYPE, envelopeJson, signEnvelope } from '../dist/lib/dsse.js';
import { loadKeys } from '../dist/lib/sign.js';
import { receiptIntegrity } from '../dist/lib/link.js';
import { sha256FileBytes } from '../dist/lib/share-package.js';
import { redactArgsValue } from '../dist/lib/adapters/parse-common.js';
import { PREDICATE_RUN, PREDICATE_SLSA, SLSA_BUILDER_ID } from '../dist/lib/intoto.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const AKIA = 'AKIAIOSFODNN7EXAMPLE';
const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';

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
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1032-')));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# attest\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  assert.equal(cli(dir, ['init']).code, 0);
  return dir;
}

function commitFile(dir, name, body) {
  writeFileSync(join(dir, name), body);
  git(dir, ['add', name]);
  git(dir, ['commit', '-m', name]);
}

function capture(dir, extra = []) {
  const result = cli(dir, ['capture', '--agent', 'cursor', ...extra]);
  assert.equal(result.code, 0, result.err + result.out);
  return result;
}

function latest(dir) {
  const result = cli(dir, ['last', '--json']);
  assert.equal(result.code, 0, result.err + result.out);
  return JSON.parse(result.out);
}

function decodeAttest(file) {
  const text = readFileSync(file, 'utf8');
  const lines = text.split('\n').filter((line) => line.trim());
  const envelopes = lines.map((line) => {
    const env = JSON.parse(line);
    const statement = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    return { env, statement, line };
  });
  return { text, envelopes };
}

function signedRepo() {
  const dir = gitRepo();
  commitFile(dir, 'README.md', '# attest\n\nchanged\n');
  capture(dir, ['--message', 'signed run']);
  assert.equal(cli(dir, ['keygen']).code, 0);
  const created = cli(dir, ['attest', '--json']);
  assert.equal(created.code, 0, created.err + created.out);
  const report = JSON.parse(created.out);
  return { dir, report, created };
}

describe('v1.0.32 in-toto attest', () => {
  it('matches the DSSE PAE known vector', () => {
    const pae = dssePae('http://example.com/HelloWorld', Buffer.from('hello world'));
    assert.equal(pae.toString('utf8'), 'DSSEv1 29 http://example.com/HelloWorld 11 hello world');
    assert.equal(DSSE_PAYLOAD_TYPE, 'application/vnd.in-toto+json');
  });

  it('redacts short passwords and encoded secrets without eating path keys', () => {
    const note = Buffer.from(AKIA).toString('base64');
    const out = redactArgsValue({
      path: 'src/keyboard.ts',
      contents: 'const password = "ab";\n',
      note,
      api_key: 'short',
      apiKey: 'short2',
      keyboard: 'layout',
      session: 'sess',
      file_path: 'src/keyboard.ts',
      'src/keyboard.ts': 'keep-path-key',
      'src/keys/config.ts': 'keep-keys-path',
    });
    assert.equal(out.path, 'src/keyboard.ts');
    assert.equal(out.contents.includes('password = "ab"'), false);
    assert.match(out.contents, /password = "\[REDACTED\]"/);
    assert.equal(out.note, '[REDACTED]');
    assert.equal(out.api_key, '[REDACTED]');
    assert.equal(out.apiKey, '[REDACTED]');
    assert.equal(out.keyboard, 'layout');
    assert.equal(out.session, '[REDACTED]');
    assert.equal(out.file_path, 'src/keyboard.ts');
    assert.equal(out['src/keyboard.ts'], 'keep-path-key');
    assert.equal(out['src/keys/config.ts'], 'keep-keys-path');
    assert.equal(JSON.stringify(out).includes(AKIA), false);
    assert.equal(JSON.stringify(out).includes(note), false);
  });

  it('documents 1.0.32 and still mentions in-toto in the changelog history', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.35');
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.32\]/);
    assert.match(changelog, /in-toto\/SLSA/);
    assert.match(changelog, /DSSE/);
    const help = cli(root, ['help', 'attest']);
    assert.equal(help.code, 0, help.err);
    assert.match(help.out, /Statement\/v1/);
    assert.match(help.out, /\.intoto\.jsonl/);
    assert.match(help.out, /not a CA/i);
  });

  it('writes a signed statement with a raw subject digest and the receipt hash chain', () => {
    const { dir, report } = signedRepo();
    assert.equal(report.ok, true);
    assert.equal(report.command, 'attest');
    assert.equal(report.version, '1.0.35');
    assert.equal(report.signed, true);
    assert.equal(report.redacted, true);
    assert.equal(report.predicateType, PREDICATE_RUN);
    assert.equal(report.envelopes, 1);
    assert.ok(report.subjects >= 1);
    assert.ok(report.path.endsWith('.intoto.jsonl'));
    const receipt = latest(dir);
    const relReceipt = report.path && receipt.path;
    const { envelopes, text } = decodeAttest(report.path);
    assert.equal(envelopes.length, 1);
    const { env, statement } = envelopes[0];
    assert.equal(env.payloadType, DSSE_PAYLOAD_TYPE);
    assert.equal(statement._type, STATEMENT_TYPE);
    assert.equal(statement.predicateType, PREDICATE_RUN);
    assert.equal(env.signatures.length, 1);
    assert.equal(env.signatures[0].keyid, report.fingerprint);
    assert.match(env.signatures[0].publicKey, /BEGIN PUBLIC KEY/);
    assert.equal(text.includes('PRIVATE KEY'), false);
    const privatePem = readFileSync(join(dir, '.agent-receipt', 'keys', 'ed25519.private'), 'utf8');
    assert.equal(text.includes(privatePem), false);
    const predicate = statement.predicate;
    assert.equal(predicate.redacted, true);
    assert.equal(predicate.cliVersion, '1.0.35');
    assert.equal(predicate.hashChainHead, receipt.sha256);
    assert.equal(predicate.receipt.sha256, receipt.sha256);
    assert.equal(predicate.receipt.name.endsWith('.md'), true);
    const subject = statement.subject.find((item) => item.name === predicate.receipt.name);
    assert.ok(subject);
    const receiptFile = join(dir, predicate.receipt.name);
    assert.equal(subject.digest.sha256, sha256FileBytes(receiptFile));
    assert.notEqual(subject.digest.sha256, predicate.hashChainHead);
    assert.equal(receiptIntegrity(readFileSync(receiptFile, 'utf8')).actual, predicate.hashChainHead);
    assert.equal(predicate.host, undefined);
    assert.equal(predicate.workspace, undefined);
    assert.ok(relReceipt);
    const verified = cli(dir, ['attest', '--verify', report.path, '--json']);
    assert.equal(verified.code, 0, verified.err + verified.out);
    const verifyBody = JSON.parse(verified.out);
    assert.equal(verifyBody.command, 'attest-verify');
    assert.equal(verifyBody.ok, true);
    assert.equal(verifyBody.signed, true);
    assert.equal(verifyBody.subjectsOk, true);
    assert.equal(verifyBody.hashChainOk, true);
    assert.equal(verifyBody.trusted, null);
    assert.match(verified.err, /trust store is empty/);
    assert.equal(cli(dir, ['trust', 'add', '--self']).code, 0);
    const trusted = cli(dir, ['attest', 'verify', report.path, '--json']);
    assert.equal(trusted.code, 0, trusted.err + trusted.out);
    assert.equal(JSON.parse(trusted.out).trusted, true);
  });

  it('verifies from a peer directory that has the fingerprint and no private key', () => {
    const { dir, report } = signedRepo();
    const { envelopes } = decodeAttest(report.path);
    const peer = keep(mkdtempSync(join(tmpdir(), 'ar1032-peer-')));
    for (const subject of envelopes[0].statement.subject) {
      const from = join(dir, subject.name);
      const to = join(peer, subject.name);
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(from, to);
    }
    mkdirSync(join(peer, '.agent-receipt'), { recursive: true });
    writeFileSync(join(peer, '.agent-receipt', 'trusted-keys.txt'), `${report.fingerprint}\n`);
    const copied = join(peer, 'peer.intoto.jsonl');
    copyFileSync(report.path, copied);
    const result = cli(peer, ['attest', '--verify', copied, '--json']);
    assert.equal(result.code, 0, result.err + result.out);
    const body = JSON.parse(result.out);
    assert.equal(body.trusted, true);
    assert.equal(body.fingerprint, report.fingerprint);
    assert.equal(readdirSync(peer).includes('ed25519.private'), false);
    assert.equal(readFileSync(copied, 'utf8').includes('PRIVATE KEY'), false);
  });

  it('fails closed when the payload, subject, signature, or hash chain is tampered', () => {
    const { dir, report } = signedRepo();
    const original = readFileSync(report.path, 'utf8');
    const { envelopes } = decodeAttest(report.path);

    const payloadFile = join(dir, 'payload.intoto.jsonl');
    const payloadEnv = JSON.parse(envelopes[0].line);
    const payloadBody = JSON.parse(Buffer.from(payloadEnv.payload, 'base64').toString('utf8'));
    payloadBody.predicate.agent = 'tampered-agent';
    payloadEnv.payload = Buffer.from(JSON.stringify(payloadBody)).toString('base64');
    writeFileSync(payloadFile, `${JSON.stringify(payloadEnv)}\n`);
    const payload = cli(dir, ['attest', '--verify', payloadFile, '--json']);
    assert.equal(payload.code, 2, payload.out);
    assert.match(JSON.parse(payload.out).reason, /signature/);

    const sigFile = join(dir, 'sig.intoto.jsonl');
    const sigEnv = JSON.parse(envelopes[0].line);
    const sig = Buffer.from(sigEnv.signatures[0].sig, 'base64');
    assert.equal(sig.length, 64);
    sig[0] ^= 0xff;
    sigEnv.signatures[0].sig = sig.toString('base64');
    writeFileSync(sigFile, `${JSON.stringify(sigEnv)}\n`);
    const badSig = cli(dir, ['attest', '--verify', sigFile, '--json']);
    assert.equal(badSig.code, 2);
    assert.match(JSON.parse(badSig.out).reason, /signature/);

    const readme = join(dir, 'README.md');
    const readmeBytes = readFileSync(readme);
    writeFileSync(readme, `${readmeBytes.toString('utf8')}\nmore\n`);
    const subject = cli(dir, ['attest', '--verify', report.path, '--json']);
    assert.equal(subject.code, 2, subject.out);
    assert.match(JSON.parse(subject.out).reason, /digest mismatch/);
    writeFileSync(readme, readmeBytes);

    const keys = loadKeys(dir);
    const forged = JSON.parse(JSON.stringify(envelopes[0].statement));
    const wrong = 'a'.repeat(64);
    forged.predicate.hashChainHead = wrong;
    forged.predicate.receipt.sha256 = wrong;
    const signed = signEnvelope(Buffer.from(JSON.stringify(forged)), keys);
    const chainFile = join(dir, 'chain.intoto.jsonl');
    writeFileSync(chainFile, `${envelopeJson(signed)}\n`);
    const chain = cli(dir, ['attest', '--verify', chainFile, '--json']);
    assert.equal(chain.code, 2, chain.out);
    assert.match(JSON.parse(chain.out).reason, /hash-chain/);
    assert.equal(readFileSync(report.path, 'utf8'), original);
  });

  it('warns and still writes when no key exists, and verify rejects the unsigned envelope', () => {
    const dir = gitRepo();
    commitFile(dir, 'README.md', '# attest\n\nunsigned\n');
    capture(dir, ['--message', 'unsigned run']);
    const created = cli(dir, ['attest', '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    assert.match(created.err, /unsigned \(no local Ed25519 keys\)/);
    assert.match(created.err, /Private keys are never included/);
    const report = JSON.parse(created.out);
    assert.equal(report.signed, false);
    assert.equal(report.warning.includes('unsigned'), true);
    const { envelopes, text } = decodeAttest(report.path);
    assert.deepEqual(envelopes[0].env.signatures, []);
    assert.equal(text.includes('PRIVATE KEY'), false);
    const verified = cli(dir, ['attest', '--verify', report.path, '--json']);
    assert.equal(verified.code, 2);
    assert.match(JSON.parse(verified.out).reason, /unsigned/);
  });

  it('warns when --no-sign is set even though a key exists', () => {
    const dir = gitRepo();
    commitFile(dir, 'README.md', '# attest\n\nno-sign\n');
    capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = cli(dir, ['attest', '--no-sign', '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    assert.match(created.err, /unsigned \(--no-sign\)/);
    const report = JSON.parse(created.out);
    assert.equal(report.signed, false);
    assert.deepEqual(decodeAttest(report.path).envelopes[0].env.signatures, []);
  });

  it('redacts predicate narrative and the redacted envelope still verifies', () => {
    const dir = gitRepo();
    commitFile(dir, 'README.md', `# ${AKIA}\npassword="ab"\n`);
    const transcript = join(dir, 'session.jsonl');
    const note = Buffer.from(AKIA).toString('base64');
    writeFileSync(
      transcript,
      `${JSON.stringify({
        type: 'assistant',
        message: {
          content: [
            {
              type: 'tool_use',
              id: 'w1',
              name: 'Write',
              input: {
                path: 'src/keyboard.ts',
                contents: 'const password = "ab";\n',
                note,
              },
            },
          ],
        },
      })}\n`,
    );
    capture(dir, [
      '--message', `ship ${AKIA} password="ab"`,
      '--transcript', transcript,
      '--adapter', 'claude-code',
    ]);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const receipt = readFileSync(latest(dir).path, 'utf8');
    assert.match(receipt, new RegExp(AKIA));
    assert.match(receipt, /password="ab"/);
    const created = cli(dir, ['attest', '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    const report = JSON.parse(created.out);
    const { envelopes, text } = decodeAttest(report.path);
    const encoded = JSON.stringify(envelopes[0].statement);
    assert.equal(encoded.includes(AKIA), false);
    assert.equal(encoded.includes('password="ab"'), false);
    assert.equal(encoded.includes(note), false);
    assert.equal(text.includes(AKIA), false);
    assert.equal(text.includes('password="ab"'), false);
    const verified = cli(dir, ['attest', '--verify', report.path, '--json']);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assert.equal(JSON.parse(verified.out).ok, true);
  });

  it('attests a session package and --session as one jsonl per receipt set', () => {
    const dir = gitRepo();
    assert.equal(cli(dir, ['keygen']).code, 0);
    commitFile(dir, 'a.txt', 'one\n');
    capture(dir, ['--session', 'sess-1032', '--message', 'one']);
    commitFile(dir, 'b.txt', 'two\n');
    capture(dir, ['--session', 'sess-1032', '--message', 'two']);
    const exported = cli(dir, ['session', 'export', 'sess-1032', '--json']);
    assert.equal(exported.code, 0, exported.err + exported.out);
    const session = JSON.parse(exported.out);
    assert.equal(session.receiptCount, 2);
    const attested = cli(dir, ['attest', session.packagePath, '--json']);
    assert.equal(attested.code, 0, attested.err + attested.out);
    const report = JSON.parse(attested.out);
    assert.equal(report.envelopes, 2);
    assert.ok(report.path.endsWith('sess-1032.intoto.jsonl'));
    assert.equal(dirname(report.path), dirname(session.packagePath));
    const { envelopes } = decodeAttest(report.path);
    assert.equal(envelopes.length, 2);
    for (const row of envelopes) {
      assert.equal(row.statement._type, STATEMENT_TYPE);
      assert.equal(row.statement.predicate.redacted, true);
      assert.equal(row.env.signatures.length, 1);
    }
    const verified = cli(dir, ['attest', '--verify', report.path, '--json']);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assert.equal(JSON.parse(verified.out).envelopes, 2);
    const sessionOut = join(dir, 'session-out');
    mkdirSync(sessionOut);
    const bySession = cli(dir, ['attest', '--session', 'sess-1032', '--out', sessionOut, '--json']);
    assert.equal(bySession.code, 0, bySession.err + bySession.out);
    const sessionReport = JSON.parse(bySession.out);
    assert.equal(sessionReport.envelopes, 2);
    assert.equal(sessionReport.path, join(sessionOut, 'sess-1032.intoto.jsonl'));
  });

  it('prints the same envelope for --json and the human report', () => {
    const dir = gitRepo();
    commitFile(dir, 'README.md', '# attest\n\nhuman\n');
    capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const json = cli(dir, ['attest', '--out', join(dir, 'a.intoto.jsonl'), '--json']);
    const human = cli(dir, ['attest', '--out', join(dir, 'b.intoto.jsonl')]);
    assert.equal(json.code, 0, json.err + json.out);
    assert.equal(human.code, 0, human.err + human.out);
    assert.equal(json.out.trim().startsWith('{'), true);
    assert.equal(human.out.trim().startsWith('{'), false);
    assert.match(human.out, /wrote/);
    const body = JSON.parse(json.out);
    assert.equal(body.command, 'attest');
    assert.equal(body.signed, true);
    assert.equal(body.predicateType, PREDICATE_RUN);
    assert.equal(body.envelopes, 1);
    assert.equal(readFileSync(join(dir, 'a.intoto.jsonl'), 'utf8'), readFileSync(join(dir, 'b.intoto.jsonl'), 'utf8'));
  });

  it('export --format intoto matches attest and does not append an export audit line', () => {
    const dir = gitRepo();
    commitFile(dir, 'README.md', '# attest\n\nexport\n');
    capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const before = readFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), 'utf8');
    const attested = cli(dir, ['attest', '--out', join(dir, 'from-attest.intoto.jsonl'), '--json']);
    const exported = cli(dir, ['export', '--format', 'intoto', '--out', join(dir, 'from-export.intoto.jsonl'), '--json']);
    assert.equal(attested.code, 0, attested.err + attested.out);
    assert.equal(exported.code, 0, exported.err + exported.out);
    assert.equal(
      readFileSync(join(dir, 'from-attest.intoto.jsonl'), 'utf8'),
      readFileSync(join(dir, 'from-export.intoto.jsonl'), 'utf8'),
    );
    const after = readFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), 'utf8');
    assert.equal(after, before);
    assert.equal(JSON.parse(exported.out).command, 'attest');
  });

  it('writes a SLSA provenance predicate that verifies', () => {
    const dir = gitRepo();
    commitFile(dir, 'README.md', '# attest\n\nslsa\n');
    capture(dir, ['--message', 'slsa run']);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = cli(dir, ['attest', '--slsa', '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    const report = JSON.parse(created.out);
    assert.equal(report.predicateType, PREDICATE_SLSA);
    const { statement } = decodeAttest(report.path).envelopes[0];
    assert.equal(statement.predicateType, PREDICATE_SLSA);
    assert.ok(statement.predicate.buildDefinition);
    assert.ok(statement.predicate.runDetails);
    assert.equal(statement.predicate.buildDefinition.buildType, PREDICATE_RUN);
    assert.equal(statement.predicate.runDetails.builder.id, SLSA_BUILDER_ID);
    assert.equal(
      statement.predicate.buildDefinition.externalParameters.hashChainHead,
      latest(dir).sha256,
    );
    const byName = cli(dir, ['attest', '--predicate', 'slsa', '--out', join(dir, 'named.intoto.jsonl'), '--json']);
    assert.equal(byName.code, 0, byName.err + byName.out);
    assert.equal(JSON.parse(byName.out).predicateType, PREDICATE_SLSA);
    const verified = cli(dir, ['attest', '--verify', report.path, '--json']);
    assert.equal(verified.code, 0, verified.err + verified.out);
    assert.equal(JSON.parse(verified.out).hashChainOk, true);
  });

  it('exits 2 and writes nothing when the receipt fails integrity', () => {
    const dir = gitRepo();
    commitFile(dir, 'README.md', '# attest\n\nbroken\n');
    capture(dir);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const receiptPath = latest(dir).path;
    const original = readFileSync(receiptPath, 'utf8');
    writeFileSync(receiptPath, original.replace('# Agent Receipt', '# Agent Receipt tampered'));
    const created = cli(dir, ['attest', '--json']);
    assert.equal(created.code, 2, created.out);
    const body = JSON.parse(created.out);
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 2);
    assert.match(body.reason, /integrity/);
    assert.equal(body.path, null);
    const names = readdirSync(join(dir, '.agent-receipt', 'receipts'));
    assert.equal(names.some((name) => name.endsWith('.intoto.jsonl')), false);
  });

  it('returns a JSON usage error for a missing attestation', () => {
    const dir = gitRepo();
    const missing = cli(dir, ['attest', '--verify', 'missing.intoto.jsonl', '--json']);
    assert.equal(missing.code, 1);
    const body = JSON.parse(missing.out);
    assert.equal(body.command, 'attest-verify');
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 1);
  });
});
