import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadConfig, validateConfig } from '../dist/lib/config.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cliResult(cwd, args) {
  const r = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    code: r.status === null ? 1 : r.status,
    out: r.stdout || '',
    err: r.stderr || '',
  };
}

function cli(cwd, args) {
  const r = cliResult(cwd, args);
  if (r.code !== 0) throw new Error(`exit ${r.code}\n${r.out}\n${r.err}`);
  return r.out;
}

function parseJson(out) {
  return JSON.parse(out);
}

function sidecar(mdPath) {
  return mdPath.replace(/\.md$/i, '.sig.json');
}

function commitFile(dir, name, body, message) {
  writeFileSync(join(dir, name), body);
  git(dir, ['add', name]);
  git(dir, ['commit', '-m', message]);
}

describe('v1.0.22 config sign / --no-sign', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo(prefix = 'agent-receipt-1022-') {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# config-sign\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function setSign(dir, value) {
    const path = join(dir, '.agent-receipt.yml');
    let text = existsSync(path) ? readFileSync(path, 'utf8') : '';
    text = text
      .split('\n')
      .filter((line) => !/^sign:/.test(line.trim()))
      .join('\n');
    if (value !== undefined) text += `\nsign: ${value}\n`;
    writeFileSync(path, text);
  }

  function wrapJson(dir, extra = []) {
    const r = cliResult(dir, ['wrap', '--agent', 'ci', '--message', 'signed', '--json', ...extra]);
    assert.equal(r.code, 0, r.out + r.err);
    const gate = parseJson(r.out);
    assert.equal(gate.command, 'wrap');
    assert.equal(gate.exitCode, 0);
    assert.equal(typeof gate.path, 'string');
    return { gate, text: r.out + r.err };
  }

  it('documents version 1.0.22, config sign, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.22\]/);
    assert.match(changelog, /sign: true/);
    assert.match(changelog, /--no-sign/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    assert.match(changelog, /not a CA/i);
    assert.match(changelog, /trust show/);
    assert.match(changelog, /HTML\/share signed package/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.27');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.27');
    assert.equal(lock.packages[''].version, '1.0.27');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.27/);

    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /sign: true/);
    assert.match(business, /--no-sign/);
    assert.match(business, /1\.0\.23/);
    const help = cli(root, ['help', 'wrap']);
    assert.match(help, /--no-sign/);
    assert.match(help, /sign: true/);
    assert.match(help, /init --org/);
    assert.match(help, /does not set `sign`|does not set sign/);
    const helpCapture = cli(root, ['help', 'capture']);
    assert.match(helpCapture, /--no-sign/);
    assert.match(helpCapture, /sign: true/);
    const policy = readFileSync(join(root, 'examples', 'org-policy.yml'), 'utf8');
    assert.match(policy, /# sign: true\s+# after keygen; CLI --no-sign overrides/);
    assert.match(policy, /v1\.0\.23/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.23/);
    assert.match(mirror, /sign: true/);
    assert.match(mirror, /--no-sign/);

    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /v1\.0\.23/);
      assert.doesNotMatch(live, /config sign: true/);
    }
  });

  it('config sign: true signs bare wrap, capture, prove, and verify', () => {
    const dir = initRepo();
    setSign(dir, 'true');
    cli(dir, ['keygen']);
    commitFile(dir, 'note.txt', 'hello\n', 'note');
    const { gate } = wrapJson(dir);
    const sig = sidecar(gate.path);
    assert.equal(existsSync(sig), true);
    const doc = JSON.parse(readFileSync(sig, 'utf8'));
    assert.equal(doc.alg, 'ed25519');
    assert.equal(doc.sha256, gate.sha256);

    const proved = parseJson(cli(dir, ['prove', gate.path, '--json']));
    assert.equal(proved.verified, true);
    assert.equal(proved.signature.present, true);
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.alg, 'ed25519');
    assert.equal(proved.signature.fingerprint, doc.fingerprint);

    const verified = parseJson(cli(dir, ['verify', gate.path, '--require-sig', '--json']));
    assert.equal(verified.exitCode, 0);
    assert.equal(verified.signature.present, true);
    assert.equal(verified.signature.ok, true);

    commitFile(dir, 'cap.txt', 'cap\n', 'cap');
    const captured = cliResult(dir, ['capture', '--agent', 'ci', '--message', 'cap', '--json']);
    assert.equal(captured.code, 0, captured.out + captured.err);
    const cap = parseJson(captured.out);
    assert.equal(existsSync(sidecar(cap.path)), true);
  });

  it('config sign: true with --no-sign writes no sidecar', () => {
    const dir = initRepo();
    setSign(dir, 'true');
    cli(dir, ['keygen']);
    commitFile(dir, 'note.txt', 'nosign\n', 'nosign');
    const { gate } = wrapJson(dir, ['--no-sign']);
    assert.equal(existsSync(sidecar(gate.path)), false);
  });

  it('--no-sign wins over --sign', () => {
    const dir = initRepo();
    setSign(dir, 'true');
    cli(dir, ['keygen']);
    commitFile(dir, 'note.txt', 'both\n', 'both');
    const { gate } = wrapJson(dir, ['--sign', '--no-sign']);
    assert.equal(existsSync(sidecar(gate.path)), false);
  });

  it('absent config and sign: false stay unsigned unless --sign', () => {
    const absent = initRepo('agent-receipt-1022-absent-');
    rmSync(join(absent, '.agent-receipt.yml'));
    cli(absent, ['keygen']);
    commitFile(absent, 'note.txt', 'absent\n', 'absent');
    const bare = wrapJson(absent);
    assert.equal(existsSync(sidecar(bare.gate.path)), false);
    assert.equal(loadConfig(absent).sign, false);
    const forced = wrapJson(absent, ['--sign']);
    assert.equal(existsSync(sidecar(forced.gate.path)), true);

    const off = initRepo('agent-receipt-1022-off-');
    setSign(off, 'false');
    cli(off, ['keygen']);
    commitFile(off, 'note.txt', 'off\n', 'off');
    assert.equal(loadConfig(off).sign, false);
    const unsigned = wrapJson(off);
    assert.equal(existsSync(sidecar(unsigned.gate.path)), false);
    const signed = wrapJson(off, ['--sign']);
    assert.equal(existsSync(sidecar(signed.gate.path)), true);
  });

  it('config sign: true without keys tips, stays unsigned, and does not exit 2', () => {
    const dir = initRepo();
    setSign(dir, 'true');
    commitFile(dir, 'note.txt', 'nokeys\n', 'nokeys');
    const r = cliResult(dir, ['wrap', '--agent', 'ci', '--message', 'nokeys', '--json']);
    assert.equal(r.code, 0, r.out + r.err);
    assert.notEqual(r.code, 2);
    assert.match(`${r.out}\n${r.err}`, /keygen/);
    const gate = parseJson(r.out);
    assert.equal(existsSync(sidecar(gate.path)), false);

    const human = cliResult(dir, ['wrap', '--agent', 'ci', '--message', 'nokeys-human']);
    assert.equal(human.code, 0, human.out + human.err);
    assert.match(`${human.out}\n${human.err}`, /left unsigned/);
    assert.match(`${human.out}\n${human.err}`, /keygen/);
  });

  it('invalid sign is rejected and init --org does not enable sign', () => {
    const dir = initRepo();
    setSign(dir, 'yes');
    const cfg = loadConfig(dir);
    assert.equal(cfg.signInvalid, true);
    assert.equal(cfg.sign, false);
    assert.ok(validateConfig(cfg).some((p) => /sign must be true or false/.test(p)));
    const doctor = cliResult(dir, ['doctor', '--json']);
    assert.equal(doctor.code, 1);
    const body = parseJson(doctor.out);
    assert.equal(body.checks.find((c) => c.id === 'config').status, 'fail');
    assert.match(body.checks.find((c) => c.id === 'config').detail, /sign must be true or false/);
    assert.equal(body.checks.find((c) => c.id === 'sign').status, 'info');

    const fresh = initRepo('agent-receipt-1022-org-');
    const out = cli(fresh, ['init', '--org']);
    assert.match(out, /does not set sign/);
    const yml = readFileSync(join(fresh, '.agent-receipt.yml'), 'utf8');
    assert.equal(/^sign:/m.test(yml), false);
    assert.match(yml, /^redact:\s*true\s*$/m);
    assert.match(yml, /^failOn:\s*high\s*$/m);
    assert.equal(loadConfig(fresh).sign, false);
  });

  it('doctor sign row is INFO, PASS, or WARN and does not fail --strict for missing keys', () => {
    const dir = initRepo();
    const unset = parseJson(cli(dir, ['doctor', '--json']));
    assert.equal(unset.exitCode, 0);
    assert.equal(unset.checks.find((c) => c.id === 'sign').status, 'info');

    setSign(dir, 'true');
    cli(dir, ['keygen']);
    const ready = parseJson(cli(dir, ['doctor', '--json']));
    assert.equal(ready.checks.find((c) => c.id === 'sign').status, 'pass');
    assert.match(ready.checks.find((c) => c.id === 'sign').detail, /sign: true/);

    rmSync(join(dir, '.agent-receipt', 'keys'), { recursive: true, force: true });
    cli(dir, ['init', '--org']);
    cli(dir, ['init', '--retention']);
    const warned = cliResult(dir, ['doctor', '--json']);
    assert.equal(warned.code, 0, warned.out + warned.err);
    const warnBody = parseJson(warned.out);
    const sign = warnBody.checks.find((c) => c.id === 'sign');
    assert.equal(sign.status, 'warn');
    assert.match(sign.detail, /keygen/);
    assert.equal(warnBody.checks.some((c) => c.status === 'fail'), false);

    const strict = cliResult(dir, ['doctor', '--strict', '--json']);
    assert.equal(strict.code, 0, strict.out + strict.err);
    const strictBody = parseJson(strict.out);
    assert.equal(strictBody.checks.find((c) => c.id === 'sign').status, 'warn');
    assert.equal(strictBody.checks.find((c) => c.id === 'policy').status, 'pass');
    assert.equal(strictBody.checks.find((c) => c.id === 'retention').status, 'pass');
    assert.equal(strictBody.checks.some((c) => c.status === 'fail'), false);
  });

  it('watch passes config sign into capture', async () => {
    const dir = initRepo('agent-receipt-1022-watch-');
    setSign(dir, 'true');
    cli(dir, ['keygen']);
    const child = spawn(
      process.execPath,
      [bin, 'watch', '--once', '--interval', '1', '--agent', 'watch-sign', '--message', 'from-watch'],
      {
        cwd: dir,
        env: { ...process.env, NO_COLOR: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('watch did not start: ' + stdout + stderr)), 8000);
      const check = () => {
        if (/baseline:/.test(stdout)) {
          clearTimeout(t);
          resolve(true);
        }
      };
      child.stdout.on('data', check);
      check();
    });
    commitFile(dir, 'watched.txt', 'watch\n', 'watch trigger');
    const code = await new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('watch --once did not exit: ' + stdout + stderr));
      }, 15000);
      child.on('close', (c) => {
        clearTimeout(t);
        resolve(c);
      });
    });
    assert.equal(code, 0, stdout + stderr);
    assert.match(stdout, /signed /);
    const receipts = readdirSync(join(dir, '.agent-receipt', 'receipts'));
    const sigs = receipts.filter((name) => name.endsWith('.sig.json'));
    assert.equal(sigs.length, 1);
  });
});
