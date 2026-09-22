import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  chmodSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { redactSecretsInText } from '../dist/lib/redact.js';
import { analyzeRisks } from '../dist/lib/risk.js';
import { sha256Hex } from '../dist/lib/hash.js';
import { runDoctorChecks } from '../dist/commands/doctor.js';
import { GROK_WRAP_SCRIPT } from '../dist/lib/grok-rule.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const GHO = 'gho_Abcdefghij0123456789ABCDEFGHIJklmnop';
const GLPAT = 'glpat-abcdefghij0123456789';
const NPM = 'npm_' + 'a'.repeat(36);
const GOOGLE = 'AIzaSyD' + 'a'.repeat(32);
const YA29 = 'ya29.a0AfH6SMCfakeTokenValue';
const ASIA = 'ASIAIOSFODNN7EXAMPLE';
const STRIPE = 'sk_live_FAKEKEY0123456789';
const SENDGRID = 'SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUV';
const AZURE = 'abcd1234EFGH5678ijkl9012MNOP3456qrst7890';
const XOXC = 'xoxc-1234567890-abcdefghij';
const SIG = 'abcdefghijklmnopqrstuvwxyz012345';

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cliResult(cwd, args) {
  try {
    const out = execFileSync(process.execPath, [bin, ...args], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: 0, out, err: '' };
  } catch (err) {
    return {
      code: err.status ?? 1,
      out: String(err.stdout || ''),
      err: String(err.stderr || ''),
    };
  }
}

function cli(cwd, args) {
  const r = cliResult(cwd, args);
  if (r.code !== 0) throw new Error(`exit ${r.code}\n${r.out}\n${r.err}`);
  return r.out;
}

function initRepo(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  git(dir, ['init']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  writeFileSync(join(dir, 'README.md'), '# enterprise fixture\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  cli(dir, ['init']);
  return dir;
}

describe('cloud token redaction', () => {
  const sample = [
    `gho=${GHO}`,
    `gl=${GLPAT}`,
    `npm=${NPM}`,
    `g=${GOOGLE}`,
    `y=${YA29}`,
    `a=${ASIA}`,
    `s=${STRIPE}`,
    `sg=${SENDGRID}`,
    `AccountKey=${AZURE}`,
    `slack=${XOXC}`,
    `https://acct.blob.core.windows.net/c?sig=${SIG}`,
    'AZURE_CLIENT_SECRET=supersecretvalue',
  ].join('\n');

  it('masks common cloud tokens without leaving the raw value', () => {
    const out = redactSecretsInText(sample);
    for (const secret of [GHO, GLPAT, NPM, GOOGLE, YA29, ASIA, STRIPE, SENDGRID, AZURE, XOXC, SIG, 'supersecretvalue']) {
      assert.equal(out.includes(secret), false, secret);
    }
    assert.match(out, /gho_\[REDACTED\]/);
    assert.match(out, /glpat-\[REDACTED\]/);
    assert.match(out, /npm_\[REDACTED\]/);
    assert.match(out, /AIza\[REDACTED\]/);
    assert.match(out, /ya29\.\[REDACTED\]/);
    assert.match(out, /ASIA\[REDACTED\]/);
    assert.match(out, /sk_live_\[REDACTED\]/);
    assert.match(out, /SG\.\[REDACTED\]/);
    assert.match(out, /AccountKey=\[REDACTED\]/);
    assert.match(out, /xox\[REDACTED\]/);
    assert.match(out, /sig=\[REDACTED\]/);
    assert.match(out, /CLIENT_SECRET=\[REDACTED\]|AZURE_CLIENT_SECRET=\[REDACTED\]/);
  });

  it('risk flags the same cloud token families', () => {
    const hints = analyzeRisks(
      [{ path: 'src/config.ts', status: 'M', insertions: 4, deletions: 0, binary: false }],
      { 'src/config.ts': sample.split('\n').map((l) => '+' + l).join('\n') + '\n' },
    );
    const codes = new Set(hints.map((h) => h.code));
    for (const code of [
      'github-token',
      'gitlab-token',
      'npm-token',
      'google-api-key',
      'google-oauth-token',
      'aws-access-key',
      'stripe-secret',
      'sendgrid-token',
      'azure-account-key',
      'slack-token',
    ]) {
      assert.ok(codes.has(code), `missing ${code}`);
    }
  });
});

describe('audit log', () => {
  let dir;

  before(() => {
    dir = initRepo('agent-receipt-audit-');
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('wrap and share append a hash chain; tamper fails --verify', () => {
    writeFileSync(join(dir, 'app.js'), 'export const n = 1;\n');
    git(dir, ['add', 'app.js']);
    git(dir, ['commit', '-m', 'app']);

    const wrapped = cliResult(dir, ['wrap', '--json', '--agent', 'ci', '--message', 'do not log this secret']);
    assert.equal(wrapped.code, 0);
    const gate = JSON.parse(wrapped.out);
    assert.equal(gate.command, 'wrap');
    assert.equal(gate.ok, true);

    const logPath = join(dir, '.agent-receipt', 'audit.jsonl');
    assert.ok(existsSync(logPath));
    let lines = readFileSync(logPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    const wrapEv = JSON.parse(lines[0]);
    assert.equal(wrapEv.event, 'wrap');
    assert.equal(wrapEv.experimental, true);
    assert.equal(wrapEv.prev, null);
    assert.equal(wrapEv.agent, 'ci');
    assert.equal(wrapEv.exitCode, 0);
    assert.equal(wrapEv.verified, true);
    assert.equal(lines[0].includes('do not log this secret'), false);

    const shared = cliResult(dir, ['share', '--json', '--out', 'share.html']);
    assert.equal(shared.code, 0);
    JSON.parse(shared.out);
    lines = readFileSync(logPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);
    const shareEv = JSON.parse(lines[1]);
    assert.equal(shareEv.event, 'share');
    assert.equal(shareEv.prev, sha256Hex(lines[0] + '\n'));
    assert.equal(shareEv.agent, 'ci');
    assert.match(shareEv.path, /share\.html$/);
    assert.equal(shareEv.redacted, true);

    const verified = cliResult(dir, ['audit', '--verify']);
    assert.equal(verified.code, 0);
    assert.match(verified.out, /audit chain OK/);
    assert.match(cli(dir, ['log', '--verify', '--json']), /"ok":true/);

    const listed = JSON.parse(cli(dir, ['audit', '--json', '--limit', '1']));
    assert.equal(listed.length, 1);
    assert.equal(listed[0].event, 'share');

    const human = cli(dir, ['audit']);
    assert.match(human, /experimental/);
    assert.match(human, /wrap/);
    assert.match(human, /share/);

    const broken = lines[0].replace(wrapEv.sha256.slice(0, 8), 'deadbeef');
    writeFileSync(logPath, broken + '\n' + lines[1] + '\n');
    const bad = cliResult(dir, ['audit', '--verify', '--json']);
    assert.equal(bad.code, 2);
    const body = JSON.parse(bad.out);
    assert.equal(body.ok, false);
    assert.equal(body.experimental, true);
    assert.ok(body.brokenAt >= 1);

    const checks = runDoctorChecks(dir);
    const audit = checks.find((c) => c.name === 'audit');
    assert.equal(audit.status, 'warn');
    const policy = checks.find((c) => c.name === 'policy');
    assert.equal(policy.status, 'info');
  });

  it('doctor policy passes when org redact and failOn are set', () => {
    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      'outDir: .agent-receipt/receipts\nredact: true\nfailOn: high\n',
    );
    const checks = runDoctorChecks(dir);
    assert.equal(checks.find((c) => c.name === 'policy').status, 'pass');
    const out = cli(dir, ['doctor']);
    assert.match(out, /\[PASS\].*policy/);
    assert.match(out, /\[WARN\].*audit/);
    assert.match(out, /Ready/);
  });
});

describe('docs mirror and CI examples', () => {
  it('docs CI mirror has the share --json smoke and the workflow scope', () => {
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /share --json/);
    assert.match(mirror, /wrap --agent ci --message smoke --json/);
    assert.match(mirror, /audit --verify/);
    assert.match(mirror, /gh auth refresh -h github.com -s workflow/);
    assert.match(mirror, /workflow` scope|`workflow` scope|workflow scope/);
    const gate = readFileSync(join(root, 'examples', 'github', 'pr-gate.yml'), 'utf8');
    assert.match(gate, /--fail-on/);
    assert.match(gate, /--json/);
    assert.match(gate, /workflow_call/);
    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /using: composite/);
    assert.match(action, /--fail-on/);
    assert.match(action, /--json/);
    const contributing = readFileSync(join(root, 'CONTRIBUTING.md'), 'utf8');
    assert.match(contributing, /gh auth refresh -h github.com -s workflow/);
  });
});

describe('SessionEnd stdin close', () => {
  let dir;

  before(() => {
    dir = initRepo('agent-receipt-stdin-');
    cli(dir, ['init', '--grok']);
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('hook script closes stdin after the drain', () => {
    assert.match(GROK_WRAP_SCRIPT, /exec 0<\/dev\/null/);
    assert.match(readFileSync(join(root, 'scripts', 'grok-wrap.sh'), 'utf8'), /exec 0<\/dev\/null/);
    assert.match(GROK_WRAP_SCRIPT, /command -v node/);
  });

  it('broken timeout without node does not block a full-pipe writer during wrap', () => {
    const script = join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh');
    const binDir = mkdtempSync(join(tmpdir(), 'agent-receipt-brokentimeout-'));
    const gitSrc = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
    symlinkSync(gitSrc, join(binDir, 'git'));
    writeFileSync(
      join(binDir, 'timeout'),
      '#!/bin/sh\n# Reject every invocation (BusyBox-like fractional failure).\nexit 2\n',
    );
    chmodSync(join(binDir, 'timeout'), 0o755);
    const startedFlag = join(binDir, 'wrap-started');
    writeFileSync(
      join(binDir, 'agent-receipt'),
      '#!/bin/sh\nprintf started >"$WRAP_STARTED"\nwhile :; do :; done\n',
    );
    chmodSync(join(binDir, 'agent-receipt'), 0o755);
    writeFileSync(join(dir, 'dirty.txt'), 'uncommitted\n');

    const helper = `
      const { spawn } = require('child_process');
      const child = spawn('/bin/sh', [process.env.HOOK_SCRIPT], {
        cwd: process.env.HOOK_CWD,
        env: process.env,
        detached: true,
        stdio: ['pipe', 'ignore', 'ignore'],
      });
      const buf = Buffer.alloc(65536, 97);
      let settled = false;
      function stop() {
        try { process.kill(-child.pid, 'SIGKILL'); } catch (e) {}
      }
      const killer = setTimeout(() => {
        if (settled) return;
        settled = true;
        stop();
        process.exit(2);
      }, 2500);
      child.stdin.on('error', (err) => {
        if (settled) return;
        if (!err || err.code !== 'EPIPE') {
          settled = true;
          clearTimeout(killer);
          stop();
          process.exit(1);
        }
        settled = true;
        clearTimeout(killer);
        setTimeout(() => { stop(); process.exit(0); }, 800);
      });
      let n = 0;
      function pump() {
        if (settled) return;
        while (n < 16) {
          n += 1;
          if (!child.stdin.write(buf)) {
            child.stdin.once('drain', pump);
            return;
          }
        }
      }
      pump();
    `;
    const result = spawnSync(process.execPath, ['-e', helper], {
      env: {
        ...process.env,
        PATH: binDir,
        HOOK_SCRIPT: script,
        HOOK_CWD: dir,
        GROK_WORKSPACE_ROOT: dir,
        HOOK_STDIN_MAX: '1024',
        HOOK_STDIN_WAIT_SEC: '0.2',
        WRAP_STARTED: startedFlag,
      },
      encoding: 'utf8',
      timeout: 4000,
    });
    assert.equal(result.error, undefined, result.error && result.error.message);
    assert.equal(result.status, 0, `stdout=${result.stdout} stderr=${result.stderr}`);
    assert.equal(existsSync(startedFlag), true, 'wrap did not start before stdin was released');
    rmSync(binDir, { recursive: true, force: true });
  });

  it('node drain is used even when timeout rejects the wait', () => {
    const script = join(dir, '.grok', 'hooks', 'agent-receipt-wrap.sh');
    const binDir = mkdtempSync(join(tmpdir(), 'agent-receipt-prefnode-'));
    const link = (cmd) => {
      const src = execFileSync('sh', ['-c', `command -v ${cmd}`], { encoding: 'utf8' }).trim();
      symlinkSync(src, join(binDir, cmd));
    };
    link('node');
    link('git');
    writeFileSync(join(binDir, 'timeout'), '#!/bin/sh\nexit 2\n');
    chmodSync(join(binDir, 'timeout'), 0o755);

    const result = spawnSync('/bin/sh', [script], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 4000,
      env: {
        ...process.env,
        PATH: `${binDir}:/usr/bin:/bin`,
        GROK_WORKSPACE_ROOT: dir,
        HOOK_STDIN_WAIT_SEC: '0.3',
      },
      input: '',
    });
    rmSync(binDir, { recursive: true, force: true });
    // spawnSync with input:'' closes stdin (EOF), so the drain returns on end
    // rather than the wait. Open-pipe case below checks the wait.
    assert.equal(result.status, 0);

    const open = spawn('/bin/sh', [script], {
      cwd: dir,
      env: {
        ...process.env,
        GROK_WORKSPACE_ROOT: dir,
        HOOK_STDIN_WAIT_SEC: '0.3',
      },
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    const started = Date.now();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        open.kill('SIGKILL');
        reject(new Error('open stdin hung'));
      }, 3000);
      open.on('exit', (status) => {
        clearTimeout(timer);
        const elapsed = Date.now() - started;
        try {
          assert.equal(status, 0);
          assert.ok(elapsed < 2500, `elapsed ${elapsed}`);
          resolve();
        } catch (err) {
          reject(err);
        }
      });
    });
  });
});
