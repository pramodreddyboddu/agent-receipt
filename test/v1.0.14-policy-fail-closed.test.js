import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

function doctorJson(dir, args) {
  const r = cliResult(dir, ['doctor', ...args, '--json']);
  return { ...r, body: r.out.trim() ? parseJson(r.out) : null };
}

function check(body, id) {
  return body.checks.find((c) => c.id === id);
}

describe('v1.0.14 fail-closed org policy', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo(prefix) {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# v1.0.14\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    return dir;
  }

  function withReceipts(dir, count) {
    const outDir = join(dir, '.agent-receipt', 'receipts');
    mkdirSync(outDir, { recursive: true });
    for (let i = 0; i < count; i++) {
      writeFileSync(join(outDir, `receipt-n-${i}.md`), `# ${i}\n`);
    }
  }

  it('fails unset policy under --strict on a small outDir; default stays info', () => {
    const dir = initRepo('agent-receipt-1014-small-');
    cli(dir, ['init']);
    const plain = doctorJson(dir, []);
    assert.equal(plain.code, 0, plain.out + plain.err);
    assert.equal(plain.body.strict, false);
    assert.equal(check(plain.body, 'policy').status, 'info');
    assert.equal(check(plain.body, 'retention').status, 'info');
    assert.match(check(plain.body, 'retention').detail, /0 receipt/);

    const strict = doctorJson(dir, ['--strict']);
    assert.equal(strict.code, 1, strict.out + strict.err);
    assert.equal(strict.body.ok, false);
    assert.equal(strict.body.strict, true);
    assert.equal(strict.body.exitCode, 1);
    assert.equal(check(strict.body, 'policy').status, 'fail');
    assert.match(check(strict.body, 'policy').detail, /init --org/);
    assert.doesNotMatch(check(strict.body, 'policy').detail, /under pressure/);
    assert.equal(check(strict.body, 'retention').status, 'fail');
    assert.match(check(strict.body, 'retention').detail, /init --retention/);

    const human = cliResult(dir, ['doctor', '--strict']);
    assert.equal(human.code, 1, human.out);
    assert.match(human.out, /\[FAIL\].*policy/);
    assert.match(human.out, /\[FAIL\].*retention/);
    assert.doesNotMatch(human.out, /Ready/);
  });

  it('fails unset retention under --strict on a small outDir when policy is set', () => {
    const dir = initRepo('agent-receipt-1014-ret-small-');
    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      'outDir: .agent-receipt/receipts\nredact: true\nfailOn: high\n',
    );
    const plain = doctorJson(dir, []);
    assert.equal(plain.code, 0, plain.out + plain.err);
    assert.equal(check(plain.body, 'retention').status, 'info');
    const strict = doctorJson(dir, ['--strict']);
    assert.equal(strict.code, 1, strict.out + strict.err);
    assert.equal(strict.body.ok, false);
    assert.equal(check(strict.body, 'policy').status, 'pass');
    assert.equal(check(strict.body, 'retention').status, 'fail');
    assert.match(check(strict.body, 'retention').detail, /any outDir/);
    const human = cliResult(dir, ['doctor', '--strict']);
    assert.equal(human.code, 1, human.out);
    assert.match(human.out, /\[PASS\].*policy/);
    assert.match(human.out, /\[FAIL\].*retention/);
  });

  it('still fails unset retention under --strict when outDir is under pressure', () => {
    const dir = initRepo('agent-receipt-1014-ret-pressure-');
    writeFileSync(
      join(dir, '.agent-receipt.yml'),
      'outDir: .agent-receipt/receipts\nredact: true\nfailOn: high\n',
    );
    withReceipts(dir, 100);
    const plain = doctorJson(dir, []);
    assert.equal(plain.code, 0, plain.out + plain.err);
    assert.equal(check(plain.body, 'policy').status, 'pass');
    assert.equal(check(plain.body, 'retention').status, 'warn');

    const strict = doctorJson(dir, ['--strict']);
    assert.equal(strict.code, 1, strict.out + strict.err);
    assert.equal(check(strict.body, 'policy').status, 'pass');
    assert.equal(check(strict.body, 'retention').status, 'fail');
    assert.match(check(strict.body, 'retention').detail, /100 receipt/);
    assert.match(check(strict.body, 'retention').detail, /init --retention/);
    const human = cliResult(dir, ['doctor', '--strict']);
    assert.equal(human.code, 1, human.out);
    assert.match(human.out, /\[FAIL\].*retention/);
    assert.match(human.out, /\[PASS\].*policy/);
  });

  it('init --org enables redact and failOn so doctor --strict passes policy', () => {
    const dir = initRepo('agent-receipt-1014-org-fresh-');
    const out = cli(dir, ['init', '--org']);
    assert.match(out, /Initialized/);
    assert.match(out, /\.agent-receipt\.yml/);
    assert.match(out, /redact: true \(set\)/);
    assert.match(out, /failOn: high \(set\)/);
    assert.match(out, /doctor --strict/);
    assert.match(out, /examples\/org-policy\.yml/);
    const yml = readFileSync(join(dir, '.agent-receipt.yml'), 'utf8');
    assert.match(yml, /^redact:\s*true\s*$/m);
    assert.match(yml, /^failOn:\s*high\s*$/m);
    assert.match(yml, /node_modules\/\*\*/);
    assert.doesNotMatch(yml, /^#\s*redact:/m);
    assert.doesNotMatch(yml, /^#\s*failOn:/m);
    assert.equal(/^maxCount:/m.test(yml), false);
    assert.equal(/^maxAgeDays:/m.test(yml), false);

    const strict = doctorJson(dir, ['--strict']);
    assert.equal(strict.code, 1, strict.out + strict.err);
    assert.equal(check(strict.body, 'policy').status, 'pass');
    assert.notEqual(check(strict.body, 'audit').status, 'fail');
    assert.equal(check(strict.body, 'retention').status, 'fail');
  });

  it('init --org preserves ignore and other keys, and is idempotent', () => {
    const dir = initRepo('agent-receipt-1014-org-merge-');
    const ymlPath = join(dir, '.agent-receipt.yml');
    const original = [
      'outDir: .agent-receipt/receipts',
      'ignore:',
      '  - node_modules/**',
      '  - secret-local/**',
      '  - "quoted:glob"',
      'riskAllowlist:',
      '  - package-json-change',
      'maxCount: 40',
      '# keep this comment',
      '# maxAgeDays: 30',
      'redact: false',
      'failOn: medium',
      '',
    ].join('\n');
    writeFileSync(ymlPath, original);
    const out = cli(dir, ['init', '--org']);
    assert.match(out, /Org policy applied/);
    assert.match(out, /redact: true \(set\)/);
    assert.match(out, /failOn: high \(set\)/);
    const after = readFileSync(ymlPath, 'utf8');
    assert.match(after, /secret-local\/\*\*/);
    assert.match(after, /quoted:glob/);
    assert.match(after, /package-json-change/);
    assert.match(after, /^maxCount:\s*40\s*$/m);
    assert.match(after, /^outDir:\s*\.agent-receipt\/receipts\s*$/m);
    assert.match(after, /keep this comment/);
    assert.match(after, /^# maxAgeDays:\s*30\s*$/m);
    assert.equal(/^maxAgeDays:/m.test(after), false);
    assert.match(after, /^redact:\s*true\s*$/m);
    assert.match(after, /^failOn:\s*high\s*$/m);
    assert.doesNotMatch(after, /^redact:\s*false/m);
    assert.doesNotMatch(after, /^failOn:\s*medium/m);

    const merged = doctorJson(dir, []);
    assert.equal(merged.code, 0, merged.out + merged.err);
    assert.match(check(merged.body, 'config').detail, /ignore=3/);
    assert.match(check(merged.body, 'config').detail, /redact=on/);
    assert.match(check(merged.body, 'config').detail, /failOn=high/);
    assert.match(check(merged.body, 'config').detail, /maxCount=40/);

    const again = cli(dir, ['init', '--org']);
    assert.match(again, /redact: true \(unchanged\)/);
    assert.match(again, /failOn: high \(unchanged\)/);
    assert.equal(readFileSync(ymlPath, 'utf8'), after);
    assert.equal(cliResult(dir, ['init', '--org']).code, 0);
  });

  it('init --policy is an alias of init --org', () => {
    const dir = initRepo('agent-receipt-1014-policy-alias-');
    const out = cli(dir, ['init', '--policy']);
    assert.equal(cliResult(dir, ['init', '--policy']).code, 0);
    assert.match(out, /redact: true \(set\)/);
    assert.match(out, /failOn: high \(set\)/);
    const yml = readFileSync(join(dir, '.agent-receipt.yml'), 'utf8');
    assert.match(yml, /^redact:\s*true\s*$/m);
    assert.match(yml, /^failOn:\s*high\s*$/m);
    const second = cli(dir, ['init', '--policy']);
    assert.match(second, /unchanged/);
    assert.equal(readFileSync(join(dir, '.agent-receipt.yml'), 'utf8'), yml);
  });

  it('broken audit still fails --strict when org policy is set', () => {
    const dir = initRepo('agent-receipt-1014-audit-');
    cli(dir, ['init', '--org']);
    mkdirSync(join(dir, '.agent-receipt'), { recursive: true });
    writeFileSync(
      join(dir, '.agent-receipt', 'audit.jsonl'),
      JSON.stringify({ prev: 'deadbeef', event: 'capture' }) + '\n',
    );
    const plain = doctorJson(dir, []);
    assert.equal(plain.code, 0, plain.out + plain.err);
    assert.equal(check(plain.body, 'audit').status, 'warn');
    assert.match(check(plain.body, 'audit').detail, /chain broken/);
    assert.equal(check(plain.body, 'policy').status, 'pass');

    const strict = doctorJson(dir, ['--strict']);
    assert.equal(strict.code, 1, strict.out + strict.err);
    assert.equal(check(strict.body, 'audit').status, 'fail');
    assert.match(check(strict.body, 'audit').detail, /chain broken/);
    assert.equal(check(strict.body, 'policy').status, 'pass');
    const human = cliResult(dir, ['doctor', '--strict']);
    assert.equal(human.code, 1, human.out);
    assert.match(human.out, /\[FAIL\].*audit/);
  });
});

describe('v1.0.14 docs', () => {
  it('documents fail-closed policy, init --org, and leaves the live workflow alone', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.14\]/);
    assert.match(changelog, /init --org/);
    assert.match(changelog, /init --policy/);
    assert.match(changelog, /cryptographic signing/);
    assert.match(changelog, /pressure-gated/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /init --org/);
    assert.match(business, /fails unset org policy/);
    assert.match(business, /broken audit chain/);
    assert.match(business, /trailingIgnored/);
    assert.match(business, /prove --json/);
    assert.doesNotMatch(
      business,
      /policy \(`redact` \+ `failOn`\) and\/or retention is unset/,
    );
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /init --org/);
    assert.match(readme, /pressure-gates unset retention/);
    const policy = readFileSync(join(root, 'examples', 'org-policy.yml'), 'utf8');
    assert.match(policy, /init --org/);
    assert.match(policy, /always fails unset org policy/);
    assert.match(policy, /doctor --strict/);
    assert.match(policy, /doctor --json/);
    assert.equal(/^maxCount:/m.test(policy), false);
    assert.equal(/^maxAgeDays:/m.test(policy), false);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /init --org/);
    assert.match(mirror, /doctor --strict --json/);
    assert.match(mirror, /v1\.0\.15/);
    assert.doesNotMatch(mirror, /--strict stays exit 0/);
    const live = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.doesNotMatch(live, /init --org/);
    const gate = readFileSync(join(root, 'examples', 'github', 'pr-gate.yml'), 'utf8');
    assert.match(gate, /github:pramodreddyboddu\/agent-receipt/);
    assert.match(gate, /--fail-on/);
    assert.match(gate, /trailingIgnored/);
    assert.match(gate, /workflow_call/);
    const action = readFileSync(join(root, 'examples', 'github', 'action.yml'), 'utf8');
    assert.match(action, /trailingIgnored/);
    assert.match(action, /exitCode !== 0 \|\| g\.ok !== true/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.17');
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.17/);
    const helpInit = cli(root, ['help', 'init']);
    assert.match(helpInit, /--org/);
    assert.match(helpInit, /--policy/);
    assert.match(helpInit, /ignore/);
    assert.match(helpInit, /does not rewrite/);
    const helpDoctor = cli(root, ['help', 'doctor']);
    assert.match(helpDoctor, /broken audit chain/);
    assert.match(helpDoctor, /even when outDir is small/);
    assert.match(helpDoctor, /Unset retention fails under --strict on any outDir/);
    assert.doesNotMatch(helpDoctor, /and\/or retention still fail only when/);
    assert.match(cli(root, ['help']), /--org sets redact/);
  });
});
