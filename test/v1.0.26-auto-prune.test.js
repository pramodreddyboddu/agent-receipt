import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
  appendFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
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

function pause() {
  execFileSync('sleep', ['0.05']);
}

function auditEvents(dir) {
  const path = join(dir, '.agent-receipt', 'audit.jsonl');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

function receiptFiles(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  if (!existsSync(out)) return [];
  return readdirSync(out)
    .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
    .sort();
}

describe('v1.0.26 auto-prune', () => {
  const dirs = [];

  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo(yml) {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1026-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# auto-prune\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    if (yml) writeFileSync(join(dir, '.agent-receipt.yml'), yml);
    return dir;
  }

  function commitChange(dir, name, body) {
    writeFileSync(join(dir, name), body);
    git(dir, ['add', name]);
    git(dir, ['commit', '-m', name]);
  }

  function wrap(dir, message, extra = []) {
    pause();
    commitChange(dir, `${message}.txt`, `${message}\n`);
    return cliResult(dir, ['wrap', '--agent', 'ci', '--message', message, ...extra]);
  }

  it('documents version 1.0.26, autoPrune, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.26\]/);
    assert.match(changelog, /autoPrune/);
    assert.match(changelog, /--no-prune/);
    assert.match(changelog, /--prune/);
    assert.match(changelog, /chain/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /was not edited|not\*\* updated/);
    assert.match(changelog, /not a CA/i);
    assert.match(changelog, /prove --html/);
    assert.match(changelog, /daemon/);
    assert.match(changelog, /not a daemon|Not a daemon/i);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.26');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.26');
    assert.equal(lock.packages[''].version, '1.0.26');
    assert.equal(lock.packages[''].dependencies, undefined);
    const versionTs = readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8');
    assert.match(versionTs, /1\.0\.26/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /autoPrune/);
    assert.match(business, /1\.0\.26/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.26/);
    assert.match(mirror, /autoPrune/);
    const gateSchema = JSON.parse(readFileSync(join(root, 'docs', 'gate.schema.json'), 'utf8'));
    assert.equal(gateSchema.required.includes('autoPrune'), false);
    assert.equal(gateSchema.required.includes('pruned'), false);
    assert.equal(gateSchema.required.includes('pruneReason'), false);
    assert.equal(typeof gateSchema.properties.autoPrune, 'object');
    assert.equal(typeof gateSchema.properties.pruned, 'object');
    assert.equal(typeof gateSchema.properties.pruneReason, 'object');
    const helpWrap = cli(root, ['help', 'wrap']);
    assert.match(helpWrap, /--no-prune/);
    assert.match(helpWrap, /--prune/);
    assert.match(helpWrap, /pruneReason/);
    const helpInit = cli(root, ['help', 'init']);
    assert.match(helpInit, /--auto-prune/);
    assert.match(helpInit, /does not turn `autoPrune` on|does not set autoPrune/);
    const workflows = readdirSync(join(root, '.github', 'workflows'));
    for (const name of workflows) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /v1\.0\.26/);
      assert.doesNotMatch(live, /autoPrune/);
    }
  });

  it('leaves receipts in place when autoPrune is unset or false', () => {
    const dir = initRepo('outDir: .agent-receipt/receipts\nmaxCount: 1\n');
    const first = wrap(dir, 'keep-a');
    assert.equal(first.code, 0, first.out + first.err);
    const second = wrap(dir, 'keep-b', ['--json']);
    assert.equal(second.code, 0, second.out + second.err);
    const gate = parseJson(second.out);
    assert.equal(gate.exitCode, 0);
    assert.equal(Object.prototype.hasOwnProperty.call(gate, 'autoPrune'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(gate, 'pruned'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(gate, 'pruneReason'), false);
    assert.equal(receiptFiles(dir).length, 2);
    assert.equal(auditEvents(dir).some((e) => e.event === 'prune'), false);
    assert.doesNotMatch(second.out, /pruned:/);
    assert.doesNotMatch(second.err, /pruned:/);

    const explicit = initRepo(
      'outDir: .agent-receipt/receipts\nmaxCount: 1\nautoPrune: false\n',
    );
    assert.equal(wrap(explicit, 'off-a').code, 0);
    const off = wrap(explicit, 'off-b');
    assert.equal(off.code, 0, off.out + off.err);
    assert.equal(receiptFiles(explicit).length, 2);
    assert.doesNotMatch(off.out, /pruned:/);
  });

  it('deletes older receipts when autoPrune is true and maxCount is set', () => {
    const dir = initRepo(
      'outDir: .agent-receipt/receipts\nmaxCount: 1\nautoPrune: true\n',
    );
    const first = wrap(dir, 'old');
    assert.equal(first.code, 0, first.out + first.err);
    const firstGate = cliResult(dir, ['last', '--json']);
    const firstPath = parseJson(firstGate.out).path;
    const second = wrap(dir, 'new', ['--json']);
    assert.equal(second.code, 0, second.out + second.err);
    const gate = parseJson(second.out);
    assert.equal(gate.command, 'wrap');
    assert.equal(gate.exitCode, 0);
    assert.equal(gate.autoPrune, true);
    assert.equal(gate.pruned, 1);
    assert.equal(gate.pruneReason, null);
    assert.equal(existsSync(gate.path), true);
    assert.equal(existsSync(firstPath), false);
    assert.notEqual(basename(gate.path), basename(firstPath));
    const files = receiptFiles(dir);
    assert.deepEqual(files, [basename(gate.path)]);
    const prunes = auditEvents(dir).filter((e) => e.event === 'prune');
    assert.equal(prunes.length, 1);
    assert.match(prunes[0].path, /old|receipt-/);
    assert.match(prunes[0].path, new RegExp(basename(firstPath).replace(/\./g, '\\.')));
    const events = auditEvents(dir);
    assert.equal(events[events.length - 1].event, 'prune');
    assert.equal(events[events.length - 2].event, 'wrap');
    assert.equal(cliResult(dir, ['audit', '--verify']).code, 0);
    assert.match(second.err, /pruned: 1 receipt/);
    assert.doesNotMatch(second.out, /pruned:/);
  });

  it('deletes nothing when autoPrune is true and retention limits are unset', () => {
    const dir = initRepo('outDir: .agent-receipt/receipts\nautoPrune: true\n');
    assert.equal(wrap(dir, 'nolimit-a').code, 0);
    const second = wrap(dir, 'nolimit-b', ['--json']);
    assert.equal(second.code, 0, second.out + second.err);
    const gate = parseJson(second.out);
    assert.equal(gate.autoPrune, true);
    assert.equal(gate.pruned, 0);
    assert.equal(gate.pruneReason, 'retention-off');
    assert.equal(receiptFiles(dir).length, 2);
    assert.equal(auditEvents(dir).some((e) => e.event === 'prune'), false);
    assert.doesNotMatch(second.out + second.err, /pruned:/);
  });

  it('lets --no-prune override config autoPrune, and --prune force it on', () => {
    const on = initRepo(
      'outDir: .agent-receipt/receipts\nmaxCount: 1\nautoPrune: true\n',
    );
    assert.equal(wrap(on, 'override-a').code, 0);
    const kept = wrap(on, 'override-b', ['--no-prune', '--json']);
    assert.equal(kept.code, 0, kept.out + kept.err);
    const keptGate = parseJson(kept.out);
    assert.equal(Object.prototype.hasOwnProperty.call(keptGate, 'autoPrune'), false);
    assert.equal(receiptFiles(on).length, 2);
    assert.equal(auditEvents(on).some((e) => e.event === 'prune'), false);

    const both = wrap(on, 'override-c', ['--prune', '--no-prune']);
    assert.equal(both.code, 0, both.out + both.err);
    assert.equal(receiptFiles(on).length, 3);
    assert.doesNotMatch(both.out, /pruned:/);

    const off = initRepo('outDir: .agent-receipt/receipts\nmaxCount: 1\n');
    assert.equal(wrap(off, 'force-a').code, 0);
    const forced = wrap(off, 'force-b', ['--prune']);
    assert.equal(forced.code, 0, forced.out + forced.err);
    assert.equal(receiptFiles(off).length, 1);
    assert.match(forced.out, /pruned: 1 receipt/);
    assert.equal(auditEvents(off).filter((e) => e.event === 'prune').length, 1);
  });

  it('keeps the new receipt when the audit chain is broken and does not fail wrap or capture', () => {
    const dir = initRepo(
      'outDir: .agent-receipt/receipts\nmaxCount: 1\nautoPrune: true\n',
    );
    const first = wrap(dir, 'chain-a', ['--json']);
    assert.equal(first.code, 0, first.out + first.err);
    const firstPath = parseJson(first.out).path;
    appendFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), '{"event":"wrap"}\n');
    const broken = wrap(dir, 'chain-b', ['--json']);
    assert.equal(broken.code, 0, broken.out + broken.err);
    const gate = parseJson(broken.out);
    assert.equal(gate.exitCode, 0);
    assert.equal(gate.ok, true);
    assert.equal(gate.autoPrune, true);
    assert.equal(gate.pruned, 0);
    assert.equal(gate.pruneReason, 'chain-broken');
    assert.equal(existsSync(gate.path), true);
    assert.equal(existsSync(firstPath), true);
    assert.equal(receiptFiles(dir).length, 2);
    assert.match(broken.err, /audit chain broken/);
    assert.match(broken.err, /prune --force/);
    assert.match(broken.err, /pruned: skipped \(audit chain broken\)/);
    assert.equal(
      auditEvents(dir).filter((e) => e.event === 'prune').length,
      0,
    );

    const manual = cliResult(dir, ['prune', '--json']);
    assert.equal(manual.code, 1, manual.out + manual.err);
    const body = parseJson(manual.out);
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 1);
    assert.equal(body.chainOk, false);
    assert.equal(body.audited, 0);
    assert.equal(existsSync(firstPath), true);
    assert.equal(existsSync(gate.path), true);

    commitChange(dir, 'capture-extra.txt', 'capture\n');
    const captured = cliResult(dir, [
      'capture',
      '--agent',
      'ci',
      '--message',
      'chain-capture',
      '--json',
    ]);
    assert.equal(captured.code, 0, captured.out + captured.err);
    const cap = parseJson(captured.out);
    assert.equal(cap.command, 'capture');
    assert.equal(cap.exitCode, 0);
    assert.equal(cap.autoPrune, true);
    assert.equal(cap.pruned, 0);
    assert.equal(cap.pruneReason, 'chain-broken');
    assert.equal(existsSync(cap.path), true);
    assert.match(captured.err, /audit chain broken/);
    assert.equal(receiptFiles(dir).length, 3);
  });

  it('warns and still exits 0 when retention config is invalid', () => {
    const dir = initRepo(
      'outDir: .agent-receipt/receipts\nautoPrune: true\nmaxCount: 0\n',
    );
    const wrapped = wrap(dir, 'bad-limit', ['--json']);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    const gate = parseJson(wrapped.out);
    assert.equal(gate.exitCode, 0);
    assert.equal(gate.autoPrune, true);
    assert.equal(gate.pruned, 0);
    assert.equal(gate.pruneReason, 'error');
    assert.equal(existsSync(gate.path), true);
    assert.match(wrapped.err, /auto-prune failed/);
    assert.equal(receiptFiles(dir).length, 1);
    const manual = cliResult(dir, ['prune']);
    assert.equal(manual.code, 1);
    assert.match(manual.err, /maxCount/);
  });

  it('does not auto-prune on share', () => {
    const dir = initRepo(
      'outDir: .agent-receipt/receipts\nmaxCount: 1\nautoPrune: true\n',
    );
    assert.equal(wrap(dir, 'share-a', ['--no-prune']).code, 0);
    assert.equal(wrap(dir, 'share-b', ['--no-prune']).code, 0);
    assert.equal(receiptFiles(dir).length, 2);
    const shared = cliResult(dir, ['share', '--json']);
    assert.equal(shared.code, 0, shared.out + shared.err);
    const gate = parseJson(shared.out);
    assert.equal(gate.command, 'share');
    assert.equal(Object.prototype.hasOwnProperty.call(gate, 'autoPrune'), false);
    assert.equal(receiptFiles(dir).length, 2);
    assert.equal(auditEvents(dir).some((e) => e.event === 'prune'), false);
  });

  it('reports autoPrune on doctor and does not fail --strict when it is unset', () => {
    const plain = mkdtempSync(join(tmpdir(), 'agent-receipt-1026-doc-'));
    dirs.push(plain);
    git(plain, ['init']);
    git(plain, ['config', 'user.email', 'test@example.com']);
    git(plain, ['config', 'user.name', 'Test']);
    cli(plain, ['init', '--org']);
    cli(plain, ['init', '--retention']);
    const yml = readFileSync(join(plain, '.agent-receipt.yml'), 'utf8');
    assert.match(yml, /^maxCount:\s*100\s*$/m);
    assert.doesNotMatch(yml, /^autoPrune:\s*true\s*$/m);
    assert.match(yml, /autoPrune: true/);
    const strict = cliResult(plain, ['doctor', '--strict', '--json']);
    assert.equal(strict.code, 0, strict.out + strict.err);
    const body = parseJson(strict.out);
    const row = body.checks.find((c) => c.id === 'autoPrune');
    assert.ok(row);
    assert.equal(row.status, 'info');

    const warned = initRepo(
      'outDir: .agent-receipt/receipts\nredact: true\nfailOn: high\nautoPrune: true\n',
    );
    const soft = cliResult(warned, ['doctor', '--json']);
    assert.equal(soft.code, 0, soft.out + soft.err);
    const softRow = parseJson(soft.out).checks.find((c) => c.id === 'autoPrune');
    assert.equal(softRow.status, 'warn');
    assert.match(softRow.detail, /init --retention/);
    const hard = cliResult(warned, ['doctor', '--strict', '--json']);
    assert.equal(hard.code, 1);
    const hardBody = parseJson(hard.out);
    assert.equal(hardBody.checks.find((c) => c.id === 'autoPrune').status, 'warn');
    assert.equal(hardBody.checks.find((c) => c.id === 'retention').status, 'fail');

    const ready = initRepo(
      'outDir: .agent-receipt/receipts\nredact: true\nfailOn: high\nmaxCount: 100\nautoPrune: true\n',
    );
    const pass = cliResult(ready, ['doctor', '--strict', '--json']);
    assert.equal(pass.code, 0, pass.out + pass.err);
    assert.equal(parseJson(pass.out).checks.find((c) => c.id === 'autoPrune').status, 'pass');

    const invalid = initRepo('outDir: .agent-receipt/receipts\nautoPrune: yes\n');
    const bad = cliResult(invalid, ['doctor', '--json']);
    assert.equal(bad.code, 1);
    const checks = parseJson(bad.out).checks;
    assert.equal(checks.find((c) => c.id === 'config').status, 'fail');
    assert.match(checks.find((c) => c.id === 'config').detail, /autoPrune must be true or false/);
    assert.equal(checks.find((c) => c.id === 'autoPrune').status, 'info');
  });

  it('init --auto-prune sets the flag without replacing ignore or redact', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1026-init-'));
    dirs.push(dir);
    const onlyLimits = cli(dir, ['init', '--retention']);
    assert.match(onlyLimits, /maxCount: 100 \(set\)/);
    assert.doesNotMatch(onlyLimits, /autoPrune: true \(set\)/);
    const ymlPath = join(dir, '.agent-receipt.yml');
    assert.doesNotMatch(readFileSync(ymlPath, 'utf8'), /^autoPrune:\s*true\s*$/m);

    writeFileSync(
      ymlPath,
      [
        'outDir: .agent-receipt/receipts',
        'ignore:',
        '  - node_modules/**',
        '  - secret-local/**',
        'redact: true',
        'failOn: medium',
        'maxCount: 40',
        '',
      ].join('\n'),
    );
    const merged = cli(dir, ['init', '--auto-prune']);
    assert.match(merged, /Auto-prune applied/);
    assert.match(merged, /autoPrune: true \(set\)/);
    const after = readFileSync(ymlPath, 'utf8');
    assert.match(after, /^autoPrune:\s*true\s*$/m);
    assert.match(after, /secret-local\/\*\*/);
    assert.match(after, /^redact:\s*true\s*$/m);
    assert.match(after, /^failOn:\s*medium\s*$/m);
    assert.match(after, /^maxCount:\s*40\s*$/m);
    const again = cli(dir, ['init', '--auto-prune']);
    assert.match(again, /autoPrune: true \(unchanged\)/);
    assert.equal(readFileSync(ymlPath, 'utf8'), after);

    const both = cli(dir, ['init', '--retention', '--auto-prune']);
    assert.match(both, /maxCount: 100/);
    assert.match(both, /autoPrune: true \(unchanged\)/);
    const combined = readFileSync(ymlPath, 'utf8');
    assert.match(combined, /^maxCount:\s*100\s*$/m);
    assert.match(combined, /^maxAgeDays:\s*30\s*$/m);
    assert.match(combined, /^autoPrune:\s*true\s*$/m);
    assert.match(combined, /secret-local\/\*\*/);
    assert.match(combined, /^redact:\s*true\s*$/m);
  });

  it('watch --once prunes after a successful capture when autoPrune is set', async () => {
    const dir = initRepo(
      'outDir: .agent-receipt/receipts\nmaxCount: 1\nautoPrune: true\n',
    );
    const first = wrap(dir, 'watch-seed', ['--no-prune', '--json']);
    assert.equal(first.code, 0, first.out + first.err);
    const seeded = parseJson(first.out).path;
    assert.equal(receiptFiles(dir).length, 1);

    const child = spawn(
      process.execPath,
      [bin, 'watch', '--once', '--interval', '1', '--agent', 'watch-bot', '--message', 'watched'],
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
    commitChange(dir, 'watched.js', 'export const w = 1;\n');
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
    assert.equal(receiptFiles(dir).length, 1);
    assert.equal(existsSync(seeded), false);
    assert.match(stdout, /pruned: 1 receipt/);
    const events = auditEvents(dir);
    assert.equal(events.filter((e) => e.event === 'watch').length, 1);
    assert.equal(events.filter((e) => e.event === 'prune').length, 1);
    assert.equal(events[events.length - 1].event, 'prune');
    assert.equal(cliResult(dir, ['audit', '--verify']).code, 0);
  });
});
