import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');

const OTHER_FP = 'b'.repeat(64);

// Secret fixtures. Each must be redacted by the share rules before HTML render.
const SECRETS = {
  openai: 'sk-live-abcdefghijklmnopqrstuvwx1234567890',
  github: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123',
  aws: 'AKIAIOSFODNN7EXAMPLE',
  password: 'correct-horse-battery-staple',
};

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
  return { code: r.status === null ? 1 : r.status, out: r.stdout || '', err: r.stderr || '' };
}

function cli(cwd, args) {
  const r = cliResult(cwd, args);
  if (r.code !== 0) throw new Error(`exit ${r.code}\n${r.out}\n${r.err}`);
  return r.out;
}

const parseJson = (out) => JSON.parse(out);

function findFiles(dir, suffix) {
  const hits = [];
  const walk = (current) => {
    for (const ent of readdirSync(current, { withFileTypes: true })) {
      if (ent.name === '.git' || ent.name === 'node_modules') continue;
      const p = join(current, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.name.endsWith(suffix)) hits.push(p);
    }
  };
  walk(dir);
  return hits;
}

/** Offline / self-contained assertions shared by every HTML the tests write. */
function assertOffline(html) {
  assert.match(html, /^<!DOCTYPE html>/);
  assert.match(html, /<style>[\s\S]+<\/style>/);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /default-src 'none'/);
  assert.doesNotMatch(html, /src\s*=\s*["']?https?:/i);
  assert.doesNotMatch(html, /href\s*=\s*["']?https?:/i);
  assert.doesNotMatch(html, /url\(\s*["']?https?:/i);
  assert.doesNotMatch(html, /@import/i);
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /<link/i);
  assert.doesNotMatch(html, /<img/i);
  assert.doesNotMatch(html, /<iframe/i);
  assert.doesNotMatch(html, /https?:\/\//i, 'no http(s) URL anywhere in the report');
}

describe('v1.0.27 prove --html offline verification report', () => {
  const dirs = [];
  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1027-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# prove-html\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function wrapClean(dir, message, file = 'note.txt', content = `${message}\n`) {
    writeFileSync(join(dir, file), content);
    git(dir, ['add', file]);
    git(dir, ['commit', '-m', 'commit']);
    const wrapped = cliResult(dir, ['wrap', '--agent', 'ci', '--message', message]);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    return wrapped;
  }

  it('documents version 1.0.27, prove --html, htmlPath, and no new dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.27\]/);
    assert.match(changelog, /prove --html/);
    assert.match(changelog, /htmlPath/);
    assert.match(changelog, /not itself signed/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.27');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.27');
    assert.equal(lock.packages[''].version, '1.0.27');
    assert.equal(lock.packages[''].dependencies, undefined);
    assert.match(readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8'), /1\.0\.27/);

    const help = cli(root, ['help', 'prove']);
    assert.match(help, /--html/);
    assert.match(help, /foo\.prove\.html/);
    assert.match(help, /htmlPath/);
    assert.doesNotMatch(help, /HTML export of this page is deferred/);
    const global = cli(root, ['help']);
    assert.match(global, /--html/);

    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /prove --html/);
    assert.match(business, /1\.0\.27/);
    assert.doesNotMatch(business, /HTML export of the\s+one-pager stays deferred/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /prove --html/);
    assert.match(readme, /v1\.0\.27/);
    const recipe = readFileSync(join(root, 'docs', 'ci-signed-gate.md'), 'utf8');
    assert.match(recipe, /prove --json --html/);
    assert.match(recipe, /v1\.0\.27/);

    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.27/);
    assert.match(mirror, /prove --json --html/);
    assert.match(mirror, /htmlPath/);
    for (const rel of ['examples/github/action.yml', 'examples/github/pr-gate.yml', 'examples/org-policy.yml']) {
      assert.match(readFileSync(join(root, rel), 'utf8'), /v1\.0\.27/, rel);
    }
    // Live workflows are untouched by this cut.
    for (const name of readdirSync(join(root, '.github', 'workflows'))) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /prove --html/);
      assert.doesNotMatch(live, /v1\.0\.27/);
    }
  });

  it('writes a sibling foo.prove.html with a PASS banner and stays offline', () => {
    const dir = initRepo();
    wrapClean(dir, 'html-target');
    assert.deepEqual(findFiles(dir, '.prove.html'), []);

    const plain = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(plain.ok, true);
    assert.equal(plain.version, '1.0.27');
    assert.equal('htmlPath' in plain, false);
    assert.deepEqual(findFiles(dir, '.prove.html'), []);

    const auditPath = join(dir, '.agent-receipt', 'audit.jsonl');
    const auditBefore = readFileSync(auditPath, 'utf8');
    const human = cliResult(dir, ['prove', '--html']);
    assert.equal(human.code, 0, human.err);
    assert.match(human.out, /PROVED/);
    assert.match(human.out, /html: .*\.prove\.html/);
    assert.equal(readFileSync(auditPath, 'utf8'), auditBefore, 'prove --html does not append audit');

    const expected = plain.path.replace(/\.md$/i, '.prove.html');
    assert.equal(existsSync(expected), true);
    const html = readFileSync(expected, 'utf8');
    assertOffline(html);
    assert.match(html, /class="banner pass"/);
    assert.match(html, /data-verdict="PASS"/);
    assert.doesNotMatch(html, /data-verdict="FAIL"/);
    assert.match(html, new RegExp(plain.sha256));
    assert.match(html, /hash chain intact/);
    assert.match(html, /UNSIGNED/);
    assert.match(html, /Redaction/);
    assert.match(html, /agent-receipt 1\.0\.27/);
    assert.match(html, /not a certificate authority/);
    assert.match(html, /not itself signed/);
    assert.match(html, /Files changed/);
    assert.match(html, /Receipt summary/);

    // *.prove.html is not a receipt: last / prove still resolve the receipt.
    const last = parseJson(cli(dir, ['last', '--json']));
    assert.equal(last.path, plain.path);
    const again = parseJson(cli(dir, ['prove', '--json']));
    assert.equal(again.path, plain.path);
    const history = cli(dir, ['history']);
    assert.doesNotMatch(history, /\.prove\.html/);
  });

  it('writes a FAIL banner on a tampered receipt and keeps exit 2', () => {
    const dir = initRepo();
    wrapClean(dir, 'tamper-html');
    const ok = parseJson(cli(dir, ['prove', '--json']));
    writeFileSync(ok.path, readFileSync(ok.path, 'utf8').replace('tamper-html', 'tampered-body'));

    const bad = cliResult(dir, ['prove', '--json', '--html']);
    assert.equal(bad.code, 2, bad.out + bad.err);
    const body = parseJson(bad.out);
    assert.equal(body.ok, false);
    assert.equal(body.verified, false);
    assert.equal(body.htmlPath, ok.path.replace(/\.md$/i, '.prove.html'));
    const html = readFileSync(body.htmlPath, 'utf8');
    assertOffline(html);
    assert.match(html, /data-verdict="FAIL"/);
    assert.match(html, /class="banner fail"/);
    assert.doesNotMatch(html, /data-verdict="PASS"/);
    assert.match(html, /does not match/);

    const human = cliResult(dir, ['prove', '--html']);
    assert.equal(human.code, 2);
    assert.match(human.out, /FAILED/);
  });

  it('redacts secrets by default and escapes HTML / defangs URLs', () => {
    const dir = initRepo();
    const message = [
      `key ${SECRETS.openai}`,
      `token ${SECRETS.github}`,
      `aws ${SECRETS.aws}`,
      `password=${SECRETS.password}`,
      '<script>alert(1)</script>',
      'see https://evil.example.com/pwn.js',
    ].join(' ');
    const content = [
      `OPENAI_API_KEY=${SECRETS.openai}`,
      `GITHUB_TOKEN=${SECRETS.github}`,
      `AWS_ACCESS_KEY_ID=${SECRETS.aws}`,
      `PASSWORD=${SECRETS.password}`,
      '<script>alert(2)</script>',
      '',
    ].join('\n');
    wrapClean(dir, message, 'config.env.txt', content);
    const proved = parseJson(cli(dir, ['prove', '--json', '--html']));
    // The source receipt itself does carry the raw values (not redacted at capture),
    // so the assertions below prove the HTML path redacts on its own.
    const receipt = readFileSync(proved.path, 'utf8');
    assert.ok(receipt.includes(SECRETS.openai), 'fixture receipt should contain the raw secret');

    const html = readFileSync(proved.htmlPath, 'utf8');
    assertOffline(html);
    for (const [name, value] of Object.entries(SECRETS)) {
      assert.equal(html.includes(value), false, `raw ${name} secret leaked into HTML`);
    }
    assert.match(html, /REDACTED/);
    assert.doesNotMatch(html, /<script>alert/);
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(html, /https\[:\]\/\/evil\.example\.com/);
  });

  it('shows a valid trusted signature, and UNTRUSTED when the allowlist rejects it', () => {
    const dir = initRepo();
    wrapClean(dir, 'signed-html');
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    cli(dir, ['sign']);
    cli(dir, ['trust', 'add', '--self']);
    const proved = parseJson(cli(dir, ['prove', '--json', '--html']));
    assert.equal(proved.signature.ok, true);
    assert.equal(proved.signature.trusted, true);
    const html = readFileSync(proved.htmlPath, 'utf8');
    assertOffline(html);
    assert.match(html, /data-verdict="PASS"/);
    assert.match(html, /VALID/);
    assert.match(html, /TRUSTED/);
    assert.match(html, new RegExp(keys.fingerprint));
    assert.doesNotMatch(html, /UNSIGNED/);

    // Replace the allowlist with a different key: active store rejects → exit 2.
    writeFileSync(join(dir, '.agent-receipt', 'trusted-keys.txt'), `${OTHER_FP}\n`);
    const rejected = cliResult(dir, ['prove', '--json', '--html']);
    assert.equal(rejected.code, 2, rejected.out + rejected.err);
    const body = parseJson(rejected.out);
    const bad = readFileSync(body.htmlPath, 'utf8');
    assert.match(bad, /data-verdict="FAIL"/);
    assert.match(bad, /INVALID|UNTRUSTED/);
    assert.match(bad, /trust/i);
  });

  it('--out <file> and --out <dir>/ choose the destination; never overwrites the receipt', () => {
    const dir = initRepo();
    wrapClean(dir, 'out-html');
    const fileOut = parseJson(cli(dir, ['prove', '--json', '--html', '--out', 'reports/custom.html']));
    assert.equal(fileOut.htmlPath, join(dir, 'reports', 'custom.html'));
    assert.match(readFileSync(fileOut.htmlPath, 'utf8'), /data-verdict="PASS"/);

    const dirOut = parseJson(cli(dir, ['prove', '--json', '--html', '--out', 'out-dir/']));
    assert.equal(dirname(dirOut.htmlPath), join(dir, 'out-dir'));
    assert.equal(basename(dirOut.htmlPath), basename(dirOut.path).replace(/\.md$/i, '.prove.html'));

    mkdirSync(join(dir, 'existing'));
    const existing = parseJson(cli(dir, ['prove', '--json', '--html', '--out', 'existing']));
    assert.equal(dirname(existing.htmlPath), join(dir, 'existing'));

    const before = readFileSync(fileOut.path, 'utf8');
    const clobber = cliResult(dir, ['prove', '--html', '--out', fileOut.path]);
    assert.equal(clobber.code, 1);
    assert.match(clobber.err, /must not overwrite the source receipt/);
    assert.equal(readFileSync(fileOut.path, 'utf8'), before);
  });

  it('--html --page writes both; --out must then be a directory', () => {
    const dir = initRepo();
    wrapClean(dir, 'both-html');
    const both = parseJson(cli(dir, ['prove', '--json', '--html', '--page']));
    assert.equal(both.pagePath, both.path.replace(/\.md$/i, '.prove.md'));
    assert.equal(both.htmlPath, both.path.replace(/\.md$/i, '.prove.html'));
    assert.equal(existsSync(both.pagePath), true);
    assert.equal(existsSync(both.htmlPath), true);

    const inDir = parseJson(cli(dir, ['prove', '--json', '--one-pager', '--html', '--out', 'both/']));
    assert.equal(dirname(inDir.pagePath), join(dir, 'both'));
    assert.equal(dirname(inDir.htmlPath), join(dir, 'both'));

    const fileBoth = cliResult(dir, ['prove', '--json', '--html', '--page', '--out', 'one-file.html']);
    assert.equal(fileBoth.code, 1);
    assert.match(parseJson(fileBoth.out).reason, /must be a directory/);
    assert.equal(existsSync(join(dir, 'one-file.html')), false);
  });

  it('--out without --page or --html is a usage error; --html does not swallow the path', () => {
    const dir = initRepo();
    wrapClean(dir, 'usage-html');
    const r = cliResult(dir, ['prove', '--out', 'x.html']);
    assert.equal(r.code, 1);
    assert.match(r.err, /--out requires --page \(or --one-pager\) or --html/);

    const receipt = parseJson(cli(dir, ['prove', '--json'])).path;
    const positional = parseJson(cli(dir, ['prove', '--html', receipt, '--json']));
    assert.equal(positional.path, receipt);
    assert.equal(positional.htmlPath, receipt.replace(/\.md$/i, '.prove.html'));

    const unknown = cliResult(dir, ['prove', '--htm']);
    assert.equal(unknown.code, 1);
    assert.match(unknown.err, /--html/);
  });

  it('prune and a later wrap never treat *.prove.html as a receipt', () => {
    const dir = initRepo();
    wrapClean(dir, 'first');
    const first = parseJson(cli(dir, ['prove', '--json', '--html']));
    wrapClean(dir, 'second', 'note2.txt');
    const dry = parseJson(cli(dir, ['prune', '--dry-run', '--max-count', '1', '--json']));
    const listed = JSON.stringify(dry);
    assert.doesNotMatch(listed, /\.prove\.html/);
    assert.equal(existsSync(first.htmlPath), true);
    const last = parseJson(cli(dir, ['last', '--json']));
    assert.doesNotMatch(last.path, /\.prove\.html$/);
  });

  it('renderProveHtml is exported and pure', async () => {
    const mod = await import(join(root, 'dist', 'index.js'));
    assert.equal(typeof mod.renderProveHtml, 'function');
    assert.equal(mod.defangUrls('go https://x.y/z'), 'go https[:]//x.y/z');
  });
});
