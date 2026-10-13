import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  appendHashFooter,
  verifyMarkdown,
  sha256Hex,
  canonicalBody,
  extractEmbeddedHash,
} from '../dist/lib/hash.js';

/** Bytes v1.0.42 wrote: cut at the first marker and drop the rest. */
function sealLikeV1042(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const out = [];
  for (const line of lines) {
    if (line.startsWith('## Integrity') || line.includes('agent-receipt-sha256')) break;
    out.push(line);
  }
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
  const body = `${out.join('\n')}\n`;
  const hash = sha256Hex(body);
  return `${body}\n## Integrity\n\n<!-- agent-receipt-sha256:${hash} -->\n\nSHA-256 of canonical body: \`${hash}\`\n`;
}

describe('hash / integrity', () => {
  it('sha256Hex is stable', () => {
    assert.equal(
      sha256Hex('hello\n'),
      '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03',
    );
  });

  it('appendHashFooter embeds verifiable hash', () => {
    const md = '# Agent Receipt\n\n- **Branch**: `main`\n';
    const withHash = appendHashFooter(md);
    assert.match(withHash, /agent-receipt-sha256:[a-f0-9]{64}/);
    const result = verifyMarkdown(withHash);
    assert.equal(result.ok, true);
    assert.equal(result.reason, 'OK');
  });

  it('detects tampering', () => {
    const md = appendHashFooter('# Agent Receipt\n\nhello\n');
    const tampered = md.replace('hello', 'HELLO');
    const result = verifyMarkdown(tampered);
    assert.equal(result.ok, false);
    assert.match(result.reason, /mismatch|tamper/i);
  });

  it('fails when marker missing', () => {
    const result = verifyMarkdown('# no hash here\n');
    assert.equal(result.ok, false);
    assert.match(result.reason, /No embedded/i);
  });

  it('canonicalBody strips integrity section', () => {
    const full = appendHashFooter('# Title\n\nbody\n');
    const body = canonicalBody(full);
    assert.equal(body.includes('agent-receipt-sha256'), false);
    assert.equal(body.includes('## Integrity'), false);
    assert.equal(extractEmbeddedHash(full)?.length, 64);
  });

  it('does not let diff context fences hide the integrity footer', () => {
    const raw = [
      '# Agent Receipt',
      '',
      '- **Version**: 1.0.43',
      '',
      '```diff',
      'diff --git a/doc.md b/doc.md',
      '--- a/doc.md',
      '+++ b/doc.md',
      '@@ -1,11 +1,11 @@',
      ' # Notes',
      ' ',
      ' ```js',
      '-const value = "before";',
      '+const value = "after-fence";',
      ' ```',
      ' ',
      ' tail',
      ' ~~~',
      ' tilde',
      ' ~~~',
      '+<!-- agent-receipt-sha256: ' + 'ab'.repeat(32) + ' -->',
      '+SENTINEL-AFTER-MARKER',
      '## Integrity',
      'quoted heading stays',
      '```',
      '',
      'after diff',
      '',
    ].join('\n');
    const sealed = appendHashFooter(raw);
    const body = canonicalBody(sealed);
    assert.match(body, /after-fence/);
    assert.match(body, /SENTINEL-AFTER-MARKER/);
    assert.match(body, /quoted heading stays/);
    assert.match(body, /after diff/);
    assert.match(body, /tilde/);
    assert.equal((body.match(/^## Integrity$/gm) || []).length, 1);
    assert.match(body, /\+<!-- agent-receipt-sha256:/);
    assert.equal(body.includes('\n<!-- agent-receipt-sha256:'), false);
    const check = verifyMarkdown(sealed);
    assert.equal(check.ok, true, check.reason);
    assert.equal(check.trailingIgnored, false);
  });

  it('keeps the v1.0.42 cut when a diff quoted the hash marker', () => {
    const raw = [
      '# Agent Receipt',
      '',
      '- **Version**: 1.0.42',
      '',
      '```diff',
      'diff --git a/old.md b/old.md',
      '--- a/old.md',
      '+++ b/old.md',
      '@@ -1,3 +1,6 @@',
      ' kept',
      '## Integrity',
      '<!-- agent-receipt-sha256: ' + 'cd'.repeat(32) + ' -->',
      '+AFTER-HASH-LINE',
      '```',
      '',
      'after the fence',
      '',
    ].join('\n');
    const sealed = sealLikeV1042(raw);
    assert.equal(sealed.includes('AFTER-HASH-LINE'), false);
    assert.equal(sealed.includes('after the fence'), false);
    assert.match(sealed, /```diff/);
    assert.equal(sealed.includes('\n```\n'), false);
    const check = verifyMarkdown(sealed);
    assert.equal(check.ok, true, check.reason);
    assert.equal(canonicalBody(sealed).includes('## Integrity'), false);
    assert.match(canonicalBody(sealed), /```diff/);
    assert.equal(canonicalBody(sealed).includes('AFTER-HASH-LINE'), false);
  });

  it('keeps the v1.0.42 cut when a fenced block quoted the marker', () => {
    const raw = [
      '# Agent Receipt',
      '',
      '- **Version**: 1.0.42',
      '',
      '```',
      '<!-- agent-receipt-sha256: ' + 'ef'.repeat(32) + ' -->',
      'SENTINEL',
      '```',
      '',
      'after',
      '',
    ].join('\n');
    const sealed = sealLikeV1042(raw);
    assert.equal(sealed.includes('SENTINEL'), false);
    const check = verifyMarkdown(sealed);
    assert.equal(check.ok, true, check.reason);
    assert.match(canonicalBody(sealed), /```/);
    assert.equal(canonicalBody(sealed).includes('after'), false);
  });
});
