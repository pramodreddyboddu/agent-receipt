import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  appendHashFooter,
  verifyMarkdown,
  sha256Hex,
  canonicalBody,
  extractEmbeddedHash,
} from '../dist/lib/hash.js';

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
});
