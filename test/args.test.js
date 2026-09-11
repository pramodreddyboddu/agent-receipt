import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, flagString, flagBool, flagNumber } from '../dist/lib/args.js';

describe('parseArgs', () => {
  it('parses command and flags', () => {
    const p = parseArgs([
      'node',
      'bin',
      'capture',
      '--since',
      'main',
      '--commits',
      '3',
      '--full',
      '--message',
      'hi',
    ]);
    assert.equal(p.command, 'capture');
    assert.equal(flagString(p.flags, 'since'), 'main');
    assert.equal(flagNumber(p.flags, 'commits'), 3);
    assert.equal(flagBool(p.flags, 'full'), true);
    assert.equal(flagString(p.flags, 'message'), 'hi');
  });

  it('supports --key=value', () => {
    const p = parseArgs(['node', 'bin', 'capture', '--agent=cursor']);
    assert.equal(flagString(p.flags, 'agent'), 'cursor');
  });

  it('defaults to help', () => {
    const p = parseArgs(['node', 'bin']);
    assert.equal(p.command, 'help');
  });
});
