import { readFileSync } from 'node:fs';
import { verifyMarkdown } from '../lib/hash.js';
import { resolveReceiptPath } from './show.js';

export function cmdVerify(cwd: string, pathArg?: string): boolean {
  const path = resolveReceiptPath(cwd, pathArg);
  const text = readFileSync(path, 'utf8');
  const result = verifyMarkdown(text);

  console.log(`Verifying: ${path}`);
  if (result.ok) {
    console.log('✓ OK — receipt integrity verified');
    console.log(`  sha256: ${result.actual}`);
    return true;
  }
  console.error('✗ FAIL — ' + result.reason);
  if (result.expected) console.error(`  expected: ${result.expected}`);
  console.error(`  actual:   ${result.actual}`);
  console.error('The Markdown body no longer matches the embedded hash.');
  return false;
}
