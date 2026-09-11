import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { writeDefaultConfig } from '../lib/config.js';
import { CURSOR_RULE_MDC, CURSOR_RULE_REL } from '../lib/cursor-rule.js';
import { color } from '../lib/color.js';

export interface InitOptions {
  /** Write .cursor/rules/agent-receipt.mdc so Cursor agents capture on wrap-up. */
  cursor?: boolean;
}

export function writeCursorRule(cwd: string): string {
  const dest = join(cwd, CURSOR_RULE_REL);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, CURSOR_RULE_MDC, 'utf8');
  return dest;
}

export function cmdInit(cwd: string, opts: InitOptions = {}): void {
  const { configFile, notesFile } = writeDefaultConfig(cwd);
  console.log(color.green('✓') + ' Initialized agent-receipt');
  console.log(`  config: ${configFile}`);
  console.log(`  notes:  ${notesFile}`);
  if (opts.cursor) {
    const rule = writeCursorRule(cwd);
    console.log(`  cursor: ${rule}`);
  }
  console.log('');
  console.log('Next steps:');
  console.log('  agent-receipt capture --agent cursor --message "session notes"');
  console.log('  agent-receipt history');
  console.log('  agent-receipt last');
  console.log('  agent-receipt install-hooks   # optional auto-capture on commit');
  console.log('  agent-receipt watch --once    # capture after the next commit');
  if (!opts.cursor) {
    console.log('  agent-receipt init --cursor   # drop Cursor rule (agent runs capture)');
  }
}
