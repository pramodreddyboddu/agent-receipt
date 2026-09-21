import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { writeDefaultConfig } from '../lib/config.js';
import { CURSOR_RULE_MDC, CURSOR_RULE_REL } from '../lib/cursor-rule.js';
import {
  GROK_HOOK_JSON,
  GROK_HOOK_REL,
  GROK_RULE_MD,
  GROK_RULE_REL,
  GROK_WRAP_SCRIPT,
  GROK_WRAP_SCRIPT_REL,
} from '../lib/grok-rule.js';
import { color } from '../lib/color.js';

export interface InitOptions {
  /** Write .cursor/rules/agent-receipt.mdc so Cursor agents capture on wrap-up. */
  cursor?: boolean;
  /** Write .grok rule + SessionEnd hook so Grok Build sessions can wrap. */
  grok?: boolean;
}

export function writeCursorRule(cwd: string): string {
  const dest = join(cwd, CURSOR_RULE_REL);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, CURSOR_RULE_MDC, 'utf8');
  return dest;
}

export interface GrokIntegrationPaths {
  rule: string;
  hook: string;
  script: string;
}

/** Rule Grok loads every session, plus a non-blocking dirty-tree SessionEnd hook. */
export function writeGrokIntegration(cwd: string): GrokIntegrationPaths {
  const rule = join(cwd, GROK_RULE_REL);
  const hook = join(cwd, GROK_HOOK_REL);
  const script = join(cwd, GROK_WRAP_SCRIPT_REL);
  mkdirSync(dirname(rule), { recursive: true });
  mkdirSync(dirname(script), { recursive: true });
  writeFileSync(rule, GROK_RULE_MD, 'utf8');
  writeFileSync(hook, GROK_HOOK_JSON, 'utf8');
  writeFileSync(script, GROK_WRAP_SCRIPT, 'utf8');
  try {
    chmodSync(script, 0o755);
  } catch {
    // The hook invokes `sh`, so a missing +x bit is non-fatal.
  }
  return { rule, hook, script };
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
  if (opts.grok) {
    const grok = writeGrokIntegration(cwd);
    console.log(`  grok:   ${grok.rule}`);
    console.log(`  hook:   ${grok.hook}`);
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
  if (!opts.grok) {
    console.log('  agent-receipt init --grok     # Grok rule + SessionEnd hook (--redact)');
  } else {
    console.log('  agent-receipt wrap --agent grok --redact --message "what changed"');
    console.log('  Trust Grok project hooks once: grok --trust   (or /hooks-trust)');
  }
}
