import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { configPath, writeDefaultConfig } from '../lib/config.js';
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
  /**
   * Set `redact: true` and `failOn: high` on `.agent-receipt.yml`.
   * Missing config is written like `init`, with those keys enabled.
   * An existing file is merged in place (ignore, outDir, retention stay).
   */
  org?: boolean;
  /**
   * Set `maxCount: 100` and `maxAgeDays: 30` on `.agent-receipt.yml`.
   * Missing config is written like `init`, with those keys enabled.
   * An existing file is merged in place (ignore, redact, failOn stay).
   * Does not set `autoPrune` (sudden deletes surprise existing users).
   */
  retention?: boolean;
  /**
   * Set `autoPrune: true` without replacing ignore, redact, failOn, or
   * retention limits. Combine with `--retention` when both should be set.
   * Does not delete anything by itself.
   */
  autoPrune?: boolean;
}

/** Disk-pressure tip and examples/org-policy.yml use these same numbers. */
export const INIT_RETENTION_MAX_COUNT = '100';
export const INIT_RETENTION_MAX_AGE_DAYS = '30';

export interface OrgPolicyYamlResult {
  text: string;
  redactChanged: boolean;
  failOnChanged: boolean;
}

export interface OrgPolicyResult {
  configFile: string;
  notesFile: string;
  created: boolean;
  redactChanged: boolean;
  failOnChanged: boolean;
}

function stripCr(line: string): { text: string; cr: string } {
  if (line.endsWith('\r')) return { text: line.slice(0, -1), cr: '\r' };
  return { text: line, cr: '' };
}

/** Scalar before an inline comment, with surrounding quotes removed. */
function normalizeScalar(raw: string): string {
  let v = raw.trim();
  const hash = v.search(/\s#/);
  if (hash >= 0) v = v.slice(0, hash).trim();
  if (
    (v.startsWith('"') && v.endsWith('"') && v.length >= 2) ||
    (v.startsWith("'") && v.endsWith("'") && v.length >= 2)
  ) {
    v = v.slice(1, -1);
  }
  return v;
}

/**
 * Set one top-level key. Active lines win: every uncommented `key:` is
 * rewritten. A commented `# key:` line is uncommented only when no active
 * line exists. Otherwise the key is appended. Other lines are untouched.
 * Returns whether the text changed.
 */
function setYamlScalar(lines: string[], key: string, value: string): boolean {
  const active = new RegExp(`^(\\s*)${key}\\s*:(.*)$`);
  const commented = new RegExp(`^(\\s*)#\\s*${key}\\s*:(.*)$`);
  const hits: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    const { text } = stripCr(lines[i]);
    if (text.trimStart().startsWith('#')) continue;
    if (active.test(text)) hits.push(i);
  }
  if (hits.length) {
    let changed = false;
    for (const i of hits) {
      const { text, cr } = stripCr(lines[i]);
      const m = text.match(active);
      if (!m) continue;
      if (normalizeScalar(m[2]) === value) continue;
      const inline = m[2].match(/(\s+#.*)$/);
      lines[i] = `${m[1]}${key}: ${value}${inline ? inline[1] : ''}${cr}`;
      changed = true;
    }
    return changed;
  }
  for (let i = 0; i < lines.length; i++) {
    const { text, cr } = stripCr(lines[i]);
    const m = text.match(commented);
    if (!m) continue;
    lines[i] = `${m[1]}${key}: ${value}${cr}`;
    return true;
  }
  if (lines.length && (lines[lines.length - 1] === '' || lines[lines.length - 1] === '\r')) {
    lines.splice(lines.length - 1, 0, `${key}: ${value}`);
  } else {
    lines.push(`${key}: ${value}`);
  }
  return true;
}

/**
 * Enable org policy keys in YAML text. Does not rewrite `ignore`,
 * `riskAllowlist`, `outDir`, retention keys, or unrelated comments.
 * Already-correct keys are left byte-for-byte alone.
 */
export function applyOrgPolicyYaml(text: string): OrgPolicyYamlResult {
  const lines = text.split('\n');
  const redactChanged = setYamlScalar(lines, 'redact', 'true');
  const failOnChanged = setYamlScalar(lines, 'failOn', 'high');
  if (!redactChanged && !failOnChanged) {
    return { text, redactChanged: false, failOnChanged: false };
  }
  let next = lines.join('\n');
  if (!next.endsWith('\n')) next += '\n';
  return { text: next, redactChanged, failOnChanged };
}

/**
 * Write org policy onto `.agent-receipt.yml`. Creates the default config
 * first when the file is missing. Does not replace an existing file's
 * ignore list or other keys.
 */
export function applyOrgPolicy(cwd: string): OrgPolicyResult {
  const configFile = configPath(cwd);
  const created = !existsSync(configFile);
  let notesFile = join(cwd, '.agent-receipt', 'SETUP.md');
  if (created) {
    const written = writeDefaultConfig(cwd);
    notesFile = written.notesFile;
  }
  const before = readFileSync(configFile, 'utf8');
  const applied = applyOrgPolicyYaml(before);
  if (applied.text !== before) writeFileSync(configFile, applied.text, 'utf8');
  return {
    configFile,
    notesFile,
    created,
    redactChanged: applied.redactChanged,
    failOnChanged: applied.failOnChanged,
  };
}

export interface RetentionYamlResult {
  text: string;
  maxCountChanged: boolean;
  maxAgeDaysChanged: boolean;
}

export interface RetentionResult {
  configFile: string;
  notesFile: string;
  created: boolean;
  maxCountChanged: boolean;
  maxAgeDaysChanged: boolean;
}

/**
 * Enable retention defaults in YAML text. Does not rewrite `ignore`,
 * `redact`, `failOn`, `outDir`, or unrelated comments.
 * Already-correct keys are left byte-for-byte alone.
 */
export function applyRetentionYaml(text: string): RetentionYamlResult {
  const lines = text.split('\n');
  const maxCountChanged = setYamlScalar(lines, 'maxCount', INIT_RETENTION_MAX_COUNT);
  const maxAgeDaysChanged = setYamlScalar(lines, 'maxAgeDays', INIT_RETENTION_MAX_AGE_DAYS);
  if (!maxCountChanged && !maxAgeDaysChanged) {
    return { text, maxCountChanged: false, maxAgeDaysChanged: false };
  }
  let next = lines.join('\n');
  if (!next.endsWith('\n')) next += '\n';
  return { text: next, maxCountChanged, maxAgeDaysChanged };
}

/**
 * Write retention defaults onto `.agent-receipt.yml`. Creates the default
 * config first when the file is missing. Does not replace ignore, redact,
 * or failOn.
 */
export function applyRetention(cwd: string): RetentionResult {
  const configFile = configPath(cwd);
  const created = !existsSync(configFile);
  let notesFile = join(cwd, '.agent-receipt', 'SETUP.md');
  if (created) {
    const written = writeDefaultConfig(cwd);
    notesFile = written.notesFile;
  }
  const before = readFileSync(configFile, 'utf8');
  const applied = applyRetentionYaml(before);
  if (applied.text !== before) writeFileSync(configFile, applied.text, 'utf8');
  return {
    configFile,
    notesFile,
    created,
    maxCountChanged: applied.maxCountChanged,
    maxAgeDaysChanged: applied.maxAgeDaysChanged,
  };
}

export interface AutoPruneYamlResult {
  text: string;
  autoPruneChanged: boolean;
}

export interface AutoPruneResult {
  configFile: string;
  notesFile: string;
  created: boolean;
  autoPruneChanged: boolean;
}

/**
 * Enable `autoPrune: true` in YAML text. Does not rewrite `ignore`,
 * `redact`, `failOn`, `outDir`, retention keys, or unrelated comments.
 * An already-true key is left byte-for-byte alone.
 */
export function applyAutoPruneYaml(text: string): AutoPruneYamlResult {
  const lines = text.split('\n');
  const autoPruneChanged = setYamlScalar(lines, 'autoPrune', 'true');
  if (!autoPruneChanged) {
    return { text, autoPruneChanged: false };
  }
  let next = lines.join('\n');
  if (!next.endsWith('\n')) next += '\n';
  return { text: next, autoPruneChanged };
}

/**
 * Write `autoPrune: true` onto `.agent-receipt.yml`. Creates the default
 * config first when the file is missing. Does not replace ignore, redact,
 * failOn, or retention limits. Does not delete receipts.
 */
export function applyAutoPrune(cwd: string): AutoPruneResult {
  const configFile = configPath(cwd);
  const created = !existsSync(configFile);
  let notesFile = join(cwd, '.agent-receipt', 'SETUP.md');
  if (created) {
    const written = writeDefaultConfig(cwd);
    notesFile = written.notesFile;
  }
  const before = readFileSync(configFile, 'utf8');
  const applied = applyAutoPruneYaml(before);
  if (applied.text !== before) writeFileSync(configFile, applied.text, 'utf8');
  return {
    configFile,
    notesFile,
    created,
    autoPruneChanged: applied.autoPruneChanged,
  };
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
  let configFile = '';
  let notesFile = '';
  let org: OrgPolicyResult | undefined;
  let retention: RetentionResult | undefined;
  let autoPrune: AutoPruneResult | undefined;
  if (!opts.org && !opts.retention && !opts.autoPrune) {
    const written = writeDefaultConfig(cwd);
    configFile = written.configFile;
    notesFile = written.notesFile;
  } else {
    if (opts.org) {
      org = applyOrgPolicy(cwd);
      configFile = org.configFile;
      notesFile = org.notesFile;
    }
    if (opts.retention) {
      retention = applyRetention(cwd);
      configFile = retention.configFile;
      notesFile = retention.notesFile;
    }
    if (opts.autoPrune) {
      autoPrune = applyAutoPrune(cwd);
      configFile = autoPrune.configFile;
      notesFile = autoPrune.notesFile;
    }
  }
  const fresh = Boolean(
    org?.created || retention?.created || autoPrune?.created || (!org && !retention && !autoPrune),
  );
  if (!fresh && org && retention && autoPrune) {
    console.log(color.green('✓') + ' Org policy, retention, and auto-prune applied');
  } else if (!fresh && org && retention) {
    console.log(color.green('✓') + ' Org policy and retention applied');
  } else if (!fresh && org && autoPrune) {
    console.log(color.green('✓') + ' Org policy and auto-prune applied');
  } else if (!fresh && retention && autoPrune) {
    console.log(color.green('✓') + ' Retention defaults and auto-prune applied');
  } else if (!fresh && org) {
    console.log(color.green('✓') + ' Org policy applied');
  } else if (!fresh && retention) {
    console.log(color.green('✓') + ' Retention defaults applied');
  } else if (!fresh && autoPrune) {
    console.log(color.green('✓') + ' Auto-prune applied');
  } else {
    console.log(color.green('✓') + ' Initialized agent-receipt');
  }
  console.log(`  config: ${configFile}`);
  if (fresh) {
    console.log(`  notes:  ${notesFile}`);
  }
  if (org) {
    console.log(`  redact: true (${org.redactChanged ? 'set' : 'unchanged'})`);
    console.log(`  failOn: high (${org.failOnChanged ? 'set' : 'unchanged'})`);
  }
  if (retention) {
    console.log(
      `  maxCount: ${INIT_RETENTION_MAX_COUNT} (${retention.maxCountChanged ? 'set' : 'unchanged'})`,
    );
    console.log(
      `  maxAgeDays: ${INIT_RETENTION_MAX_AGE_DAYS} (${retention.maxAgeDaysChanged ? 'set' : 'unchanged'})`,
    );
  }
  if (autoPrune) {
    console.log(`  autoPrune: true (${autoPrune.autoPruneChanged ? 'set' : 'unchanged'})`);
  }
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
  if (opts.org) {
    console.log('  agent-receipt doctor --strict   # policy row should pass');
    console.log('  tip: examples/org-policy.yml (init --org does not replace local ignore)');
    console.log('  tip: init --org does not set sign (keys may be absent; add sign: true after keygen)');
  }
  if (opts.retention) {
    console.log('  agent-receipt prune --dry-run   # preview trusted retention');
    console.log('  tip: trusted prune refuses to delete when the audit chain is broken');
    if (!opts.autoPrune) {
      console.log('  tip: add autoPrune: true (or init --auto-prune) to delete after capture, wrap, and watch');
    }
  }
  if (opts.autoPrune) {
    console.log('  tip: autoPrune deletes only when maxCount or maxAgeDays is set');
    console.log('  tip: a broken audit chain skips the delete and does not fail capture, wrap, or watch');
    console.log('  tip: --no-prune overrides for one run. Not a daemon.');
  }
}
