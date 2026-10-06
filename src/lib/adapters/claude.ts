import { chmodSync, existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { applyProjectFile, applyUninstallPlan, assertSafeProjectPath, planAdapterUninstall, projectRoot, strippedResult } from './backup.js';
import { wrapHookScript } from './hook-script.js';
import { hookCommand, isOurCommand, jsonText, projectPath, readJsonObject, requireEventArray, requireHookObject } from './json-config.js';
import {
  eventsFromCalls,
  exitStatuses,
  parseJsonRecords,
  readTranscriptText,
  resolveCwd,
  transcriptCalls,
  unparseable,
} from './parse-common.js';
import type { AgentAdapter, InstallOptions, InstallResult, ParseResult, UninstallOptions } from './types.js';

export const CLAUDE_SETTINGS_REL = '.claude/settings.json';
export const CLAUDE_RULE_REL = '.claude/rules/agent-receipt.md';
export const CLAUDE_SCRIPT_REL = '.claude/hooks/agent-receipt-wrap.sh';
export const CLAUDE_COMMAND = hookCommand(CLAUDE_SCRIPT_REL);
const RULE_MARKER = '<!-- agent-receipt:claude-rule -->';

export const CLAUDE_RULE_MD = `${RULE_MARKER}
# agent-receipt (Claude Code wrap-up)

This repo uses **agent-receipt**. When a session changes files, run wrap yourself:

\`\`\`bash
agent-receipt wrap --agent claude-code --redact --message "<one-line summary>"
\`\`\`

\`agent-receipt init --claude\` also installs a project SessionEnd hook (and a Stop hook) that runs that wrap only when the tree is dirty and passes \`--transcript\` when Claude sends \`transcript_path\`. The hook exits 0. Prefer the explicit wrap so the message names what changed.

Do not commit \`.env\`, private keys, or tokens. Do not drop \`--redact\` when the receipt might be shared.
`;

function commandOnPath(name: string): boolean {
  const result = spawnSync('sh', ['-c', `command -v ${name}`], { encoding: 'utf8' });
  return result.status === 0 && Boolean(result.stdout.trim());
}

function hookGroups(value: unknown): unknown[] {
  return Array.isArray(value) ? value.slice() : [];
}

function groupHasOurs(group: unknown): boolean {
  const doc = group && typeof group === 'object' ? (group as { hooks?: unknown }).hooks : null;
  return Array.isArray(doc) && doc.some((hook) => isOurCommand((hook as { command?: unknown })?.command));
}

function mergeEvent(existing: unknown, command: string, rel: string, event: string): unknown[] {
  const groups = requireEventArray(existing, rel, event);
  if (groups.some((group) => groupHasOurs(group))) return groups;
  groups.push({ hooks: [{ type: 'command', command, timeout: 120 }] });
  return groups;
}

function stripEvent(existing: unknown): unknown[] {
  const next: unknown[] = [];
  for (const group of hookGroups(existing)) {
    if (!group || typeof group !== 'object') {
      next.push(group);
      continue;
    }
    const raw = (group as { hooks?: unknown }).hooks;
    if (!Array.isArray(raw)) {
      next.push(group);
      continue;
    }
    const hooks = raw.filter((hook) => !isOurCommand((hook as { command?: unknown })?.command));
    if (hooks.length === 0) continue;
    next.push({ ...(group as Record<string, unknown>), hooks });
  }
  return next;
}

function eventsToInstall(opts?: InstallOptions): string[] {
  // SessionEnd is the documented end-of-session event. Stop is included so a
  // turn that stops without SessionEnd still wraps. Pass { stop: false } to
  // keep SessionEnd only.
  if (opts?.stop === false) return ['SessionEnd'];
  return ['SessionEnd', 'Stop'];
}

function settingsText(cwd: string, opts?: InstallOptions): string {
  const filePath = projectPath(cwd, CLAUDE_SETTINGS_REL);
  assertSafeProjectPath(cwd, filePath);
  const parsed = readJsonObject(filePath, CLAUDE_SETTINGS_REL);
  if (!parsed.ok) throw new Error(parsed.reason);
  const root = parsed.value;
  const hooks = requireHookObject(root.hooks, CLAUDE_SETTINGS_REL);
  for (const event of eventsToInstall(opts)) {
    hooks[event] = mergeEvent(hooks[event], CLAUDE_COMMAND, CLAUDE_SETTINGS_REL, event);
  }
  root.hooks = hooks;
  return jsonText(root, parsed.indent);
}

function chmodScript(path: string, dryRun: boolean): void {
  if (dryRun || !existsSync(path)) return;
  try {
    chmodSync(path, 0o755);
  } catch {
    // The hook invokes `sh`, so a missing +x bit is non-fatal.
  }
}

function fromApplies(applies: Array<{ path: string; changed: boolean }>): InstallResult {
  return {
    files: applies.map((item) => item.path),
    changed: applies.filter((item) => item.changed).map((item) => item.path),
  };
}

function matchesRel(stored: string, rel: string): boolean {
  return stored === rel || stored.endsWith(`/${rel}`);
}

function stripSettings(cwd: string, rel: string, dryRun: boolean): { path: string; changed: boolean } | null {
  const filePath = projectPath(projectRoot(cwd), rel);
  assertSafeProjectPath(projectRoot(cwd), filePath);
  if (!existsSync(filePath)) return { path: filePath, changed: false };
  const parsed = readJsonObject(filePath, rel);
  if (!parsed.ok) throw new Error(parsed.reason);
  const root = parsed.value;
  const hooks =
    root.hooks && typeof root.hooks === 'object' && !Array.isArray(root.hooks)
      ? { ...(root.hooks as Record<string, unknown>) }
      : null;
  if (!hooks) return { path: filePath, changed: false };
  let touched = false;
  for (const event of ['SessionEnd', 'Stop']) {
    if (!hookGroups(hooks[event]).some((group) => groupHasOurs(group))) continue;
    const next = stripEvent(hooks[event]);
    touched = true;
    if (next.length === 0) delete hooks[event];
    else hooks[event] = next;
  }
  if (!touched) return { path: filePath, changed: false };
  if (Object.keys(hooks).length === 0) delete root.hooks;
  else root.hooks = hooks;
  const next = Object.keys(root).length === 0 ? null : jsonText(root, parsed.indent);
  return applyProjectFile(cwd, 'claude-code', rel, next, { dryRun, backup: false, stored: true });
}

function stripOwned(cwd: string, rel: string): { path: string; changed: boolean } {
  return { path: projectPath(projectRoot(cwd), rel), changed: false };
}

function stripInstalled(cwd: string, dryRun: boolean): InstallResult {
  const applies = [];
  const filePath = projectPath(cwd, CLAUDE_SETTINGS_REL);
  assertSafeProjectPath(cwd, filePath);
  if (existsSync(filePath)) {
    const parsed = readJsonObject(filePath, CLAUDE_SETTINGS_REL);
    if (!parsed.ok) throw new Error(parsed.reason);
    const root = parsed.value;
    const hooks =
      root.hooks && typeof root.hooks === 'object' && !Array.isArray(root.hooks)
        ? { ...(root.hooks as Record<string, unknown>) }
        : null;
    if (hooks) {
      let touched = false;
      for (const event of ['SessionEnd', 'Stop']) {
        if (!hookGroups(hooks[event]).some((group) => groupHasOurs(group))) continue;
        const next = stripEvent(hooks[event]);
        touched = true;
        if (next.length === 0) delete hooks[event];
        else hooks[event] = next;
      }
      if (touched) {
        if (Object.keys(hooks).length === 0) delete root.hooks;
        else root.hooks = hooks;
        const next = Object.keys(root).length === 0 ? null : jsonText(root, parsed.indent);
        applies.push(applyProjectFile(cwd, 'claude-code', CLAUDE_SETTINGS_REL, next, { dryRun, backup: false }));
      }
    }
  }
  for (const rel of [CLAUDE_RULE_REL, CLAUDE_SCRIPT_REL]) {
    const path = projectPath(cwd, rel);
    assertSafeProjectPath(cwd, path);
    if (!existsSync(path)) continue;
    const text = readFileSync(path, 'utf8');
    if (!text.includes('agent-receipt')) continue;
    applies.push(applyProjectFile(cwd, 'claude-code', rel, null, { dryRun, backup: false }));
  }
  return strippedResult(applies);
}

export const claudeAdapter: AgentAdapter = {
  name: 'claude-code',
  detect(cwd: string): boolean {
    return (
      existsSync(projectPath(cwd, '.claude')) ||
      existsSync(projectPath(cwd, 'CLAUDE.md')) ||
      commandOnPath('claude')
    );
  },
  status(cwd: string) {
    const settings = projectPath(cwd, CLAUDE_SETTINGS_REL);
    const rule = existsSync(projectPath(cwd, CLAUDE_RULE_REL));
    let hook = false;
    if (existsSync(settings)) {
      const parsed = readJsonObject(settings, CLAUDE_SETTINGS_REL);
      if (parsed.ok) {
        const hooks = parsed.value.hooks;
        const doc = hooks && typeof hooks === 'object' ? (hooks as Record<string, unknown>) : {};
        hook = ['SessionEnd', 'Stop'].some((event) => hookGroups(doc[event]).some((group) => groupHasOurs(group)));
      }
    }
    const installed = hook || rule;
    const status = hook && rule ? 'full' : installed ? 'partial' : 'absent';
    const detail = !installed
      ? 'not installed (agent-receipt init --claude)'
      : hook && rule
        ? 'SessionEnd hook + rule'
        : hook
          ? 'hook only'
          : 'rule only';
    return { name: 'claude-code', detected: this.detect(cwd), installed, status, detail };
  },
  install(cwd: string, opts?: InstallOptions): InstallResult {
    const dryRun = Boolean(opts?.dryRun);
    const settings = settingsText(cwd, opts);
    const applies = [
      applyProjectFile(cwd, 'claude-code', CLAUDE_SETTINGS_REL, settings, { dryRun }),
      applyProjectFile(cwd, 'claude-code', CLAUDE_RULE_REL, CLAUDE_RULE_MD, { dryRun }),
      applyProjectFile(cwd, 'claude-code', CLAUDE_SCRIPT_REL, wrapHookScript('claude-code'), { dryRun }),
    ];
    chmodScript(applies[2].path, dryRun);
    return fromApplies(applies);
  },
  uninstall(cwd: string, opts?: UninstallOptions): InstallResult {
    const dryRun = Boolean(opts?.dryRun);
    const plan = planAdapterUninstall(cwd, 'claude-code', Boolean(opts?.force));
    if (plan.hadBackup) {
      return applyUninstallPlan(cwd, 'claude-code', plan, dryRun, (entry) => {
        if (matchesRel(entry.rel, CLAUDE_SETTINGS_REL)) return stripSettings(cwd, entry.rel, dryRun);
        if (matchesRel(entry.rel, CLAUDE_RULE_REL) || matchesRel(entry.rel, CLAUDE_SCRIPT_REL)) return stripOwned(cwd, entry.rel);
        return null;
      });
    }
    return stripInstalled(cwd, dryRun);
  },
  parseTranscript(filePath: string, cwd?: string): ParseResult {
    const loaded = readTranscriptText(filePath);
    if (!loaded.ok) return { ok: false, events: [], reason: loaded.reason };
    const records = parseJsonRecords(loaded.text);
    const bad = unparseable(records, 'claude-code');
    if (bad) return bad;
    const calls = records.records.flatMap((record) => transcriptCalls(record));
    const exits = exitStatuses(records.records);
    return { ok: true, events: eventsFromCalls(calls, exits, resolveCwd(cwd)) };
  },
};
