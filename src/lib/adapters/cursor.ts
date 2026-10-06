import { chmodSync, existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { CURSOR_RULE_MDC, CURSOR_RULE_REL } from '../cursor-rule.js';
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

export const CURSOR_HOOKS_REL = '.cursor/hooks.json';
export const CURSOR_SCRIPT_REL = '.cursor/hooks/agent-receipt-wrap.sh';
export const CURSOR_COMMAND = hookCommand(CURSOR_SCRIPT_REL);

function commandOnPath(name: string): boolean {
  const result = spawnSync('sh', ['-c', `command -v ${name}`], { encoding: 'utf8' });
  return result.status === 0 && Boolean(result.stdout.trim());
}

function entries(value: unknown): unknown[] {
  return Array.isArray(value) ? value.slice() : [];
}

function hasOurs(list: unknown): boolean {
  return entries(list).some((entry) => isOurCommand((entry as { command?: unknown })?.command));
}

function mergeEntries(existing: unknown, command: string, rel: string, event: string): unknown[] {
  const list = requireEventArray(existing, rel, event);
  if (list.some((entry) => isOurCommand((entry as { command?: unknown })?.command))) return list;
  list.push({ command, timeout: 120 });
  return list;
}

function stripEntries(existing: unknown): unknown[] {
  return entries(existing).filter((entry) => !isOurCommand((entry as { command?: unknown })?.command));
}

function hookMap(cwd: string): Record<string, unknown> | null {
  const filePath = projectPath(cwd, CURSOR_HOOKS_REL);
  if (!existsSync(filePath)) return null;
  const parsed = readJsonObject(filePath, CURSOR_HOOKS_REL);
  if (!parsed.ok) return null;
  const hooks = parsed.value.hooks;
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) return {};
  return hooks as Record<string, unknown>;
}

function stripCursorHooks(
  cwd: string,
  rel: string,
  dryRun: boolean,
  stored: boolean,
): { path: string; changed: boolean } | null {
  const root = stored ? projectRoot(cwd) : cwd;
  const filePath = projectPath(root, rel);
  assertSafeProjectPath(projectRoot(cwd), filePath);
  if (!existsSync(filePath)) return { path: filePath, changed: false };
  const parsed = readJsonObject(filePath, rel);
  if (!parsed.ok) throw new Error(parsed.reason);
  const doc = parsed.value;
  const hooks =
    doc.hooks && typeof doc.hooks === 'object' && !Array.isArray(doc.hooks)
      ? { ...(doc.hooks as Record<string, unknown>) }
      : null;
  if (!hooks) return { path: filePath, changed: false };
  let touched = false;
  for (const event of ['sessionEnd', 'stop']) {
    if (!hasOurs(hooks[event])) continue;
    const next = stripEntries(hooks[event]);
    touched = true;
    if (next.length === 0) delete hooks[event];
    else hooks[event] = next;
  }
  if (!touched) return { path: filePath, changed: false };
  if (Object.keys(hooks).length === 0) delete doc.hooks;
  else doc.hooks = hooks;
  const versionOnly = Object.keys(doc).length === 1 && doc.version !== undefined && !doc.hooks;
  const text = Object.keys(doc).length === 0 || versionOnly ? null : jsonText(doc, parsed.indent);
  return applyProjectFile(cwd, 'cursor', rel, text, { dryRun, backup: false, stored });
}

export const cursorAdapter: AgentAdapter = {
  name: 'cursor',
  detect(cwd: string): boolean {
    return existsSync(projectPath(cwd, '.cursor')) || commandOnPath('cursor');
  },
  status(cwd: string) {
    const rule = existsSync(projectPath(cwd, CURSOR_RULE_REL));
    const hooks = hookMap(cwd);
    const hook = Boolean(hooks && (hasOurs(hooks.sessionEnd) || hasOurs(hooks.stop)));
    const installed = rule || hook;
    const status = rule && hook ? 'full' : installed ? 'partial' : 'absent';
    const detail = !installed
      ? 'not installed (agent-receipt init --cursor)'
      : rule && hook
        ? 'rule + sessionEnd and stop hooks'
        : rule
          ? 'rule only'
          : 'sessionEnd hook only';
    return { name: 'cursor', detected: this.detect(cwd), installed, status, detail };
  },
  install(cwd: string, opts?: InstallOptions): InstallResult {
    const dryRun = Boolean(opts?.dryRun);
    const filePath = projectPath(cwd, CURSOR_HOOKS_REL);
    assertSafeProjectPath(cwd, filePath);
    const parsed = readJsonObject(filePath, CURSOR_HOOKS_REL);
    if (!parsed.ok) throw new Error(parsed.reason);
    const root = parsed.value;
    if (root.version === undefined) root.version = 1;
    const hooks = requireHookObject(root.hooks, CURSOR_HOOKS_REL);
    hooks.sessionEnd = mergeEntries(hooks.sessionEnd, CURSOR_COMMAND, CURSOR_HOOKS_REL, 'sessionEnd');
    if (opts?.stop !== false) hooks.stop = mergeEntries(hooks.stop, CURSOR_COMMAND, CURSOR_HOOKS_REL, 'stop');
    root.hooks = hooks;
    const applies = [
      applyProjectFile(cwd, 'cursor', CURSOR_RULE_REL, CURSOR_RULE_MDC, { dryRun }),
      applyProjectFile(cwd, 'cursor', CURSOR_HOOKS_REL, jsonText(root, parsed.indent), { dryRun }),
      applyProjectFile(cwd, 'cursor', CURSOR_SCRIPT_REL, wrapHookScript('cursor'), { dryRun }),
    ];
    if (!dryRun && existsSync(applies[2].path)) {
      try {
        chmodSync(applies[2].path, 0o755);
      } catch {
        // The hook invokes `sh`.
      }
    }
    return {
      files: applies.map((item) => item.path),
      changed: applies.filter((item) => item.changed).map((item) => item.path),
    };
  },
  uninstall(cwd: string, opts?: UninstallOptions): InstallResult {
    const dryRun = Boolean(opts?.dryRun);
    const plan = planAdapterUninstall(cwd, 'cursor', Boolean(opts?.force));
    if (plan.hadBackup) {
      return applyUninstallPlan(cwd, 'cursor', plan, dryRun, (entry) => {
        if (entry.rel === CURSOR_HOOKS_REL || entry.rel.endsWith(`/${CURSOR_HOOKS_REL}`)) {
          return stripCursorHooks(cwd, entry.rel, dryRun, true);
        }
        if (entry.rel.endsWith(CURSOR_RULE_REL) || entry.rel.endsWith(CURSOR_SCRIPT_REL)) {
          return { path: projectPath(projectRoot(cwd), entry.rel), changed: false };
        }
        return null;
      });
    }
    const applies = [];
    const rule = projectPath(cwd, CURSOR_RULE_REL);
    assertSafeProjectPath(cwd, rule);
    if (existsSync(rule) && readFileSync(rule, 'utf8') === CURSOR_RULE_MDC) {
      applies.push(applyProjectFile(cwd, 'cursor', CURSOR_RULE_REL, null, { dryRun, backup: false }));
    }
    const filePath = projectPath(cwd, CURSOR_HOOKS_REL);
    assertSafeProjectPath(cwd, filePath);
    if (existsSync(filePath)) {
      const parsed = readJsonObject(filePath, CURSOR_HOOKS_REL);
      if (!parsed.ok) throw new Error(parsed.reason);
      const root = parsed.value;
      const hooks =
        root.hooks && typeof root.hooks === 'object' && !Array.isArray(root.hooks)
          ? { ...(root.hooks as Record<string, unknown>) }
          : null;
      if (hooks) {
        let touched = false;
        for (const event of ['sessionEnd', 'stop']) {
          if (!hasOurs(hooks[event])) continue;
          const next = stripEntries(hooks[event]);
          touched = true;
          if (next.length === 0) delete hooks[event];
          else hooks[event] = next;
        }
        if (touched) {
          if (Object.keys(hooks).length === 0) delete root.hooks;
          else root.hooks = hooks;
          const versionOnly = Object.keys(root).length === 1 && root.version !== undefined && !root.hooks;
          const text = Object.keys(root).length === 0 || versionOnly ? null : jsonText(root, parsed.indent);
          applies.push(applyProjectFile(cwd, 'cursor', CURSOR_HOOKS_REL, text, { dryRun, backup: false }));
        }
      }
    }
    const script = projectPath(cwd, CURSOR_SCRIPT_REL);
    assertSafeProjectPath(cwd, script);
    if (existsSync(script) && readFileSync(script, 'utf8').includes('agent-receipt')) {
      applies.push(applyProjectFile(cwd, 'cursor', CURSOR_SCRIPT_REL, null, { dryRun, backup: false }));
    }
    return strippedResult(applies);
  },
  parseTranscript(filePath: string, cwd?: string): ParseResult {
    const loaded = readTranscriptText(filePath);
    if (!loaded.ok) return { ok: false, events: [], reason: loaded.reason };
    const records = parseJsonRecords(loaded.text);
    const bad = unparseable(records, 'cursor');
    if (bad) return bad;
    const calls = records.records.flatMap((record) => transcriptCalls(record));
    return { ok: true, events: eventsFromCalls(calls, exitStatuses(records.records), resolveCwd(cwd)) };
  },
};
