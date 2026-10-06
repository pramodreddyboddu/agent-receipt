import { chmodSync, existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  GROK_HOOK_JSON,
  GROK_HOOK_REL,
  GROK_RULE_MD,
  GROK_RULE_REL,
  GROK_WRAP_SCRIPT,
  GROK_WRAP_SCRIPT_REL,
} from '../grok-rule.js';
import { applyProjectFile, assertSafeProjectPath, restoreAdapter } from './backup.js';
import { isOurCommand, jsonText, projectPath, readJsonObject } from './json-config.js';
import {
  eventsFromCalls,
  eventsFromGrokMarkdown,
  exitStatuses,
  parseJsonRecords,
  readTranscriptText,
  resolveCwd,
  transcriptCalls,
} from './parse-common.js';
import type { AgentAdapter, InstallOptions, InstallResult, ParseResult, UninstallOptions } from './types.js';

const GROK_COMMAND = 'sh .grok/hooks/agent-receipt-wrap.sh';

function commandOnPath(name: string): boolean {
  const result = spawnSync('sh', ['-c', `command -v ${name}`], { encoding: 'utf8' });
  return result.status === 0 && Boolean(result.stdout.trim());
}

function owned(rel: string, expected: string, cwd: string): boolean {
  const path = projectPath(cwd, rel);
  return existsSync(path) && readFileSync(path, 'utf8') === expected;
}

function hookGroups(value: unknown): unknown[] {
  return Array.isArray(value) ? value.slice() : [];
}

function groupHasOurs(group: unknown): boolean {
  const doc = group && typeof group === 'object' ? (group as { hooks?: unknown }).hooks : null;
  return Array.isArray(doc) && doc.some((hook) => isOurCommand((hook as { command?: unknown })?.command));
}

function mergeSessionEnd(existing: unknown): unknown[] {
  const groups = hookGroups(existing);
  if (groups.some((group) => groupHasOurs(group))) return groups;
  groups.push({ hooks: [{ type: 'command', command: GROK_COMMAND, timeout: 120 }] });
  return groups;
}

/**
 * A missing hook file stays the exact `GROK_HOOK_JSON` bytes (`init --grok`
 * tests compare them). An existing file is merged so other keys survive.
 */
function hookText(cwd: string): string {
  const filePath = projectPath(cwd, GROK_HOOK_REL);
  assertSafeProjectPath(cwd, filePath);
  if (!existsSync(filePath)) return GROK_HOOK_JSON;
  const current = readFileSync(filePath, 'utf8');
  if (current === GROK_HOOK_JSON) return GROK_HOOK_JSON;
  const parsed = readJsonObject(filePath, GROK_HOOK_REL);
  if (!parsed.ok) throw new Error(parsed.reason);
  const root = parsed.value;
  const hooks =
    root.hooks && typeof root.hooks === 'object' && !Array.isArray(root.hooks)
      ? { ...(root.hooks as Record<string, unknown>) }
      : {};
  hooks.SessionEnd = mergeSessionEnd(hooks.SessionEnd);
  root.hooks = hooks;
  return jsonText(root);
}

export const grokAdapter: AgentAdapter = {
  name: 'grok',
  detect(cwd: string): boolean {
    return existsSync(projectPath(cwd, '.grok')) || commandOnPath('grok');
  },
  status(cwd: string) {
    const present = [GROK_RULE_REL, GROK_HOOK_REL, GROK_WRAP_SCRIPT_REL].filter((rel) =>
      existsSync(projectPath(cwd, rel)),
    );
    const installed = present.length > 0;
    const status = present.length === 3 ? 'full' : installed ? 'partial' : 'absent';
    const detail =
      present.length === 3
        ? 'rule + SessionEnd hook installed (stdin drained, then closed — open pipe cannot hang wrap)'
        : installed
          ? `partial (${present.length}/3 files)`
          : 'not installed (agent-receipt init --grok)';
    return { name: 'grok', detected: this.detect(cwd), installed, status, detail };
  },
  install(cwd: string, opts?: InstallOptions): InstallResult {
    const dryRun = Boolean(opts?.dryRun);
    const hook = hookText(cwd);
    const applies = [
      applyProjectFile(cwd, 'grok', GROK_RULE_REL, GROK_RULE_MD, { dryRun }),
      applyProjectFile(cwd, 'grok', GROK_HOOK_REL, hook, { dryRun }),
      applyProjectFile(cwd, 'grok', GROK_WRAP_SCRIPT_REL, GROK_WRAP_SCRIPT, { dryRun }),
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
    const restored = restoreAdapter(cwd, 'grok', dryRun);
    if (restored.hadBackup) return { files: restored.files, changed: restored.changed };
    const applies = [];
    const files: Array<[string, string]> = [
      [GROK_RULE_REL, GROK_RULE_MD],
      [GROK_HOOK_REL, GROK_HOOK_JSON],
      [GROK_WRAP_SCRIPT_REL, GROK_WRAP_SCRIPT],
    ];
    for (const [rel, expected] of files) {
      if (!owned(rel, expected, cwd)) continue;
      applies.push(applyProjectFile(cwd, 'grok', rel, null, { dryRun, backup: false }));
    }
    return {
      files: applies.map((item) => item.path),
      changed: applies.filter((item) => item.changed).map((item) => item.path),
    };
  },
  parseTranscript(filePath: string, cwd?: string): ParseResult {
    const loaded = readTranscriptText(filePath);
    if (!loaded.ok) return { ok: false, events: [], reason: loaded.reason };
    const workspace = resolveCwd(cwd);
    const records = parseJsonRecords(loaded.text);
    if (records.parsed > 0) {
      const calls = records.records.flatMap((record) => transcriptCalls(record));
      const events = eventsFromCalls(calls, exitStatuses(records.records), workspace);
      if (events.length > 0 || records.failed === 0) return { ok: true, events };
    }
    const markdown = eventsFromGrokMarkdown(loaded.text, workspace);
    if (markdown.length > 0) return { ok: true, events: markdown };
    return {
      ok: false,
      events: [],
      reason: 'grok transcript is not parseable JSONL or an exported tool list',
    };
  },
};
