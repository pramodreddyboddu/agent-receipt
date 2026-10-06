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

export const CODEX_HOOKS_REL = '.codex/hooks.json';
export const CODEX_SCRIPT_REL = '.codex/hooks/agent-receipt-wrap.sh';
export const CODEX_AGENTS_REL = 'AGENTS.md';
export const CODEX_COMMAND = hookCommand(CODEX_SCRIPT_REL);
const START = '<!-- agent-receipt:codex:start -->';
const END = '<!-- agent-receipt:codex:end -->';

export const CODEX_RULE_MD = `${START}
# agent-receipt (Codex wrap-up)

This repo uses **agent-receipt**. When a session changes files, run wrap yourself:

\`\`\`bash
agent-receipt wrap --agent codex --redact --message "<one-line summary>"
\`\`\`

\`agent-receipt init --codex\` installs project SessionEnd and Stop hooks (\`.codex/hooks.json\`) that run that wrap only when the tree is dirty and pass \`--transcript\` when Codex sends \`transcript_path\`. SessionEnd runs when the main thread ends. \`--no-stop\` keeps SessionEnd only. Enable \`features.hooks\` in Codex config, and trust the project hooks. The hook exits 0. This block is the project instruction; it does not replace AGENTS.md content outside these markers.

Do not commit \`.env\`, private keys, or tokens.
${END}
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

function eventsToInstall(opts?: InstallOptions): string[] {
  if (opts?.stop === false) return ['SessionEnd'];
  return ['SessionEnd', 'Stop'];
}

function mergeEvent(existing: unknown, rel: string, event: string): unknown[] {
  const groups = requireEventArray(existing, rel, event);
  if (groups.some((group) => groupHasOurs(group))) return groups;
  groups.push({ hooks: [{ type: 'command', command: CODEX_COMMAND, timeout: 120 }] });
  return groups;
}

function stripStop(existing: unknown): unknown[] {
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

function upsertAgents(text: string): string {
  const block = `${CODEX_RULE_MD.trim()}\n`;
  const re = new RegExp(`${START}[\\s\\S]*?${END}\\n?`);
  if (re.test(text)) return text.replace(re, block);
  if (!text.trim()) return block;
  const sep = text.endsWith('\n') ? '\n' : '\n\n';
  return `${text}${sep}${block}`;
}

function stripAgents(text: string): string {
  const re = new RegExp(`\\n?${START}[\\s\\S]*?${END}\\n?`);
  return text.replace(re, '\n').replace(/\n{3,}/g, '\n\n');
}

function hasOurEvent(cwd: string, event: string): boolean {
  const filePath = projectPath(cwd, CODEX_HOOKS_REL);
  if (!existsSync(filePath)) return false;
  const parsed = readJsonObject(filePath, CODEX_HOOKS_REL);
  if (!parsed.ok) return false;
  const hooks = parsed.value.hooks;
  const doc = hooks && typeof hooks === 'object' ? (hooks as Record<string, unknown>) : {};
  return hookGroups(doc[event]).some((group) => groupHasOurs(group));
}

function matchesRel(stored: string, rel: string): boolean {
  return stored === rel || stored.endsWith(`/${rel}`);
}

function stripHooksFile(cwd: string, rel: string, dryRun: boolean, stored: boolean): { path: string; changed: boolean } | null {
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
  for (const event of ['SessionEnd', 'Stop']) {
    if (!hookGroups(hooks[event]).some((group) => groupHasOurs(group))) continue;
    const next = stripStop(hooks[event]);
    touched = true;
    if (next.length === 0) delete hooks[event];
    else hooks[event] = next;
  }
  if (!touched) return { path: filePath, changed: false };
  if (Object.keys(hooks).length === 0) delete doc.hooks;
  else doc.hooks = hooks;
  const text = Object.keys(doc).length === 0 ? null : jsonText(doc, parsed.indent);
  return applyProjectFile(cwd, 'codex', rel, text, { dryRun, backup: false, stored });
}

function stripAgentsFile(cwd: string, rel: string, dryRun: boolean, stored: boolean): { path: string; changed: boolean } | null {
  const root = stored ? projectRoot(cwd) : cwd;
  const filePath = projectPath(root, rel);
  assertSafeProjectPath(projectRoot(cwd), filePath);
  if (!existsSync(filePath)) return { path: filePath, changed: false };
  const text = readFileSync(filePath, 'utf8');
  if (!text.includes(START)) return { path: filePath, changed: false };
  const next = stripAgents(text).trim();
  return applyProjectFile(cwd, 'codex', rel, next ? `${next}\n` : null, { dryRun, backup: false, stored });
}

function hasRule(cwd: string): boolean {
  const filePath = projectPath(cwd, CODEX_AGENTS_REL);
  if (!existsSync(filePath)) return false;
  return readFileSync(filePath, 'utf8').includes(START);
}

export const codexAdapter: AgentAdapter = {
  name: 'codex',
  detect(cwd: string): boolean {
    return existsSync(projectPath(cwd, '.codex')) || existsSync(projectPath(cwd, 'AGENTS.md')) || commandOnPath('codex');
  },
  status(cwd: string) {
    const sessionEnd = hasOurEvent(cwd, 'SessionEnd');
    const stop = hasOurEvent(cwd, 'Stop');
    const hook = sessionEnd || stop;
    const rule = hasRule(cwd);
    const installed = hook || rule;
    const status = hook && rule ? 'full' : installed ? 'partial' : 'absent';
    const hookDetail = sessionEnd && stop ? 'SessionEnd + Stop hooks' : sessionEnd ? 'SessionEnd hook' : 'Stop hook';
    const detail = !installed
      ? 'not installed (agent-receipt init --codex)'
      : hook && rule
        ? `${hookDetail} + AGENTS.md block`
        : hook
          ? `${hookDetail} only`
          : 'AGENTS.md block only';
    return { name: 'codex', detected: this.detect(cwd), installed, status, detail };
  },
  install(cwd: string, opts?: InstallOptions): InstallResult {
    const dryRun = Boolean(opts?.dryRun);
    const hooksPath = projectPath(cwd, CODEX_HOOKS_REL);
    assertSafeProjectPath(cwd, hooksPath);
    const parsed = readJsonObject(hooksPath, CODEX_HOOKS_REL);
    if (!parsed.ok) throw new Error(parsed.reason);
    const root = parsed.value;
    const hooks = requireHookObject(root.hooks, CODEX_HOOKS_REL);
    for (const event of eventsToInstall(opts)) {
      hooks[event] = mergeEvent(hooks[event], CODEX_HOOKS_REL, event);
    }
    root.hooks = hooks;
    const agentsPath = projectPath(cwd, CODEX_AGENTS_REL);
    assertSafeProjectPath(cwd, agentsPath);
    const previous = existsSync(agentsPath) ? readFileSync(agentsPath, 'utf8') : '';
    const agentsNext = upsertAgents(previous);
    const agentsText = agentsNext.endsWith('\n') ? agentsNext : `${agentsNext}\n`;
    const applies = [
      applyProjectFile(cwd, 'codex', CODEX_HOOKS_REL, jsonText(root, parsed.indent), { dryRun }),
      applyProjectFile(cwd, 'codex', CODEX_SCRIPT_REL, wrapHookScript('codex'), { dryRun }),
      applyProjectFile(cwd, 'codex', CODEX_AGENTS_REL, agentsText, { dryRun }),
    ];
    if (!dryRun && existsSync(applies[1].path)) {
      try {
        chmodSync(applies[1].path, 0o755);
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
    const plan = planAdapterUninstall(cwd, 'codex', Boolean(opts?.force));
    if (plan.hadBackup) {
      return applyUninstallPlan(cwd, 'codex', plan, dryRun, (entry) => {
        if (matchesRel(entry.rel, CODEX_HOOKS_REL)) return stripHooksFile(cwd, entry.rel, dryRun, true);
        if (matchesRel(entry.rel, CODEX_AGENTS_REL)) return stripAgentsFile(cwd, entry.rel, dryRun, true);
        if (matchesRel(entry.rel, CODEX_SCRIPT_REL)) return { path: projectPath(projectRoot(cwd), entry.rel), changed: false };
        return null;
      });
    }
    const applies = [];
    const hooks = stripHooksFile(cwd, CODEX_HOOKS_REL, dryRun, false);
    if (hooks?.changed) applies.push(hooks);
    const script = projectPath(cwd, CODEX_SCRIPT_REL);
    assertSafeProjectPath(cwd, script);
    if (existsSync(script) && readFileSync(script, 'utf8').includes('agent-receipt')) {
      applies.push(applyProjectFile(cwd, 'codex', CODEX_SCRIPT_REL, null, { dryRun, backup: false }));
    }
    const agents = stripAgentsFile(cwd, CODEX_AGENTS_REL, dryRun, false);
    if (agents?.changed) applies.push(agents);
    return strippedResult(applies);
  },
  parseTranscript(filePath: string, cwd?: string): ParseResult {
    const loaded = readTranscriptText(filePath);
    if (!loaded.ok) return { ok: false, events: [], reason: loaded.reason };
    const records = parseJsonRecords(loaded.text);
    const bad = unparseable(records, 'codex');
    if (bad) return bad;
    const calls = records.records.flatMap((record) => transcriptCalls(record));
    return { ok: true, events: eventsFromCalls(calls, exitStatuses(records.records), resolveCwd(cwd)) };
  },
};
