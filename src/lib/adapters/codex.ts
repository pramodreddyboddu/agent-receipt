import { chmodSync, existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { applyProjectFile, assertSafeProjectPath, restoreAdapter } from './backup.js';
import { wrapHookScript } from './hook-script.js';
import { isOurCommand, jsonText, projectPath, readJsonObject } from './json-config.js';
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
export const CODEX_COMMAND = `sh ${CODEX_SCRIPT_REL}`;
const START = '<!-- agent-receipt:codex:start -->';
const END = '<!-- agent-receipt:codex:end -->';

export const CODEX_RULE_MD = `${START}
# agent-receipt (Codex wrap-up)

This repo uses **agent-receipt**. When a session changes files, run wrap yourself:

\`\`\`bash
agent-receipt wrap --agent codex --redact --message "<one-line summary>"
\`\`\`

\`agent-receipt init --codex\` installs a project Stop hook (\`.codex/hooks.json\`) that runs that wrap only when the tree is dirty and passes \`--transcript\` when Codex sends \`transcript_path\`. Codex has no SessionEnd event in the documented hook list, so Stop is the end-of-turn hook. Enable \`features.hooks\` in Codex config, and trust the project hooks. The hook exits 0. This block is the project instruction; it does not replace AGENTS.md content outside these markers.

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

function mergeStop(existing: unknown): unknown[] {
  const groups = hookGroups(existing);
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

function hasStop(cwd: string): boolean {
  const filePath = projectPath(cwd, CODEX_HOOKS_REL);
  if (!existsSync(filePath)) return false;
  const parsed = readJsonObject(filePath, CODEX_HOOKS_REL);
  if (!parsed.ok) return false;
  const hooks = parsed.value.hooks;
  const doc = hooks && typeof hooks === 'object' ? (hooks as Record<string, unknown>) : {};
  return hookGroups(doc.Stop).some((group) => groupHasOurs(group));
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
    const hook = hasStop(cwd);
    const rule = hasRule(cwd);
    const installed = hook || rule;
    const status = hook && rule ? 'full' : installed ? 'partial' : 'absent';
    const detail = !installed
      ? 'not installed (agent-receipt init --codex)'
      : hook && rule
        ? 'Stop hook + AGENTS.md block'
        : hook
          ? 'Stop hook only'
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
    const hooks =
      root.hooks && typeof root.hooks === 'object' && !Array.isArray(root.hooks)
        ? { ...(root.hooks as Record<string, unknown>) }
        : {};
    hooks.Stop = mergeStop(hooks.Stop);
    root.hooks = hooks;
    const agentsPath = projectPath(cwd, CODEX_AGENTS_REL);
    assertSafeProjectPath(cwd, agentsPath);
    const previous = existsSync(agentsPath) ? readFileSync(agentsPath, 'utf8') : '';
    const agentsNext = upsertAgents(previous);
    const agentsText = agentsNext.endsWith('\n') ? agentsNext : `${agentsNext}\n`;
    const applies = [
      applyProjectFile(cwd, 'codex', CODEX_HOOKS_REL, jsonText(root), { dryRun }),
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
    const restored = restoreAdapter(cwd, 'codex', dryRun);
    if (restored.hadBackup) return { files: restored.files, changed: restored.changed };
    const applies = [];
    const filePath = projectPath(cwd, CODEX_HOOKS_REL);
    assertSafeProjectPath(cwd, filePath);
    if (existsSync(filePath)) {
      const parsed = readJsonObject(filePath, CODEX_HOOKS_REL);
      if (!parsed.ok) throw new Error(parsed.reason);
      const root = parsed.value;
      const hooks =
        root.hooks && typeof root.hooks === 'object' && !Array.isArray(root.hooks)
          ? { ...(root.hooks as Record<string, unknown>) }
          : null;
      if (hooks && hookGroups(hooks.Stop).some((group) => groupHasOurs(group))) {
        const next = stripStop(hooks.Stop);
        if (next.length === 0) delete hooks.Stop;
        else hooks.Stop = next;
        if (Object.keys(hooks).length === 0) delete root.hooks;
        else root.hooks = hooks;
        const text = Object.keys(root).length === 0 ? null : jsonText(root);
        applies.push(applyProjectFile(cwd, 'codex', CODEX_HOOKS_REL, text, { dryRun, backup: false }));
      }
    }
    const script = projectPath(cwd, CODEX_SCRIPT_REL);
    assertSafeProjectPath(cwd, script);
    if (existsSync(script) && readFileSync(script, 'utf8').includes('agent-receipt')) {
      applies.push(applyProjectFile(cwd, 'codex', CODEX_SCRIPT_REL, null, { dryRun, backup: false }));
    }
    const agents = projectPath(cwd, CODEX_AGENTS_REL);
    assertSafeProjectPath(cwd, agents);
    if (existsSync(agents)) {
      const text = readFileSync(agents, 'utf8');
      if (text.includes(START)) {
        const next = stripAgents(text).trim();
        applies.push(
          applyProjectFile(cwd, 'codex', CODEX_AGENTS_REL, next ? `${next}\n` : null, { dryRun, backup: false }),
        );
      }
    }
    return {
      files: applies.map((item) => item.path),
      changed: applies.filter((item) => item.changed).map((item) => item.path),
    };
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
