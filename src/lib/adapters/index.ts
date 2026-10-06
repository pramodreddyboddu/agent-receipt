import { claudeAdapter } from './claude.js';
import { codexAdapter } from './codex.js';
import { cursorAdapter } from './cursor.js';
import { grokAdapter } from './grok.js';
import type { AdapterStatus, AgentAdapter } from './types.js';

export const ADAPTERS: AgentAdapter[] = [claudeAdapter, codexAdapter, grokAdapter, cursorAdapter];

const BY_NAME = new Map(ADAPTERS.map((adapter) => [adapter.name, adapter]));

export function getAdapter(name: string | undefined): AgentAdapter | null {
  if (!name) return null;
  return BY_NAME.get(name) ?? null;
}

/** Map a receipt `--agent` label onto an adapter. Unknown labels return null. */
export function adapterForAgent(agent: string | undefined): AgentAdapter | null {
  if (!agent) return null;
  const key = agent.trim().toLowerCase();
  if (key === 'claude-code' || key === 'claude') return claudeAdapter;
  if (key === 'codex') return codexAdapter;
  if (key === 'grok') return grokAdapter;
  if (key === 'cursor') return cursorAdapter;
  return null;
}

export function listAdapterStatus(cwd: string): AdapterStatus[] {
  return ADAPTERS.map((adapter) => adapter.status(cwd));
}

export { claudeAdapter, codexAdapter, cursorAdapter, grokAdapter };
export type {
  AdapterStatus,
  AgentAdapter,
  InstallOptions,
  InstallResult,
  ParseResult,
  ToolCallEvent,
  UninstallOptions,
} from './types.js';
