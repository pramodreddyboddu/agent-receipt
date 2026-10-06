import { existsSync, readFileSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import {
  DEFAULT_MAX_TOOL_ARG_CHARS,
  DEFAULT_MAX_TOOL_EVENTS,
  DEFAULT_MAX_TRANSCRIPT_BYTES,
} from '../byte-limit.js';
import { clipText, redactTranscriptText } from './redact-transcript.js';
import type { ParseResult, ToolCallEvent } from './types.js';

const PATH_KEYS = new Set([
  'file_path',
  'filePath',
  'filepath',
  'path',
  'target_file',
  'targetFile',
  'notebook_path',
  'notebookPath',
]);

const WRITE_TOOLS = new Set([
  'edit',
  'editfile',
  'write',
  'writefile',
  'multiedit',
  'notebookedit',
  'searchreplace',
  'strreplace',
  'applypatch',
  'deletefile',
  'createfile',
]);

const SHELL_TOOLS = new Set([
  'bash',
  'shell',
  'shellcommand',
  'runterminalcmd',
  'execcommand',
  'powershell',
  'terminal',
]);

export function normTool(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function asObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** String id, or a finite JSON-RPC number id rendered in decimal. */
export function idOf(value: unknown): string | null {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return stringOrNull(value);
}

/**
 * Read a transcript without throwing. Over the byte cap, missing, or not a
 * regular file is `ok: false` so capture can warn and skip the section.
 */
export function readTranscriptText(filePath: string): { ok: true; text: string } | { ok: false; reason: string } {
  let size = 0;
  try {
    const st = statSync(filePath);
    if (!st.isFile()) return { ok: false, reason: `transcript is not a regular file: ${filePath}` };
    size = st.size;
  } catch {
    return { ok: false, reason: `transcript not found: ${filePath}` };
  }
  if (size > DEFAULT_MAX_TRANSCRIPT_BYTES) {
    return {
      ok: false,
      reason: `transcript is ${size} bytes, over the ${DEFAULT_MAX_TRANSCRIPT_BYTES} byte cap`,
    };
  }
  if (size === 0) return { ok: false, reason: 'transcript is empty' };
  try {
    return { ok: true, text: readFileSync(filePath, 'utf8') };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `transcript unreadable (${detail})` };
  }
}

export interface JsonRecords {
  records: unknown[];
  parsed: number;
  failed: number;
}

/** JSONL, a JSON array, or one JSON object. Blank lines are skipped. */
export function parseJsonRecords(text: string): JsonRecords {
  const trimmed = text.trim();
  if (!trimmed) return { records: [], parsed: 0, failed: 0 };
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const doc = JSON.parse(trimmed);
      if (Array.isArray(doc)) return { records: doc, parsed: doc.length, failed: 0 };
      if (doc && typeof doc === 'object') return { records: [doc], parsed: 1, failed: 0 };
    } catch {
      // Fall through to line-oriented JSONL. A pretty-printed object that
      // failed above is one failed record if no line parses.
    }
  }
  const records: unknown[] = [];
  let parsed = 0;
  let failed = 0;
  for (const line of text.split('\n')) {
    const item = line.trim();
    if (!item) continue;
    try {
      records.push(JSON.parse(item));
      parsed += 1;
    } catch {
      failed += 1;
    }
  }
  return { records, parsed, failed };
}

export function unparseable(records: JsonRecords, label: string): ParseResult | null {
  if (records.parsed > 0) return null;
  if (records.failed === 0) return { ok: false, events: [], reason: `${label} transcript is empty` };
  return { ok: false, events: [], reason: `${label} transcript is not parseable JSON` };
}

/** Cwd-relative path, or empty when it is outside the workspace. */
export function normalizeTouch(raw: string, cwd: string): string {
  const trimmed = raw.replace(/\\/g, '/').trim();
  if (!trimmed || trimmed.length > 500) return '';
  const base = cwd && existsSync(cwd) ? cwd : cwd || process.cwd();
  let candidate = trimmed;
  if (isAbsolute(raw) || trimmed.startsWith('/')) {
    const rel = relative(base, raw);
    candidate = rel.split(sep).join('/');
    if (!candidate || candidate.startsWith('..') || isAbsolute(rel)) return '';
  } else if (trimmed.startsWith('./')) {
    candidate = trimmed.slice(2);
  }
  candidate = candidate.replace(/^\.\/+/, '').replace(/\/+$/, '');
  if (!candidate || candidate.startsWith('..') || candidate.includes('\0')) return '';
  return candidate;
}

function collectPaths(input: unknown, depth = 0): string[] {
  if (depth > 4 || !input || typeof input !== 'object') return [];
  const out: string[] = [];
  if (Array.isArray(input)) {
    for (const item of input) out.push(...collectPaths(item, depth + 1));
    return out;
  }
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (PATH_KEYS.has(key) && typeof value === 'string') out.push(value);
    else if (value && typeof value === 'object') out.push(...collectPaths(value, depth + 1));
  }
  return out;
}

function commandOf(input: unknown): string | null {
  const doc = asObject(input);
  if (!doc) return typeof input === 'string' ? input : null;
  for (const key of ['command', 'cmd', 'script', 'cmd_line']) {
    if (typeof doc[key] === 'string') return doc[key] as string;
  }
  return null;
}

function summarize(input: unknown): string {
  if (input == null) return '';
  if (typeof input === 'string') return input;
  try {
    return JSON.stringify(input);
  } catch {
    return '';
  }
}

/**
 * A secret-shaped key, after camelCase is split (`apiKey` → `api_key`).
 * `key` must be its own token so `keyboard` and `monkey` stay. No `/g`:
 * `RegExp.test` with `/g` remembers `lastIndex`.
 */
const SENSITIVE_ARG_KEY =
  /(^|[^a-z0-9])(pass(?:word|wd)?|pwd|secrets?|tokens?|auth(?:orization|entication|n)?|cred(?:ential)?s?|cookies?|sessions?|keys?)([^a-z0-9]|$)/i;

function normalizeArgKey(key: string): string {
  return key
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[-\s]+/g, '_')
    .toLowerCase();
}

/** Path-like keys are file names, not secrets, even when they contain `key`. */
function isPathLikeArgKey(key: string): boolean {
  return key.includes('/') || key.includes('\\');
}

/** True when the whole value should be replaced. Path keys are not. */
export function isSensitiveArgKey(key: string): boolean {
  if (isPathLikeArgKey(key)) return false;
  return SENSITIVE_ARG_KEY.test(normalizeArgKey(key));
}

/**
 * Walk tool arguments before they are stringified. A JSON `"password":"…"`
 * value never matches `password=…` because the quote sits in front of `:`.
 * Free text under a non-sensitive key (`contents`, `new_string`) still goes
 * through `redactTranscriptText`.
 */
export function redactArgsValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[REDACTED]';
  if (Array.isArray(value)) return value.map((item) => redactArgsValue(item, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      out[key] = isSensitiveArgKey(key) ? '[REDACTED]' : redactArgsValue(child, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string') return redactTranscriptText(value);
  return value;
}

function summarizeRedacted(input: unknown): string {
  if (input == null) return '';
  if (typeof input === 'string') return input;
  try {
    return JSON.stringify(redactArgsValue(input));
  } catch {
    return '';
  }
}

export interface RawCall {
  id: string | null;
  tool: string;
  input: unknown;
  timestamp: string | null;
}

export function eventFromCall(call: RawCall, cwd: string, exitStatus: number | null): ToolCallEvent {
  const tool = clipText(redactTranscriptText(call.tool), 80) || 'tool';
  const kind = normTool(call.tool);
  const shell = SHELL_TOOLS.has(kind);
  const write = WRITE_TOOLS.has(kind);
  const paths = collectPaths(call.input)
    .map((p) => normalizeTouch(redactTranscriptText(p), cwd))
    .filter((p) => p.length > 0);
  const files = [...new Set(paths)].slice(0, 20);
  const command = shell ? clipText(redactTranscriptText(commandOf(call.input) ?? summarizeRedacted(call.input)), DEFAULT_MAX_TOOL_ARG_CHARS) : null;
  const argsSummary = clipText(
    redactTranscriptText(shell ? (command ?? '') : summarizeRedacted(call.input)),
    DEFAULT_MAX_TOOL_ARG_CHARS,
  );
  let timestamp: string | null = null;
  if (call.timestamp && !/[\r\n\u0000]/.test(call.timestamp)) {
    timestamp = clipText(redactTranscriptText(call.timestamp), 80);
  }
  return {
    tool,
    argsSummary,
    files,
    writes: write ? files : [],
    command: command || null,
    exitStatus: typeof exitStatus === 'number' && Number.isFinite(exitStatus) ? exitStatus : null,
    timestamp,
  };
}

export function capEvents(events: ToolCallEvent[]): { events: ToolCallEvent[]; truncated: number } {
  if (events.length <= DEFAULT_MAX_TOOL_EVENTS) return { events, truncated: 0 };
  return {
    events: events.slice(0, DEFAULT_MAX_TOOL_EVENTS),
    truncated: events.length - DEFAULT_MAX_TOOL_EVENTS,
  };
}

function timestampOf(doc: Record<string, unknown>): string | null {
  for (const key of ['timestamp', 'time', 'ts', 'created_at']) {
    if (typeof doc[key] === 'string') return doc[key] as string;
  }
  return null;
}

function pushCall(out: RawCall[], call: RawCall): void {
  if (!call.tool.trim()) return;
  out.push(call);
}

/** Claude / Cursor content blocks: `{type:"tool_use"|"tool_call", name, input|arguments}`. */
export function toolUsesFromRecord(record: unknown): RawCall[] {
  const doc = asObject(record);
  if (!doc) return [];
  const timestamp = timestampOf(doc);
  const out: RawCall[] = [];
  const take = (block: Record<string, unknown>, idFrom: unknown) => {
    const type = block.type;
    if (type !== 'tool_use' && type !== 'tool_call') return;
    const name = typeof block.name === 'string' ? block.name : '';
    let input: unknown = block.input ?? block.arguments ?? block.args ?? {};
    if (typeof input === 'string') {
      try {
        input = JSON.parse(input);
      } catch {
        input = { command: input };
      }
    }
    pushCall(out, { id: stringOrNull(idFrom), tool: name, input, timestamp });
  };
  if (doc.type === 'tool_use' || doc.type === 'tool_call') take(doc, doc.id);
  const message = asObject(doc.message);
  const content = message?.content ?? doc.content;
  if (Array.isArray(content)) {
    for (const block of content) {
      const item = asObject(block);
      if (!item) continue;
      take(item, item.id);
    }
  }
  if (typeof doc.toolName === 'string') {
    pushCall(out, {
      id: stringOrNull(doc.id ?? doc.toolUseId),
      tool: doc.toolName,
      input: doc.toolInput ?? doc.input ?? {},
      timestamp,
    });
  }
  return out;
}

/** Codex `function_call` / `response_item` payloads. Arguments may be a JSON string. */
export function functionCallsFromRecord(record: unknown): RawCall[] {
  const doc = asObject(record);
  if (!doc) return [];
  const timestamp = timestampOf(doc);
  const payload = asObject(doc.payload);
  const candidates = [doc, payload].filter((item): item is Record<string, unknown> => Boolean(item));
  const out: RawCall[] = [];
  const seen = new Set<string>();
  for (const item of candidates) {
    const type = item.type;
    if (type !== 'function_call' && type !== 'response.function_call') continue;
    const name = typeof item.name === 'string' ? item.name : '';
    const id = stringOrNull(item.call_id ?? item.callId ?? item.id);
    const key = `${id ?? ''}::${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let input: unknown = item.arguments ?? item.args ?? item.input ?? {};
    if (typeof input === 'string') {
      try {
        input = JSON.parse(input);
      } catch {
        input = { command: input };
      }
    }
    pushCall(out, { id, tool: name, input, timestamp });
  }
  return out;
}

const MCP_WRAPPERS = new Set(['callmcptool', 'mcptool', 'usemcptool', 'usecallmcptool']);

function parseMaybeJson(input: unknown): unknown {
  if (typeof input !== 'string') return input ?? {};
  try {
    return JSON.parse(input);
  } catch {
    return { arguments: input };
  }
}

/** `mcp__server__tool` (double underscore). Server and tool may contain `_`. */
export function parseMcpDunder(name: string): { server: string; tool: string } | null {
  const parts = name.split('__');
  if (parts.length < 3 || parts[0].toLowerCase() !== 'mcp' || !parts[1]) return null;
  const tool = parts.slice(2).join('__');
  if (!tool) return null;
  return { server: parts[1], tool };
}

export function mcpToolLabel(server: string | null, tool: string): string {
  return server ? `mcp:${server}/${tool}` : `mcp:${tool}`;
}

/**
 * CallMcpTool / `mcp__server__tool` become `mcp:<server>/<tool>`.
 * The wrapper envelope is replaced by the inner arguments so redaction
 * sees the tool args, not only the transport fields.
 */
export function normalizeMcpTool(call: RawCall): RawCall {
  const kind = normTool(call.tool);
  if (MCP_WRAPPERS.has(kind)) {
    const doc = asObject(call.input);
    if (!doc) return call;
    const server = stringOrNull(doc.server ?? doc.serverName ?? doc.mcpServer ?? doc.providerIdentifier);
    const name = stringOrNull(doc.toolName ?? doc.tool ?? doc.name);
    if (!name) return call;
    return {
      ...call,
      tool: mcpToolLabel(server, name),
      input: parseMaybeJson(doc.arguments ?? doc.args ?? doc.input ?? {}),
    };
  }
  const dunder = parseMcpDunder(call.tool);
  if (dunder) return { ...call, tool: mcpToolLabel(dunder.server, dunder.tool) };
  return call;
}

function takeMcpObject(doc: Record<string, unknown>, timestamp: string | null): RawCall | null {
  if (doc.method === 'tools/call') {
    const params = asObject(doc.params) ?? {};
    const name = stringOrNull(params.name ?? params.toolName ?? params.tool);
    if (!name) return null;
    const server = stringOrNull(params.server ?? params.serverName ?? doc.server ?? doc.serverName);
    return {
      id: idOf(doc.id),
      tool: mcpToolLabel(server, name),
      input: parseMaybeJson(params.arguments ?? params.args ?? {}),
      timestamp,
    };
  }
  const type = doc.type;
  if (type === 'mcp_tool_call' || type === 'mcp_call' || type === 'mcp_tool_use') {
    const name = stringOrNull(doc.tool ?? doc.toolName ?? doc.name);
    if (!name) return null;
    const server = stringOrNull(doc.server ?? doc.serverName ?? doc.mcpServer);
    return {
      id: idOf(doc.call_id ?? doc.callId ?? doc.id),
      tool: mcpToolLabel(server, name),
      input: parseMaybeJson(doc.arguments ?? doc.args ?? doc.input ?? {}),
      timestamp: timestampOf(doc) ?? timestamp,
    };
  }
  return null;
}

/**
 * MCP calls that are not ordinary tool_use blocks: JSON-RPC `tools/call`
 * and Codex-style `mcp_tool_call`. Nested `message` / `payload` / `content`
 * are walked. Arguments are not walked again.
 */
export function mcpCallsFromRecord(record: unknown): RawCall[] {
  const out: RawCall[] = [];
  const visit = (value: unknown, depth: number, inheritedTs: string | null) => {
    if (depth > 6) return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1, inheritedTs);
      return;
    }
    const doc = asObject(value);
    if (!doc) return;
    const ts = timestampOf(doc) ?? inheritedTs;
    const call = takeMcpObject(doc, ts);
    if (call) pushCall(out, call);
    for (const key of ['message', 'payload', 'content', 'item', 'items']) {
      if (doc[key] != null) visit(doc[key], depth + 1, ts);
    }
  };
  visit(record, 0, null);
  return out;
}

function callKey(call: RawCall): string {
  return `${call.id ?? ''}\0${call.tool}\0${summarize(call.input)}`;
}

/** Tool uses, Codex function calls, and MCP calls, de-duplicated. */
export function transcriptCalls(record: unknown): RawCall[] {
  const calls = [
    ...toolUsesFromRecord(record),
    ...functionCallsFromRecord(record),
    ...mcpCallsFromRecord(record),
  ].map((call) => normalizeMcpTool(call));
  const seen = new Set<string>();
  const out: RawCall[] = [];
  for (const call of calls) {
    const key = callKey(call);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(call);
  }
  return out;
}

/** Later tool_result / function_call_output lines. `is_error` maps to 1 or 0. */
export function exitStatuses(records: unknown[]): Map<string, number> {
  const map = new Map<string, number>();
  const visit = (value: unknown, depth: number) => {
    if (depth > 5) return;
    const doc = asObject(value);
    if (!doc) return;
    const id = idOf(doc.tool_use_id ?? doc.toolUseId ?? doc.call_id ?? doc.callId);
    const interesting =
      doc.type === 'tool_result' ||
      doc.type === 'function_call_output' ||
      doc.exit_code !== undefined ||
      doc.exitCode !== undefined ||
      doc.is_error !== undefined;
    if (id && interesting) {
      if (typeof doc.exit_code === 'number') map.set(id, doc.exit_code);
      else if (typeof doc.exitCode === 'number') map.set(id, doc.exitCode);
      else if (typeof doc.is_error === 'boolean') map.set(id, doc.is_error ? 1 : 0);
    }
    if (Array.isArray(doc.content)) {
      for (const item of doc.content) visit(item, depth + 1);
    }
    if (doc.message) visit(doc.message, depth + 1);
    if (doc.payload && doc.payload !== doc) visit(doc.payload, depth + 1);
  };
  for (const record of records) visit(record, 0);
  return map;
}

export function eventsFromCalls(calls: RawCall[], exits: Map<string, number>, cwd: string): ToolCallEvent[] {
  return calls.map((call) => {
    const exit = call.id ? exits.get(call.id) : undefined;
    return eventFromCall(call, cwd, exit === undefined ? null : exit);
  });
}

/** Best-effort Grok export: blocks that contain a `tool:` or `name:` line. */
export function eventsFromGrokMarkdown(text: string, cwd: string): ToolCallEvent[] {
  const events: ToolCallEvent[] = [];
  for (const block of text.split(/\n{2,}/)) {
    const name = block.match(/^(?:#{1,3}\s*)?(?:\*\*)?(?:tool|toolName|name)(?:\*\*)?:\s*(\S+)/im);
    if (!name) continue;
    const command = block.match(/^(?:command|cmd):\s*(.+)$/im);
    const file = block.match(/^(?:file|path|file_path):\s*(\S+)/im);
    const input: Record<string, unknown> = {};
    if (command) input.command = command[1].trim();
    if (file) input.file_path = file[1].trim();
    events.push(eventFromCall({ id: null, tool: name[1], input, timestamp: null }, cwd, null));
  }
  return events;
}

export function resolveCwd(cwd?: string): string {
  return resolve(cwd || process.cwd());
}
