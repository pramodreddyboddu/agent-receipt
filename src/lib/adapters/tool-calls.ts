import { sha256Hex } from '../hash.js';
import { DEFAULT_MAX_TOOL_EVENTS, DEFAULT_MAX_TOOL_SECTION_BYTES } from '../byte-limit.js';
import type { RiskHint } from '../risk.js';
import { adapterForAgent, ADAPTERS, getAdapter } from './index.js';
import { capEvents, normalizeTouch } from './parse-common.js';
import { redactTranscriptText } from './redact-transcript.js';
import type { ToolCallEvent } from './types.js';

export interface ToolCallSection {
  adapter: string;
  events: ToolCallEvent[];
  truncated: number;
  sha256: string;
}

const USER_HEADINGS = new Set([
  '# Agent Receipt',
  '## What to review',
  '## Session',
  '## Tool calls',
]);

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(',')}}`;
}

/** SHA-256 of the capped, redacted events that are written on the receipt. */
export function hashToolEvents(events: ToolCallEvent[]): string {
  const canonical = events.map((event) => ({
    argsSummary: event.argsSummary,
    command: event.command,
    exitStatus: event.exitStatus,
    files: event.files,
    timestamp: event.timestamp,
    tool: event.tool,
    writes: event.writes,
  }));
  return sha256Hex(stableStringify(canonical));
}

function safeInline(value: string): string {
  return value.replace(/`/g, "'").replace(/[\r\n]+/g, ' ');
}

function bullet(event: ToolCallEvent): string {
  const bits = [`\`${safeInline(event.tool)}\``];
  if (event.exitStatus !== null) bits.push(`exit ${event.exitStatus}`);
  if (event.command) bits.push(`\`${safeInline(event.command)}\``);
  else if (event.argsSummary) bits.push(`\`${safeInline(event.argsSummary)}\``);
  if (event.files.length) bits.push(`files: ${event.files.map((file) => `\`${safeInline(file)}\``).join(', ')}`);
  let line = `- ${bits.join(' — ')}`;
  if (USER_HEADINGS.has(line)) line = ` ${line}`;
  return line;
}

/** The heading is the first line, exactly once. User lines cannot repeat it. */
export function formatToolCallSection(section: ToolCallSection): string {
  const counts = new Map<string, number>();
  for (const event of section.events) counts.set(event.tool, (counts.get(event.tool) ?? 0) + 1);
  const byTool = [...counts.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([tool, count]) => `${tool} ${count}`)
    .join(', ');
  const lines = [
    '## Tool calls',
    '',
    `- **Count**: ${section.events.length}`,
    `- **By tool**: ${byTool || '(none)'}`,
    `- **Adapter**: ${section.adapter}`,
    `- **Tool-calls sha256**: \`${section.sha256}\``,
  ];
  for (const event of section.events) lines.push(bullet(event));
  if (section.truncated > 0) {
    lines.push('');
    lines.push(
      `_Truncated: ${section.truncated} events omitted (cap ${DEFAULT_MAX_TOOL_EVENTS}). The tool-calls sha256 covers the capped list._`,
    );
  }
  lines.push('');
  return lines.join('\n');
}

function fitSection(section: ToolCallSection): ToolCallSection {
  let current = section;
  while (
    Buffer.byteLength(formatToolCallSection(current), 'utf8') > DEFAULT_MAX_TOOL_SECTION_BYTES &&
    current.events.length > 0
  ) {
    const events = current.events.slice(0, -1);
    current = {
      adapter: current.adapter,
      events,
      truncated: current.truncated + 1,
      sha256: hashToolEvents(events),
    };
  }
  return current;
}

export interface LoadToolCallsOptions {
  cwd: string;
  transcript: string;
  adapter?: string;
  agent?: string;
}

/**
 * Parse a transcript into the section stored on the receipt.
 * Unknown `--adapter` throws (usage). A missing or unparseable file returns
 * ok false so the caller can warn and still exit 0.
 */
export function loadToolCallSection(
  opts: LoadToolCallsOptions,
): { ok: true; section: ToolCallSection } | { ok: false; reason: string } {
  if (opts.adapter) {
    const named = getAdapter(opts.adapter);
    if (!named) {
      throw new Error(
        `Unknown adapter "${opts.adapter}". Known adapters: ${ADAPTERS.map((item) => item.name).join(', ')}.`,
      );
    }
    const parsed = named.parseTranscript(opts.transcript, opts.cwd);
    if (!parsed.ok) return { ok: false, reason: parsed.reason || 'transcript could not be parsed' };
    const capped = capEvents(parsed.events);
    return {
      ok: true,
      section: fitSection({
        adapter: named.name,
        events: capped.events,
        truncated: capped.truncated,
        sha256: hashToolEvents(capped.events),
      }),
    };
  }
  const preferred = adapterForAgent(opts.agent);
  if (preferred) {
    const parsed = preferred.parseTranscript(opts.transcript, opts.cwd);
    if (!parsed.ok) return { ok: false, reason: parsed.reason || 'transcript could not be parsed' };
    const capped = capEvents(parsed.events);
    return {
      ok: true,
      section: fitSection({
        adapter: preferred.name,
        events: capped.events,
        truncated: capped.truncated,
        sha256: hashToolEvents(capped.events),
      }),
    };
  }
  let best: { name: string; events: ToolCallEvent[] } | null = null;
  let reason = 'transcript did not match a known adapter format';
  for (const adapter of ADAPTERS) {
    const parsed = adapter.parseTranscript(opts.transcript, opts.cwd);
    if (!parsed.ok) {
      if (parsed.reason) reason = parsed.reason;
      continue;
    }
    if (!best || parsed.events.length > best.events.length) {
      best = { name: adapter.name, events: parsed.events };
    }
  }
  if (!best) return { ok: false, reason };
  const capped = capEvents(best.events);
  return {
    ok: true,
    section: fitSection({
      adapter: best.name,
      events: capped.events,
      truncated: capped.truncated,
      sha256: hashToolEvents(capped.events),
    }),
  };
}

/**
 * Low-severity risks. A diff path no tool call mentions, and an explicit
 * write tool whose path is absent from the diff. Shell text is not a write.
 */
export function toolCallCrossCheck(diffPaths: string[], events: ToolCallEvent[], cwd: string): RiskHint[] {
  const mentioned = new Set<string>();
  const writes = new Set<string>();
  for (const event of events) {
    for (const file of event.files) {
      const path = normalizeTouch(file, cwd);
      if (path) mentioned.add(path);
    }
    for (const file of event.writes) {
      const path = normalizeTouch(file, cwd);
      if (!path) continue;
      mentioned.add(path);
      writes.add(path);
    }
  }
  const diffs = new Set<string>();
  for (const file of diffPaths) {
    const path = normalizeTouch(file, cwd);
    if (path) diffs.add(path);
  }
  const risks: RiskHint[] = [];
  for (const path of diffs) {
    if (mentioned.has(path)) continue;
    risks.push({
      severity: 'low',
      code: 'tool-call-unmentioned-diff',
      path,
      message: redactTranscriptText(`diff touches ${path} and no tool call mentions it`),
    });
  }
  for (const path of writes) {
    if (diffs.has(path)) continue;
    risks.push({
      severity: 'low',
      code: 'tool-call-write-not-in-diff',
      path,
      message: redactTranscriptText(`tool call writes ${path} and the diff does not show it`),
    });
  }
  return risks;
}
