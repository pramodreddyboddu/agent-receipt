/**
 * OpenTelemetry OTLP/JSON trace document (ExportTraceServiceRequest).
 * File only: no network, no collector client, no wall clock.
 * The same receipt bytes produce the same JSON bytes.
 *
 * traceId is the first 16 bytes of the trace-root receipt sha256.
 * spanId is the first 8 bytes of sha256(`${receiptSha}:${index}`).
 * Index 0 is that receipt. Later indexes are its commands and tool calls.
 * A session tree shares one traceId. Each receipt still uses its own sha
 * for its span ids. Times are decimal unix-nano strings.
 * Span kind and status.code are OTLP enum integers, not names.
 */
import { DEFAULT_MAX_TOOL_ARG_CHARS } from './byte-limit.js';
import { redactTranscriptText } from './adapters/redact-transcript.js';
import { sha256Hex } from './hash.js';
import { redactSecretsInText } from './redact.js';
import { parseRiskSummaryMarkdown } from './risk.js';

const NAME_MAX = 128;
const SERVICE = 'agent-receipt';

export interface OtlpActivity {
  /** Span name, already redacted and clipped. */
  name: string;
  tool: string | null;
  command: string | null;
  args: string | null;
  exitCode: number | null;
  policyDenied: boolean;
  /** Recorded time, or null when the receipt has none for this event. */
  timestamp: string | null;
}

export interface OtlpReceipt {
  sha256: string;
  agent: string | null;
  adapter: string | null;
  host: string | null;
  repo: string | null;
  riskTotal: number;
  maxSeverity: 'high' | 'medium' | 'low' | 'none';
  /** Null when neither the audit log nor the companion JSON recorded it. */
  failedOn: boolean | null;
  /** Gate exit from the audit log. Null when unknown. Not a child exit. */
  exitCode: number | null;
  signed: boolean;
  /** 1-based last matching audit.jsonl line. Null when unknown. */
  hashChainPosition: number | null;
  timestamp: string | null;
  policyDenied: boolean;
  activities: OtlpActivity[];
  children: OtlpReceipt[];
}

interface AnyValue {
  stringValue?: string;
  intValue?: string;
  boolValue?: boolean;
}

interface Attribute {
  key: string;
  value: AnyValue;
}

/**
 * OTLP/JSON encodes enums as integers.
 * SpanKind: 1 INTERNAL, 3 CLIENT. StatusCode: 1 OK, 2 ERROR.
 * 0 is STATUS_CODE_UNSET and is not emitted.
 */
const SPAN_KIND_INTERNAL = 1;
const SPAN_KIND_CLIENT = 3;
const STATUS_CODE_OK = 1;
const STATUS_CODE_ERROR = 2;

interface SpanStatus {
  code: typeof STATUS_CODE_OK | typeof STATUS_CODE_ERROR;
  message?: string;
}

interface Span {
  traceId: string;
  spanId: string;
  parentSpanId: string;
  name: string;
  kind: typeof SPAN_KIND_INTERNAL | typeof SPAN_KIND_CLIENT;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: Attribute[];
  status: SpanStatus;
}

/** First 8 bytes of sha256(`${receiptSha}:${index}`), 16 lowercase hex chars. */
export function spanIdFor(receiptSha: string, index: number): string {
  return sha256Hex(`${receiptSha}:${index}`).slice(0, 16);
}

/** First 16 bytes of the receipt sha256, 32 lowercase hex chars. */
export function traceIdFor(receiptSha: string): string {
  return receiptSha.slice(0, 32).toLowerCase();
}

/**
 * Decimal unix-nano. Zone-less calendar times are UTC.
 * 16–20 digit values stay. 13-digit values are milliseconds.
 * 10-digit values are seconds. Unparseable input returns null.
 * This does not read the clock.
 */
export function unixNano(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const text = raw.trim();
  if (!text) return null;
  if (/^\d{16,20}$/.test(text)) return text;
  if (/^\d{13}$/.test(text)) return (BigInt(text) * 1000000n).toString();
  if (/^\d{10}$/.test(text)) return (BigInt(text) * 1000000000n).toString();
  let iso = text;
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(iso)) {
    iso = `${iso.replace(' ', 'T')}Z`;
  }
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return (BigInt(ms) * 1000000n).toString();
}

function scrub(value: string): string {
  return value
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[\u2028\u2029\t]+/g, ' ')
    .replace(/ {2,}/g, ' ')
    .trim();
}

function clip(value: string, max: number): string {
  const flat = scrub(value);
  if (!flat) return '';
  if (flat.length <= max) return flat;
  return `${flat.slice(0, Math.max(0, max - 1))}…`;
}

/** Commands, args, and tool names. Host labels and repo URLs must not use this. */
function redactNarrative(value: string, max = DEFAULT_MAX_TOOL_ARG_CHARS): string {
  return clip(redactTranscriptText(value), max);
}

/**
 * Host labels and Remote URLs. Secret tokens only.
 * redactTranscriptText would also turn hostnames and https URLs into `[host]`.
 */
function redactLabel(value: string): string {
  return clip(redactSecretsInText(value), DEFAULT_MAX_TOOL_ARG_CHARS);
}

function field(text: string, label: string): string | null {
  const match = text.match(new RegExp(`^- \\*\\*${label}\\*\\*:([^\\n]*)$`, 'm'));
  if (!match) return null;
  let value = match[1].trim();
  if (value.startsWith('`') && value.endsWith('`') && value.length >= 2) {
    value = value.slice(1, -1);
  }
  return value || null;
}

function sectionAfter(text: string, heading: string): string {
  const escaped = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`^## ${escaped}\\n`, 'm').exec(text);
  if (!match) return '';
  const rest = text.slice(match.index + match[0].length);
  const next = rest.search(/^## /m);
  return next === -1 ? rest : rest.slice(0, next);
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('`') && trimmed.endsWith('`') && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

interface ToolLine {
  line: number;
  tool: string;
  exit: number | null;
  command: string | null;
}

function parseToolLine(line: string, lineNo: number): ToolLine | null {
  if (!line.startsWith('- `')) return null;
  const parts = line.slice(2).split(' — ');
  const tool = unquote(parts[0] ?? '');
  if (!tool) return null;
  let exit: number | null = null;
  let command: string | null = null;
  for (const part of parts.slice(1)) {
    const exitMatch = part.match(/^exit (-?\d+)$/);
    if (exitMatch) {
      exit = Number(exitMatch[1]);
      continue;
    }
    if (part.startsWith('files:')) continue;
    if (part.startsWith('`')) command = unquote(part);
  }
  return { line: lineNo, tool, exit, command };
}

function parseDeny(markdown: string): { denied: boolean; evidence: string[] } {
  const section = sectionAfter(markdown, 'Policy packs');
  const evidence: string[] = [];
  let denied = false;
  for (const line of section.split('\n')) {
    const match = line.match(/^\|\s*(deny|warn)\s*\|\s*([A-Za-z]+)\s*\|\s*`([^`]*)`\s*\|\s*(.*?)\s*\|\s*$/i);
    if (!match || match[1].toLowerCase() !== 'deny') continue;
    denied = true;
    const ev = redactNarrative(match[4] ?? '');
    if (ev) evidence.push(ev);
  }
  return { denied, evidence };
}

function activityDenied(evidence: string[], tool: string, command: string | null): boolean {
  const parts = [tool, command ?? ''].map((item) => item.toLowerCase()).filter((item) => item.length >= 4);
  for (const raw of evidence) {
    const ev = raw.toLowerCase();
    if (ev.length < 4) continue;
    for (const part of parts) {
      if (part.includes(ev) || ev.includes(part)) return true;
    }
  }
  return false;
}

function activityFrom(
  tool: string,
  command: string | null,
  args: string | null,
  exitCode: number | null,
  evidence: string[],
): OtlpActivity {
  const denied = activityDenied(evidence, tool, command);
  const named = command || tool || (command ? 'command' : 'tool');
  return {
    name: clip(named, NAME_MAX) || (command ? 'command' : 'tool'),
    tool: tool || null,
    command,
    args: command ? null : args,
    exitCode,
    policyDenied: denied,
    timestamp: null,
  };
}

/**
 * Commands and tool calls in file order. A shell tool call is one span.
 * A `## Commands` line that repeats that command is not a second span.
 * Diff bodies are not copied.
 */
function activitiesFrom(markdown: string, evidence: string[]): OtlpActivity[] {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  let section: 'none' | 'commands' | 'tools' | 'other' = 'none';
  const tools: ToolLine[] = [];
  const commands: Array<{ line: number; text: string }> = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('## ')) {
      if (line === '## Tool calls') section = 'tools';
      else if (line === '## Commands') section = 'commands';
      else section = 'other';
      continue;
    }
    if (section === 'tools') {
      const parsed = parseToolLine(line, i);
      if (parsed) tools.push(parsed);
      continue;
    }
    if (section === 'commands' && line.startsWith('- ')) {
      const text = line.slice(2).trim();
      if (!text || text.startsWith('_') || text.startsWith('**')) continue;
      commands.push({ line: i, text });
    }
  }

  const pending: Array<{ line: number; activity: OtlpActivity }> = [];
  const seenCommands = new Set<string>();
  for (const toolLine of tools) {
    const tool = redactNarrative(toolLine.tool) || 'tool';
    const payload = toolLine.command ? redactNarrative(toolLine.command) : null;
    const isArgs = Boolean(payload && (payload.startsWith('{') || payload.startsWith('[')));
    const command = payload && !isArgs ? payload : null;
    const args = isArgs ? payload : null;
    if (command) seenCommands.add(command);
    pending.push({
      line: toolLine.line,
      activity: activityFrom(tool, command, args, toolLine.exit, evidence),
    });
  }
  for (const commandLine of commands) {
    const command = redactNarrative(commandLine.text);
    if (!command || seenCommands.has(command)) continue;
    seenCommands.add(command);
    pending.push({
      line: commandLine.line,
      activity: activityFrom('command', command, null, null, evidence),
    });
  }
  pending.sort((a, b) => a.line - b.line);
  return pending.map((item) => item.activity);
}

/** Facts from one verified receipt. The caller fills sha, audit, and signature. */
export function parseReceiptFacts(markdown: string): OtlpReceipt {
  const risk = parseRiskSummaryMarkdown(markdown);
  const deny = parseDeny(markdown);
  const agent = field(markdown, 'Agent');
  const adapter = field(sectionAfter(markdown, 'Tool calls'), 'Adapter');
  const host = field(markdown, 'Host');
  const repo = field(markdown, 'Remote');
  const maxSeverity = risk.maxSeverity ?? 'none';
  return {
    sha256: '',
    agent: agent ? redactLabel(agent) : null,
    adapter: adapter ? redactLabel(adapter) : null,
    host: host ? redactLabel(host) : null,
    repo: repo ? redactLabel(repo) : null,
    riskTotal: risk.total,
    maxSeverity,
    failedOn: null,
    exitCode: null,
    signed: false,
    hashChainPosition: null,
    timestamp: field(markdown, 'Timestamp'),
    policyDenied: deny.denied,
    activities: activitiesFrom(markdown, deny.evidence),
    children: [],
  };
}

function attributes(pairs: Array<[string, string | number | boolean | null | undefined]>): Attribute[] {
  const out: Attribute[] = [];
  for (const [key, raw] of pairs) {
    if (raw === null || raw === undefined) continue;
    if (typeof raw === 'string') {
      if (!raw) continue;
      out.push({ key, value: { stringValue: raw } });
    } else if (typeof raw === 'boolean') {
      out.push({ key, value: { boolValue: raw } });
    } else if (typeof raw === 'number' && Number.isFinite(raw)) {
      out.push({ key, value: { intValue: String(Math.trunc(raw)) } });
    }
  }
  out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return out;
}

function assertId(id: string, width: number, what: string): void {
  if (!new RegExp(`^[0-9a-f]{${width}}$`).test(id) || /^0+$/.test(id)) {
    throw new Error(`refusing an invalid ${what}`);
  }
}

function statusFor(error: boolean, policy: boolean): SpanStatus {
  if (!error) return { code: STATUS_CODE_OK };
  return { code: STATUS_CODE_ERROR, message: policy ? 'policy deny' : 'non-zero exit' };
}

function receiptSpan(receipt: OtlpReceipt, traceId: string, parentSpanId: string, start: string): Span {
  const spanId = spanIdFor(receipt.sha256, 0);
  assertId(spanId, 16, 'spanId');
  const error =
    receipt.policyDenied || receipt.failedOn === true || (receipt.exitCode !== null && receipt.exitCode !== 0);
  return {
    traceId,
    spanId,
    parentSpanId,
    name: 'agent.run',
    kind: SPAN_KIND_INTERNAL,
    startTimeUnixNano: start,
    endTimeUnixNano: start,
    attributes: attributes([
      ['agent_receipt.adapter', receipt.adapter],
      ['agent_receipt.agent', receipt.agent],
      ['agent_receipt.exit_code', receipt.exitCode],
      ['agent_receipt.failed_on', receipt.failedOn],
      ['agent_receipt.hash_chain_position', receipt.hashChainPosition],
      ['agent_receipt.index', 0],
      ['agent_receipt.max_severity', receipt.maxSeverity],
      ['agent_receipt.policy_denied', receipt.policyDenied ? true : null],
      ['agent_receipt.risk', receipt.riskTotal],
      ['agent_receipt.sha256', receipt.sha256],
      ['agent_receipt.signed', receipt.signed],
      ['gen_ai.agent.name', receipt.agent],
      ['host.name', receipt.host],
      ['vcs.repository.url.full', receipt.repo],
    ]),
    status: statusFor(error, receipt.policyDenied),
  };
}

function activitySpan(
  receipt: OtlpReceipt,
  activity: OtlpActivity,
  index: number,
  traceId: string,
  parentSpanId: string,
  parentStart: string,
): Span {
  const spanId = spanIdFor(receipt.sha256, index);
  assertId(spanId, 16, 'spanId');
  const start = unixNano(activity.timestamp) ?? parentStart;
  const error = activity.policyDenied || (activity.exitCode !== null && activity.exitCode !== 0);
  return {
    traceId,
    spanId,
    parentSpanId,
    name: activity.name,
    kind: SPAN_KIND_CLIENT,
    startTimeUnixNano: start,
    endTimeUnixNano: start,
    attributes: attributes([
      ['agent_receipt.args', activity.args],
      ['agent_receipt.exit_code', activity.exitCode],
      ['agent_receipt.index', index],
      ['agent_receipt.kind', activity.command ? 'command' : 'tool'],
      ['agent_receipt.tool', activity.tool],
      ['gen_ai.tool.name', activity.tool],
      ['process.command_line', activity.command],
    ]),
    status: statusFor(error, activity.policyDenied),
  };
}

function walk(receipt: OtlpReceipt, traceId: string, parentSpanId: string, spans: Span[], seen: Set<string>): void {
  const start = unixNano(receipt.timestamp) ?? '0';
  const span = receiptSpan(receipt, traceId, parentSpanId, start);
  if (seen.has(span.spanId)) throw new Error('refusing a trace with a duplicate spanId');
  seen.add(span.spanId);
  spans.push(span);
  receipt.activities.forEach((activity, index) => {
    const child = activitySpan(receipt, activity, index + 1, traceId, span.spanId, start);
    if (seen.has(child.spanId)) throw new Error('refusing a trace with a duplicate spanId');
    seen.add(child.spanId);
    spans.push(child);
  });
  for (const child of receipt.children) walk(child, traceId, span.spanId, spans, seen);
}

/**
 * One ExportTraceServiceRequest. `roots[0]` is the trace source.
 * Later roots are orphans and stay parentless in the same trace.
 * The caller rejects a parent cycle before this runs.
 */
export function renderOtlp(roots: OtlpReceipt[], version: string): string {
  if (!roots.length) throw new Error('otlp export has no receipts');
  const traceSource = roots[0];
  const traceId = traceIdFor(traceSource.sha256);
  assertId(traceId, 32, 'traceId');
  const spans: Span[] = [];
  const seen = new Set<string>();
  for (const root of roots) walk(root, traceId, '', spans, seen);
  const document = {
    resourceSpans: [
      {
        resource: {
          attributes: attributes([
            ['host.name', traceSource.host],
            ['service.name', SERVICE],
            ['service.version', version],
            ['vcs.repository.url.full', traceSource.repo],
          ]),
        },
        scopeSpans: [
          {
            scope: {
              name: SERVICE,
              version,
            },
            spans,
          },
        ],
      },
    ],
  };
  return `${JSON.stringify(document)}\n`;
}
