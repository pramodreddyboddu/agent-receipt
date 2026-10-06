/**
 * Multi-agent receipt linking (thin slice).
 *
 * A session id groups related runs. A parent reference is the link id
 * (`r-` + 16 hex) or the sha256 of the run that spawned this one.
 * Agent and host are short labels. Host is omitted unless the user opts in.
 *
 * These fields are written into the hashed Markdown body, inside the
 * `## Session` block the writer already emits. A receipt is 1.0.28+ only
 * when `matchV1028WriterSession` matches: the 1.0.28 writer grammar, with
 * fence awareness off, and exactly one `# Agent Receipt`, one
 * `## What to review`, and one `## Session` in the whole file. Fences do
 * not hide a line. Anything else is pre-1.0.28: no link metadata, and
 * verify uses 1.0.27 rules. An old writer quotes only the first message
 * line and then emits its own header, so a pasted 1.0.28 block leaves two
 * or more of each heading. The 1.0.28 writer never emits those lines from
 * user content. Nothing is written when no link flag and no
 * AGENT_RECEIPT_SESSION / PARENT / AGENT / HOST env is set.
 *
 * `--agent` stays the 1.0.27 free-form label (spaces allowed). `--session`
 * still accepts the values 1.0.27 stored, including spaces and slashes, as
 * one line. Generated ids (`--session new`, `--link`) are `s-` + 16 hex.
 * The strict label charset applies to `--host` and to those generated ids.
 * `--parent` is an r- id, a sha256, or a path that parses as a receipt.
 *
 * `wrap --link` (or `--session`, including `--session new`) exports
 * AGENT_RECEIPT_SESSION and AGENT_RECEIPT_PARENT into a child process
 * given after `--`, so a nested wrap records the same session and this
 * receipt's id as its parent. Flags win over env. `--session new` generates
 * a fresh session id. `--link` with no session reuses the env session or
 * generates one.
 */

import { randomBytes } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { assertReadableSize, type ByteLimitError } from './byte-limit.js';
import { isAbsolute, join, resolve } from 'node:path';
import { loadConfig } from './config.js';
import { extractEmbeddedHash, verifyMarkdown } from './hash.js';
import {
  decodeBacktickField,
  isInsideSessionPackage,
  isInsideSharePackage,
  isProveOnePagerName,
  isSessionPackageDirName,
  isSharePackageDirName,
  STRUCTURAL_HEADING_LINES,
} from './receipt.js';

/** 1–64 of [A-Za-z0-9._:-], must start alphanumeric, no ".." and no slashes. */
export const LINK_LABEL_MAX = 64;

/**
 * Free-form `--agent` / config `defaultAgent` / legacy `--session`.
 * Long enough for 1.0.27 display names. Longer values are rejected.
 */
export const FREEFORM_LABEL_MAX = 256;

const LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const LINK_ID_RE = /^r-[0-9a-f]{16}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
/** Newlines, C0 controls, DEL, and Unicode line separators. */
const CONTROL_RE = /[\u0000-\u001f\u007f\u2028\u2029]/;

const LINK_FIELD_LABELS = new Set(['Id', 'Session', 'Parent', 'Agent', 'Host']);

export const WARN_CROSS_SESSION = 'cross-session-parent';
export const WARN_PARENT_UNVERIFIED = 'parent-unverified';
export const WARN_MISSING_SESSION = 'missing-session';

export interface LinkMeta {
  id: string | null;
  session: string | null;
  parent: string | null;
  agent: string | null;
  host: string | null;
  timestamp: string | null;
}

export interface ResolveLinkInput {
  /** True when `--session` was passed (value may be the sentinel `new`). */
  sessionFlagPresent: boolean;
  sessionFlag?: string;
  parentFlagPresent: boolean;
  parentFlag?: string;
  /** True when `--agent` / `-a` was passed. */
  agentFlagPresent: boolean;
  agentFlag?: string;
  hostFlagPresent: boolean;
  hostFlag?: string;
  /** wrap-only. Generate a session when none is set, and export env to a child. */
  link: boolean;
  env?: NodeJS.ProcessEnv;
}

export interface ResolvedLink {
  /** Set when this run should record a session. */
  session?: string;
  /** Canonical parent reference (link id or 64-hex sha256). */
  parent?: string;
  /** From the flag or env only. Callers apply their own default when absent. */
  agent?: string;
  host?: string;
  /**
   * Link id to write on this receipt. Set whenever session, parent, or host
   * is recorded, and whenever wrap will export a parent id to a child.
   */
  id?: string;
  /**
   * Wrap should set AGENT_RECEIPT_SESSION and AGENT_RECEIPT_PARENT for a
   * child. True for `--link` and for an explicit `--session` (including `new`).
   */
  propagate: boolean;
}

export function newLinkId(): string {
  return `r-${randomBytes(8).toString('hex')}`;
}

export function newSessionId(): string {
  return `s-${randomBytes(8).toString('hex')}`;
}

/** Strict charset for new link labels (`--host`, generated `s-` session ids). */
export function validateLinkLabel(kind: string, value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`Invalid ${kind}: value is empty.`);
  }
  if (trimmed.length > LINK_LABEL_MAX || !LABEL_RE.test(trimmed) || trimmed.includes('..')) {
    throw new Error(
      `Invalid ${kind} ${JSON.stringify(value)}: use 1–${LINK_LABEL_MAX} characters ` +
        '(letters, digits, ".", "_", ":", "-"), starting with a letter or digit. ' +
        'Path separators and ".." are rejected.',
    );
  }
  return trimmed;
}

function rejectControl(kind: string, value: string): void {
  if (CONTROL_RE.test(value)) {
    throw new Error(
      `Invalid ${kind}: newlines and control characters are rejected.`,
    );
  }
}

/**
 * `--agent`, `AGENT_RECEIPT_AGENT`, and config `defaultAgent`.
 * Same acceptance as 1.0.27 except control characters, newlines, and length.
 */
export function validateAgentLabel(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error('Invalid agent: value is empty.');
  }
  if (trimmed.length > FREEFORM_LABEL_MAX) {
    throw new Error(
      `Invalid agent: use at most ${FREEFORM_LABEL_MAX} characters.`,
    );
  }
  rejectControl('agent', trimmed);
  return trimmed;
}

/**
 * `--session` and `AGENT_RECEIPT_SESSION`. 1.0.27 stored this string raw
 * (spaces and slashes included). Keep that, but only as a single line so
 * the value cannot break out of the Session header field.
 */
export function validateLegacySession(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error('Invalid session: value is empty.');
  }
  if (trimmed.length > FREEFORM_LABEL_MAX) {
    throw new Error(
      `Invalid session: use at most ${FREEFORM_LABEL_MAX} characters.`,
    );
  }
  rejectControl('session', trimmed);
  return trimmed;
}

export function validateStoredId(value: string): string {
  const trimmed = value.trim();
  if (!LINK_ID_RE.test(trimmed)) {
    throw new Error(
      `Invalid id ${JSON.stringify(trimmed)}: link id must be r- followed by 16 hex digits.`,
    );
  }
  return trimmed;
}

/** Value stored on the Parent line after path resolution. */
export function validateStoredParent(value: string): string {
  const trimmed = value.trim();
  if (LINK_ID_RE.test(trimmed) || SHA256_RE.test(trimmed)) return trimmed;
  throw new Error(
    `Invalid parent ${JSON.stringify(trimmed)}: stored parent must be an r- id or a 64-hex sha256.`,
  );
}

function envValue(env: NodeJS.ProcessEnv | undefined, name: string): string | undefined {
  const raw = env?.[name];
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  return trimmed ? trimmed : undefined;
}

function requireFlagValue(name: string, present: boolean, value: string | undefined): string | undefined {
  if (!present) return undefined;
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`--${name} requires a value.`);
  }
  return value.trim();
}

/** Receipt .md files under outDir, newest last is not required. Skips prove pages, share packages, and session packages. */
export function listOutDirReceipts(cwd: string): string[] {
  const cfg = loadConfig(cwd);
  const dir = cfg.outDir.startsWith('/') ? cfg.outDir : join(cwd, cfg.outDir);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => !isSharePackageDirName(f) && !isSessionPackageDirName(f))
    .filter((f) => f.endsWith('.md') && !isProveOnePagerName(f))
    .map((f) => join(dir, f))
    .filter((p) => !isInsideSharePackage(p) && !isInsideSessionPackage(p))
    .filter((p) => {
      try {
        return statSync(p).isFile();
      } catch {
        return false;
      }
    });
}

function markdownLines(markdown: string): string[] {
  return markdown.replace(/\r\n/g, '\n').split('\n');
}

const NOTHING_FLAGGED =
  '_Nothing flagged. Skim the file list if this session should have been a no-op._';
/** Inserted by redact into the session block, after Workspace. */
const REDACTED_NOTICE =
  '- **Redacted**: yes — high/secret findings masked for safer sharing';
const NEXT_WRITER_HEADINGS = new Set([
  '## Notable changes',
  '## Commits',
  '## Files changed',
]);

// `s` so a CR or U+2028 inside one physical line still matches. Those are
// not line endings here; lines were already split on LF.
const REVIEW_ITEM_RE =
  /^(\d+)\. \*\*(high|medium|notable)\*\* `[^`]+` \u2014 .*$/s;
const FILES_ROW_RE = /^\| Files \| \d+( \([^)\n]+\))? \|$/;
const LINES_ROW_RE = /^\| Lines \| \+\d+ \/ \u2212\d+ \|$/;
const COMMITS_ROW_RE = /^\| Commits \| \d+ \|$/;
const RISK_ROW_RE =
  /^\| Risk \| (?:none|\d+ \(high \d+, medium \d+, low \d+\)) \|$/;
const MAX_SEV_ROW_RE = /^\| Max severity \| \*\*(?:high|medium|low)\*\* \|$/;
const VERSION_RE = /^- \*\*Version\*\*: \d+\.\d+\.\d+$/;
const TIMESTAMP_RE = /^- \*\*Timestamp\*\*: \S.*$/s;
const BRANCH_RE = /^- \*\*Branch\*\*: `[^`]*`$/;
const HEAD_RE = /^- \*\*HEAD\*\*: `[^`]*`$/;
const REMOTE_RE = /^- \*\*Remote\*\*: .+$/s;
const RANGE_COMMITTED_RE =
  /^- \*\*Range\*\*: `[^`]*` \(`[^`]*` \u2192 HEAD\)$/;
const RANGE_DIRTY_RE =
  /^- \*\*Range\*\*: `[^`]*` _\(working tree; not committed\)_$/;
const SNAPSHOT_RE =
  /^- \*\*Snapshot\*\*: \*\*uncommitted\*\* \(staged \+ unstaged \+ untracked\)$/;
const ID_RE = /^- \*\*Id\*\*: .+$/s;
const AGENT_RE = /^- \*\*Agent\*\*: .+$/s;
const SESSION_RE = /^- \*\*Session\*\*: .+$/s;
const PARENT_RE = /^- \*\*Parent\*\*: .+$/s;
const HOST_RE = /^- \*\*Host\*\*: .+$/s;
const MESSAGE_RE = /^- \*\*Message\*\*: .*$/s;
const WORKSPACE_RE = /^- \*\*Workspace\*\*: `[^`]*`$/;

/**
 * Split a receipt the way the 1.0.28 writer ended lines.
 *
 * The writer joins with `\n`. A file that is entirely CRLF is that same
 * document with the line ending translated, so those pairs become `\n`.
 * A bare CR (CR-only file, or a CR that is not part of a CRLF pair mixed
 * with real CRLF) is not that writer. A single `\r\n` inside an otherwise
 * LF file is the `## What to review\r` message trick: reject it here so
 * the heading does not become a clean `## What to review` after a global
 * CRLF strip. An embedded CR that is not a line ending (a 1.0.27 agent
 * value `pre\rmid`) stays inside its LF line.
 */
function writerGrammarLines(markdown: string): string[] | null {
  const hasCrlf = markdown.includes('\r\n');
  const hasLoneCr = /\r(?!\n)/.test(markdown);
  const hasLoneLf = /(^|[^\r])\n/.test(markdown);
  if (hasLoneCr) {
    if (!markdown.includes('\n') || hasCrlf) return null;
    return markdown.split('\n');
  }
  if (hasCrlf) {
    if (hasLoneLf) return null;
    return markdown.replace(/\r\n/g, '\n').split('\n');
  }
  return markdown.split('\n');
}

/**
 * Session-field lines of a 1.0.28 writer header, or null when the file is
 * not that header.
 *
 * Fence awareness is deliberately off from the title line through the end
 * of `## Session`. A 1.0.16/1.0.27 writer quotes only the first message
 * line and emits the rest raw, so a message can carry a fake
 * `## What to review` / `## Summary` / `## Session` whose trailing ```
 * opens a fence. That fence hides the real header and the second copy of
 * the message; the second copy's ``` closes it. A fence-aware scan then
 * sees exactly one block in the writer's position and links the receipt.
 * Tracking fences would accept that spoof. This function does not track
 * them. It requires the exact bytes `formatMarkdown` emits: the title,
 * only TL;DR quotes and blank lines, the first `## What to review` with
 * the writer's review body, `## Summary` with the writer's metric table,
 * `## Session` fields in writer order, then the heading the writer emits
 * next (`## Notable changes`, `## Commits`, or `## Files changed`). A raw
 * line, a fence (` ``` ` or `~~~`, any info string), an extra heading, a
 * CR-only or mixed line ending, or an out-of-order field means
 * pre-1.0.28: no link metadata.
 *
 * That grammar alone still accepts a layout mimic: an old writer quotes
 * only the first message line, so the rest of a pasted 1.0.28 block is
 * raw, and this scan stops at the first `## Commits`. The real header is
 * later in the file. After the grammar matches, the whole file is scanned
 * again with fences ignored (a fenced line still counts). There must be
 * exactly one `# Agent Receipt`, one `## What to review`, and one
 * `## Session`. Any other count is pre-1.0.28. When the TL;DR line
 * contains a timestamp, it must be the header Timestamp; a TL;DR with no
 * timestamp skips that check. The 1.0.28 writer emits one and it matches.
 */
export function matchV1028WriterSession(markdown: string): string[] | null {
  const lines = writerGrammarLines(markdown);
  if (!lines) return null;
  let i = 0;
  if (lines[i] !== '# Agent Receipt') return null;
  i += 1;
  while (lines[i] === '') i += 1;
  if (!/^> \*\*TL;DR\*\* \S/.test(lines[i] ?? '')) return null;
  while (i < lines.length && lines[i] !== '## What to review') {
    const line = lines[i];
    // `>` is the writer's blank quote. `> ` is a TL;DR or message line.
    if (line === '' || line === '>' || line.startsWith('> ')) {
      i += 1;
      continue;
    }
    return null;
  }
  if (lines[i] !== '## What to review') return null;
  i += 1;
  if (lines[i] !== '') return null;
  i += 1;
  if (lines[i] === NOTHING_FLAGGED) {
    i += 1;
  } else {
    let n = 1;
    while (REVIEW_ITEM_RE.test(lines[i] ?? '')) {
      if (Number((lines[i].match(/^(\d+)/) ?? [])[1]) !== n) return null;
      n += 1;
      i += 1;
    }
    if (n === 1) return null;
  }
  if (lines[i] !== '') return null;
  i += 1;
  if (lines[i] !== '## Summary') return null;
  i += 1;
  if (lines[i] !== '') return null;
  i += 1;
  if (lines[i] !== '| Metric | Value |') return null;
  i += 1;
  if (lines[i] !== '|--------|-------|') return null;
  i += 1;
  if (!FILES_ROW_RE.test(lines[i] ?? '')) return null;
  i += 1;
  if (!LINES_ROW_RE.test(lines[i] ?? '')) return null;
  i += 1;
  if (!COMMITS_ROW_RE.test(lines[i] ?? '')) return null;
  i += 1;
  if (!RISK_ROW_RE.test(lines[i] ?? '')) return null;
  i += 1;
  if (MAX_SEV_ROW_RE.test(lines[i] ?? '')) i += 1;
  if (lines[i] !== '') return null;
  i += 1;
  if (lines[i] !== '## Session') return null;
  i += 1;
  if (lines[i] !== '') return null;
  i += 1;

  const bodyStart = i;
  const take = (re: RegExp): boolean => {
    if (re.test(lines[i] ?? '')) {
      i += 1;
      return true;
    }
    return false;
  };
  if (!take(VERSION_RE) || !take(TIMESTAMP_RE) || !take(BRANCH_RE) || !take(HEAD_RE)) {
    return null;
  }
  take(REMOTE_RE);
  if (take(RANGE_DIRTY_RE)) {
    if (!take(SNAPSHOT_RE)) return null;
  } else if (!take(RANGE_COMMITTED_RE)) {
    return null;
  }
  take(ID_RE);
  take(AGENT_RE);
  take(SESSION_RE);
  take(PARENT_RE);
  take(HOST_RE);
  if (take(MESSAGE_RE)) {
    while ((lines[i] ?? '').startsWith('  ')) i += 1;
  }
  if (!take(WORKSPACE_RE)) return null;
  if (lines[i] === REDACTED_NOTICE) i += 1;
  if (lines[i] !== '') return null;
  i += 1;
  if (!NEXT_WRITER_HEADINGS.has(lines[i] ?? '')) return null;
  const body = lines.slice(bodyStart, i - 1);
  if (!exactlyOneStructuralHeading(lines)) return null;
  const tsLine = body.find((line) => line.startsWith('- **Timestamp**: '));
  const ts = tsLine ? tsLine.slice('- **Timestamp**: '.length) : '';
  if (!tldrTimestampAgrees(lines, ts)) return null;
  return body;
}

/** Fences are not tracked. A line inside a fence counts. */
function exactlyOneStructuralHeading(lines: string[]): boolean {
  const counts = new Map<string, number>();
  for (const heading of STRUCTURAL_HEADING_LINES) counts.set(heading, 0);
  for (const line of lines) {
    if (!counts.has(line)) continue;
    counts.set(line, (counts.get(line) ?? 0) + 1);
  }
  for (const count of counts.values()) {
    if (count !== 1) return false;
  }
  return true;
}

/**
 * The 1.0.28 writer puts the header timestamp in the TL;DR between ` · `.
 * No timestamp-shaped token in that line means this writer did not emit
 * one: skip the check. A token that is not the header timestamp is a mimic.
 */
function tldrTimestampAgrees(lines: string[], headerTimestamp: string): boolean {
  const tldr = lines.find((line) => line.startsWith('> **TL;DR** '));
  if (!tldr) return true;
  if (!/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(tldr)) return true;
  return tldr.includes(` · ${headerTimestamp} · `);
}

/**
 * Body of the writer `## Session` block when the header matches the 1.0.28
 * writer grammar. Otherwise null, which callers treat as pre-1.0.28: no
 * link metadata.
 */
export function sessionHeaderLines(markdown: string): string[] | null {
  return matchV1028WriterSession(markdown);
}

/**
 * `.` does not match CR or U+2028/U+2029, so a value with those characters
 * would otherwise fail the match and be read as absent. `s` keeps them.
 */
const FIELD_RE = /^- \*\*([A-Za-z][A-Za-z0-9 ]*)\*\*:\s*(.*)$/s;

function cleanFieldValue(raw: string): string {
  return raw.replace(/^`|`$/g, '').trim();
}

/**
 * Field lines in the header block. Indented message continuations stay part
 * of Message (they cannot be headings or field lines). Link fields after
 * Message or Workspace are ignored.
 */
function headerFieldMap(body: string[]): Map<string, string> {
  const fields = new Map<string, string>();
  let closed = false;
  for (let i = 0; i < body.length; i++) {
    const match = body[i].match(FIELD_RE);
    if (!match) continue;
    const label = match[1];
    if (closed && LINK_FIELD_LABELS.has(label)) continue;
    if (!fields.has(label)) {
      let raw = match[2];
      if (label === 'Message') {
        const extra: string[] = [];
        while (i + 1 < body.length && body[i + 1].startsWith('  ')) {
          i += 1;
          extra.push(body[i].slice(2));
        }
        if (extra.length) raw = `${raw}\n${extra.join('\n')}`;
      }
      let value = cleanFieldValue(raw);
      if (label === 'Branch' || label === 'Workspace') value = decodeBacktickField(value);
      if (value) fields.set(label, value);
    }
    if (label === 'Message' || label === 'Workspace') closed = true;
  }
  return fields;
}

/**
 * Link rules apply only when the writer grammar matched. Version is read
 * from that block only. 1.0.28+ is `1.0.28` and any newer major.minor.patch.
 * Any other shape is not link-era, even if some line says `1.0.28`.
 */
export function isLinkEraVersion(version: string | null | undefined): boolean {
  if (!version) return false;
  const match = version.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) return false;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (major > 1) return true;
  if (major < 1) return false;
  if (minor > 0) return true;
  return patch >= 28;
}

/** Header fields keyed by their Markdown label (Branch, Agent, Message, …). */
export function parseSessionHeader(markdown: string): Record<string, string> {
  const body = sessionHeaderLines(markdown);
  if (!body) return {};
  return Object.fromEntries(headerFieldMap(body));
}

const EMPTY_LINK: LinkMeta = {
  id: null,
  session: null,
  parent: null,
  agent: null,
  host: null,
  timestamp: null,
};

export function parseLinkMeta(markdown: string): LinkMeta {
  const header = parseSessionHeader(markdown);
  if (!isLinkEraVersion(header.Version)) return { ...EMPTY_LINK };
  const field = (label: string): string | null => header[label] ?? null;
  return {
    id: field('Id'),
    session: field('Session'),
    parent: field('Parent'),
    agent: field('Agent'),
    host: field('Host'),
    timestamp: field('Timestamp'),
  };
}

/**
 * True when the markdown is an agent-receipt document, not an arbitrary file.
 * Requires a Session heading and a Version line, plus either the writer title
 * or an embedded sha256. This is not the link-era grammar: a 1.0.27 receipt
 * whose message split the header is still a receipt.
 */
export function isReceiptDocument(markdown: string): boolean {
  const lines = markdownLines(markdown).map((line) => line.replace(/\r$/, ''));
  if (!lines.includes('## Session')) return false;
  if (!lines.some((line) => line.startsWith('- **Version**:'))) return false;
  if (lines.includes('# Agent Receipt')) return true;
  const embedded = extractEmbeddedHash(markdown);
  return Boolean(embedded && SHA256_RE.test(embedded));
}

/** Host value `share` writes when it masks the label. It is not a user host. */
const REDACTED_HOST = '[REDACTED]';

/**
 * Hash-ok 1.0.28+ receipts whose strict link fields are illegal are tampered.
 * Checked: receipt id (`r-` + 16 hex), parent (`r-` id or sha256), and host
 * (strict label). Generated session ids are `s-` + 16 hex at capture; a stored
 * session is free-form, so agent and session text are not tamper material.
 * Pre-1.0.28 receipts are never failed for agent or session content.
 * The published share mask `[REDACTED]` is a legal stored host.
 */
export function linkMetaTamperReason(markdown: string): string | null {
  const header = parseSessionHeader(markdown);
  if (!isLinkEraVersion(header.Version)) return null;
  const meta = parseLinkMeta(markdown);
  try {
    if (meta.id) validateStoredId(meta.id);
    if (meta.parent) validateStoredParent(meta.parent);
    if (meta.host && meta.host !== REDACTED_HOST) validateLinkLabel('host', meta.host);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return `Invalid link metadata — receipt may have been tampered with (${msg})`;
  }
  return null;
}

/** Hash check plus header link-field validation. */
export function receiptIntegrity(markdown: string): {
  ok: boolean;
  reason: string;
  actual: string;
} {
  const hash = verifyMarkdown(markdown);
  if (!hash.ok) return { ok: false, reason: hash.reason, actual: hash.actual };
  const tamper = linkMetaTamperReason(markdown);
  if (tamper) return { ok: false, reason: tamper, actual: hash.actual };
  return { ok: true, reason: hash.reason, actual: hash.actual };
}

export interface LocalReceiptRef {
  path: string;
  /** Id line, or the embedded/actual sha256 when the receipt has no link id. */
  id: string;
  sha256: string | null;
  /** Aliases that resolve to this receipt (id, embedded hash, actual hash). */
  aliases: string[];
  meta: LinkMeta;
}

export interface ReadReceiptOptions {
  /** When set, stat and refuse before reading a larger file. */
  maxBytes?: number;
}

export function readLocalReceipt(
  filePath: string,
  opts?: ReadReceiptOptions,
): LocalReceiptRef | null {
  if (opts?.maxBytes !== undefined) {
    assertReadableSize(filePath, opts.maxBytes, `receipt ${filePath}`, '--max-receipt-bytes');
  }
  let text: string;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch (err) {
    if (opts?.maxBytes !== undefined && isByteLimit(err)) throw err;
    return null;
  }
  const meta = parseLinkMeta(text);
  const verified = verifyMarkdown(text);
  const embeddedRaw = extractEmbeddedHash(text);
  const embedded = embeddedRaw && SHA256_RE.test(embeddedRaw) ? embeddedRaw.toLowerCase() : null;
  // canonicalBody always hashes, so a file with no marker still has an id.
  const sha256 = verified.actual;
  const id = meta.id && LINK_ID_RE.test(meta.id) ? meta.id : sha256;
  const aliases = new Set<string>();
  aliases.add(id);
  if (meta.id && LINK_ID_RE.test(meta.id)) aliases.add(meta.id);
  if (embedded) aliases.add(embedded);
  if (SHA256_RE.test(sha256)) aliases.add(sha256);
  return { path: filePath, id, sha256, aliases: [...aliases], meta };
}

function isByteLimit(err: unknown): err is ByteLimitError {
  return Boolean(err && typeof err === 'object' && (err as { name?: string }).name === 'ByteLimitError');
}

export function indexLocalReceipts(
  cwd: string,
  opts?: ReadReceiptOptions,
): Map<string, LocalReceiptRef> {
  const map = new Map<string, LocalReceiptRef>();
  for (const filePath of listOutDirReceipts(cwd)) {
    const rec = readLocalReceipt(filePath, opts);
    if (!rec) continue;
    for (const alias of rec.aliases) {
      if (!map.has(alias)) map.set(alias, rec);
    }
  }
  return map;
}

/**
 * Normalize `--parent` / AGENT_RECEIPT_PARENT.
 * Accepts a link id, a 64-hex sha256, or a receipt path (no `..`).
 * A path or a hash of a local receipt is stored as that receipt's link id
 * when it has one, otherwise as its sha256. A hash or link id that is not
 * local is kept so a cross-host parent can be named (the session command
 * flags it as an orphan).
 */
export function resolveParentRef(cwd: string, raw: string): string {
  const value = raw.trim();
  if (!value) {
    throw new Error('--parent requires a receipt id, a path, or a sha256 hash.');
  }
  if (value.length > 4096) {
    throw new Error('--parent is too long (max 4096 characters).');
  }
  if (CONTROL_RE.test(value)) {
    throw new Error('--parent contains a control character.');
  }
  if (value.includes('..') || value.includes('\\')) {
    throw new Error(
      '--parent must not contain ".." or backslashes. Pass a receipt id, a sha256, or a path without traversal.',
    );
  }
  if (LINK_ID_RE.test(value)) return value;
  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    const hex = value.toLowerCase();
    const local = indexLocalReceipts(cwd).get(hex);
    if (local) return local.id;
    return hex;
  }
  const asPath = isAbsolute(value) ? value : resolve(cwd, value);
  if (!existsSync(asPath)) {
    throw new Error(
      `--parent ${JSON.stringify(value)} is not a receipt id (r- + 16 hex), a 64-hex sha256, or an existing receipt path.`,
    );
  }
  let st;
  try {
    st = statSync(asPath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`--parent path cannot be read (${value}): ${msg}`);
  }
  if (!st.isFile()) {
    throw new Error(`--parent path is not a file: ${value}`);
  }
  let text: string;
  try {
    text = readFileSync(asPath, 'utf8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`--parent path cannot be read (${value}): ${msg}`);
  }
  if (!isReceiptDocument(text)) {
    throw new Error(
      `--parent ${JSON.stringify(value)} is not a receipt file. Pass an r- id, a 64-hex sha256, or a path to an agent-receipt Markdown file.`,
    );
  }
  const local = readLocalReceipt(asPath);
  if (!local) {
    throw new Error(`--parent file has no receipt id or hash: ${value}`);
  }
  return local.id;
}

/**
 * Flags win over env. `--session new` generates an id and does not keep the
 * env session. `--link` with no session reuses the env session or generates one.
 * Agent from the flag or env is returned for the caller to prefer over its
 * built-in default. An absent agent does not invent one.
 */
export function resolveLink(cwd: string, input: ResolveLinkInput): ResolvedLink {
  const env = input.env ?? process.env;
  const sessionFlag = requireFlagValue('session', input.sessionFlagPresent, input.sessionFlag);
  const parentFlag = requireFlagValue('parent', input.parentFlagPresent, input.parentFlag);
  const agentFlag = requireFlagValue('agent', input.agentFlagPresent, input.agentFlag);
  const hostFlag = requireFlagValue('host', input.hostFlagPresent, input.hostFlag);

  let session: string | undefined;
  if (sessionFlag === 'new') {
    session = newSessionId();
  } else if (sessionFlag !== undefined) {
    session = validateLegacySession(sessionFlag);
  } else {
    const fromEnv = envValue(env, 'AGENT_RECEIPT_SESSION');
    if (fromEnv) session = validateLegacySession(fromEnv);
  }

  if (input.link && !session) {
    session = newSessionId();
  }

  let parent: string | undefined;
  if (parentFlag !== undefined) {
    parent = resolveParentRef(cwd, parentFlag);
  } else {
    const fromEnv = envValue(env, 'AGENT_RECEIPT_PARENT');
    if (fromEnv) parent = resolveParentRef(cwd, fromEnv);
  }

  let agent: string | undefined;
  if (agentFlag !== undefined) {
    agent = validateAgentLabel(agentFlag);
  } else {
    const fromEnv = envValue(env, 'AGENT_RECEIPT_AGENT');
    if (fromEnv) agent = validateAgentLabel(fromEnv);
  }

  let host: string | undefined;
  if (hostFlag !== undefined) {
    host = validateLinkLabel('host', hostFlag);
  } else {
    const fromEnv = envValue(env, 'AGENT_RECEIPT_HOST');
    if (fromEnv) host = validateLinkLabel('host', fromEnv);
  }

  const propagate = Boolean(input.link || input.sessionFlagPresent);
  const record = Boolean(session || parent || host || propagate);
  const id = record ? newLinkId() : undefined;

  if (parent && id && parent === id) {
    throw new Error('--parent resolved to this receipt. Pick a different parent.');
  }
  if (parent && !LINK_ID_RE.test(parent) && !SHA256_RE.test(parent)) {
    throw new Error(`--parent resolved to an unexpected value: ${parent}`);
  }

  return {
    session,
    parent,
    agent,
    host,
    id,
    propagate,
  };
}

export interface SessionNode {
  id: string;
  parent: string | null;
  agent: string | null;
  verified: boolean;
  exitCode: 0 | 2;
  orphan: boolean;
  cycle: boolean;
  /** cross-session-parent, parent-unverified, missing-session. */
  warnings: string[];
  timestamp: string | null;
  status: 'pass' | 'fail';
  path: string;
}

/**
 * Flat session rows in timestamp order, with orphan and cycle flags.
 * `local` maps every alias (link id and sha256) of every outDir receipt,
 * including receipts in other sessions. A parent missing from that map is
 * an orphan. A cycle is a loop inside this session only.
 */
export function buildSessionNodes(
  rows: Array<{
    id: string;
    parent: string | null;
    agent: string | null;
    verified: boolean;
    timestamp: string | null;
    path: string;
    aliases: string[];
  }>,
  local: Map<string, { id: string }>,
): SessionNode[] {
  const sorted = [...rows].sort((a, b) => {
    const ta = a.timestamp ?? '';
    const tb = b.timestamp ?? '';
    if (ta !== tb) return ta < tb ? -1 : 1;
    return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  });

  const byId = new Map(sorted.map((row) => [row.id, row]));
  const aliasToId = new Map<string, string>();
  for (const row of sorted) {
    aliasToId.set(row.id, row.id);
    for (const alias of row.aliases) aliasToId.set(alias, row.id);
  }

  const parentOf = (id: string): string | null => {
    const row = byId.get(id);
    if (!row?.parent) return null;
    return aliasToId.get(row.parent) ?? null;
  };

  const cycle = new Set<string>();
  const state = new Map<string, 0 | 1 | 2>();
  const dfs = (id: string, stack: string[]): void => {
    state.set(id, 1);
    stack.push(id);
    const parent = parentOf(id);
    if (parent && byId.has(parent)) {
      const seen = state.get(parent) ?? 0;
      if (seen === 1) {
        const at = stack.indexOf(parent);
        for (const node of stack.slice(at)) cycle.add(node);
      } else if (seen === 0) {
        dfs(parent, stack);
      }
    }
    stack.pop();
    state.set(id, 2);
  };
  for (const row of sorted) {
    if ((state.get(row.id) ?? 0) === 0) dfs(row.id, []);
  }

  return sorted.map((row) => {
    const orphan = Boolean(row.parent) && !local.has(row.parent as string);
    const verified = row.verified;
    return {
      id: row.id,
      parent: row.parent,
      agent: row.agent,
      verified,
      exitCode: verified ? 0 : 2,
      orphan,
      cycle: cycle.has(row.id),
      warnings: [],
      timestamp: row.timestamp,
      status: verified ? 'pass' : 'fail',
      path: row.path,
    };
  });
}

/** Count from a `## Tool calls` section, or null when that heading is absent. */
function toolCallCount(filePath: string): number | null {
  try {
    const text = readFileSync(filePath, 'utf8');
    const body = text.split(/^## Tool calls$/m)[1]?.split(/^## /m)[0];
    if (body === undefined) return null;
    const match = body.match(/^- \*\*Count\*\*: (\d+)\s*$/m);
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

/**
 * Parent/child lines for human `session` output. Cycle nodes stay at the root.
 * `aliasToId` maps a stored parent reference (link id or sha256) onto the
 * canonical id of a receipt in this session.
 */
export function formatSessionTree(
  session: string,
  nodes: SessionNode[],
  aliasToId?: Map<string, string>,
  provenance?: Map<string, { originalFingerprint: string | null; resignedBy: string | null; signedBy?: string | null }>,
): string {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const children = new Map<string, SessionNode[]>();
  const roots: SessionNode[] = [];
  const parentNode = (node: SessionNode): SessionNode | undefined => {
    if (!node.parent) return undefined;
    const canonical = aliasToId?.get(node.parent) ?? node.parent;
    return byId.get(canonical);
  };
  for (const node of nodes) {
    const parent = parentNode(node);
    const nest = parent && !node.cycle && !parent.cycle;
    if (nest && parent) {
      const list = children.get(parent.id) ?? [];
      list.push(node);
      children.set(parent.id, list);
    } else {
      roots.push(node);
    }
  }
  const lines: string[] = [
    `session ${session}`,
    `${nodes.length} receipt(s)`,
    '',
  ];
  const walk = (node: SessionNode, indent: string): void => {
    const bits = [
      node.id,
      node.status,
      `exit ${node.exitCode}`,
      node.agent ? `agent=${node.agent}` : 'agent=(none)',
      node.timestamp ?? '(no timestamp)',
      node.verified ? 'verified' : 'unverified',
    ];
    if (node.orphan) bits.push('orphan');
    if (node.cycle) bits.push('cycle');
    if (node.warnings.length) bits.push(`warnings=${node.warnings.join(',')}`);
    const claim = provenance?.get(node.id);
    if (claim && (claim.originalFingerprint || claim.resignedBy || claim.signedBy)) {
      bits.push(`originalFingerprint=${claim.originalFingerprint ?? 'null'}`);
      bits.push(`resignedBy=${claim.resignedBy ?? 'null'}`);
      if (claim.signedBy) bits.push(`signedBy=${claim.signedBy}`);
    }
    const tools = toolCallCount(node.path);
    if (tools !== null) bits.push(`tools=${tools}`);
    lines.push(`${indent}- ${bits.join('  ')}`);
    for (const child of children.get(node.id) ?? []) walk(child, `${indent}  `);
  };
  for (const root of roots) walk(root, '');
  return lines.join('\n');
}
