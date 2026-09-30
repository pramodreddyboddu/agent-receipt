/**
 * Multi-agent receipt linking (thin slice).
 *
 * A session id groups related runs. A parent reference is the link id
 * (`r-` + 16 hex) or the sha256 of the run that spawned this one.
 * Agent and host are short labels. Host is omitted unless the user opts in.
 *
 * These fields are written into the hashed Markdown body. Old receipts that
 * omit them verify unchanged. Nothing is written when no link flag and no
 * AGENT_RECEIPT_SESSION / PARENT / AGENT / HOST env is set.
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
import { isAbsolute, join, resolve } from 'node:path';
import { loadConfig } from './config.js';
import { extractEmbeddedHash, verifyMarkdown } from './hash.js';
import {
  isInsideSharePackage,
  isProveOnePagerName,
  isSharePackageDirName,
} from './receipt.js';

/** 1–64 of [A-Za-z0-9._:-], must start alphanumeric, no ".." and no slashes. */
export const LINK_LABEL_MAX = 64;

const LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const LINK_ID_RE = /^r-[0-9a-f]{16}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

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

/** Receipt .md files under outDir, newest last is not required. Skips prove pages and share packages. */
export function listOutDirReceipts(cwd: string): string[] {
  const cfg = loadConfig(cwd);
  const dir = cfg.outDir.startsWith('/') ? cfg.outDir : join(cwd, cfg.outDir);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => !isSharePackageDirName(f))
    .filter((f) => f.endsWith('.md') && !isProveOnePagerName(f))
    .map((f) => join(dir, f))
    .filter((p) => !isInsideSharePackage(p))
    .filter((p) => {
      try {
        return statSync(p).isFile();
      } catch {
        return false;
      }
    });
}

export function parseLinkMeta(markdown: string): LinkMeta {
  const field = (label: string): string | null => {
    const re = new RegExp(`^- \\*\\*${label}\\*\\*:\\s*(.+)$`, 'm');
    const m = markdown.match(re);
    if (!m) return null;
    const value = m[1].replace(/^`|`$/g, '').trim();
    return value || null;
  };
  return {
    id: field('Id'),
    session: field('Session'),
    parent: field('Parent'),
    agent: field('Agent'),
    host: field('Host'),
    timestamp: field('Timestamp'),
  };
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

export function readLocalReceipt(filePath: string): LocalReceiptRef | null {
  let text: string;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
  const meta = parseLinkMeta(text);
  const embedded = extractEmbeddedHash(text);
  const actual = verifyMarkdown(text).actual || null;
  const sha256 = embedded ?? actual;
  const id = meta.id && LINK_ID_RE.test(meta.id) ? meta.id : sha256;
  if (!id) return null;
  const aliases = new Set<string>();
  aliases.add(id);
  if (meta.id) aliases.add(meta.id);
  if (embedded) aliases.add(embedded);
  if (actual) aliases.add(actual);
  return { path: filePath, id, sha256, aliases: [...aliases], meta };
}

export function indexLocalReceipts(cwd: string): Map<string, LocalReceiptRef> {
  const map = new Map<string, LocalReceiptRef>();
  for (const filePath of listOutDirReceipts(cwd)) {
    const rec = readLocalReceipt(filePath);
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
  if (value.includes('\0')) {
    throw new Error('--parent contains a null byte.');
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
    session = validateLinkLabel('session', sessionFlag);
  } else {
    const fromEnv = envValue(env, 'AGENT_RECEIPT_SESSION');
    if (fromEnv) session = validateLinkLabel('session', fromEnv);
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
    agent = validateLinkLabel('agent', agentFlag);
  } else {
    const fromEnv = envValue(env, 'AGENT_RECEIPT_AGENT');
    if (fromEnv) agent = validateLinkLabel('agent', fromEnv);
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
      timestamp: row.timestamp,
      status: verified ? 'pass' : 'fail',
      path: row.path,
    };
  });
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
    lines.push(`${indent}- ${bits.join('  ')}`);
    for (const child of children.get(node.id) ?? []) walk(child, `${indent}  `);
  };
  for (const root of roots) walk(root, '');
  return lines.join('\n');
}
