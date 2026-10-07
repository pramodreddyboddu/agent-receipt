/**
 * `export --format otlp` writes one OTLP/JSON trace file.
 * The receipt hash is checked before any write. Integrity failure
 * exits 2 and leaves no file. There is no network and no audit line.
 * Secrets in commands, args, host labels, and tool inputs are redacted.
 */
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { ByteLimitError, DEFAULT_MAX_RECEIPT_BYTES } from '../lib/byte-limit.js';
import { color } from '../lib/color.js';
import { auditLogPath, readAuditRawLines } from '../lib/audit.js';
import { receiptIntegrity } from '../lib/link.js';
import {
  parseReceiptFacts,
  renderOtlp,
  traceIdFor,
  type OtlpReceipt,
} from '../lib/otlp.js';
import { receiptsDir } from '../lib/receipt-index.js';
import {
  isRegularFile,
  locateSessionPackage,
  parseSessionManifest,
  SessionPackageUsageError,
} from '../lib/session-package.js';
import { inspectReceiptSignature } from '../lib/sign.js';
import { VERSION } from '../lib/version.js';
import { collectSession } from './session.js';
import { findLatestReceipt, resolveReceiptPath } from './show.js';

export class OtlpIntegrityError extends Error {
  readonly exitCode = 2 as const;
  constructor(message: string) {
    super(message);
    this.name = 'OtlpIntegrityError';
  }
}

export interface OtlpExportOptions {
  out?: string;
  session?: string;
}

interface Loaded {
  path: string;
  id: string;
  parent: string | null;
  cycle: boolean;
  sha256: string;
  timestamp: string | null;
  receipt: OtlpReceipt;
}

interface Source {
  loaded: Loaded[];
  /** Maps a stored parent id or sha onto the canonical receipt id. */
  aliasToId: Map<string, string>;
  fallbackDir: string;
  label: string;
  /** One receipt: `<file>.otlp.json` beside that file. A session uses `label`. */
  besideReceipt: boolean;
}

function fail(message: string): never {
  throw new Error(message);
}

function readReceipt(filePath: string): string {
  if (!isRegularFile(filePath)) fail(`receipt is not a regular file: ${filePath}`);
  const size = lstatSync(filePath).size;
  if (size > DEFAULT_MAX_RECEIPT_BYTES) {
    throw new ByteLimitError(
      `receipt is ${size} bytes, over the ${DEFAULT_MAX_RECEIPT_BYTES} byte cap: ${filePath}`,
    );
  }
  return readFileSync(filePath, 'utf8');
}

function resolveInside(root: string, name: string): string | null {
  if (!name || name.includes('\0') || name.includes('\\')) return null;
  if (isAbsolute(name)) return null;
  const abs = resolve(root, name);
  const rel = relative(root, abs);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) return null;
  return abs;
}

function companionFailedOn(mdPath: string): boolean | null {
  if (!/\.md$/i.test(mdPath)) return null;
  const jsonPath = mdPath.replace(/\.md$/i, '.json');
  if (!isRegularFile(jsonPath)) return null;
  try {
    if (lstatSync(jsonPath).size > 1024 * 1024) return null;
    const doc = JSON.parse(readFileSync(jsonPath, 'utf8')) as { failedOn?: unknown };
    return typeof doc.failedOn === 'boolean' ? doc.failedOn : null;
  } catch {
    return null;
  }
}

function auditFacts(
  cwd: string,
  sha256: string,
): { exitCode: number | null; failedOn: boolean | null; position: number | null } {
  const empty = { exitCode: null as number | null, failedOn: null as boolean | null, position: null as number | null };
  try {
    if (!existsSync(auditLogPath(cwd))) return empty;
    const lines = readAuditRawLines(cwd);
    let exitCode: number | null = null;
    let failedOn: boolean | null = null;
    let position: number | null = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].endsWith('\r') ? lines[i].slice(0, -1) : lines[i];
      try {
        const parsed = JSON.parse(line) as { sha256?: unknown; exitCode?: unknown; failedOn?: unknown };
        if (!parsed || parsed.sha256 !== sha256) continue;
        position = i + 1;
        if (typeof parsed.exitCode === 'number') exitCode = parsed.exitCode;
        if (typeof parsed.failedOn === 'boolean') failedOn = parsed.failedOn;
      } catch {
        // A broken audit line is not a match and does not fail the export.
      }
    }
    return { exitCode, failedOn, position };
  } catch {
    return empty;
  }
}

function loadOne(cwd: string, filePath: string, id: string, parent: string | null, cycle: boolean): Loaded {
  const markdown = readReceipt(filePath);
  const integrity = receiptIntegrity(markdown);
  if (!integrity.ok) {
    throw new OtlpIntegrityError(`receipt failed integrity: ${integrity.reason}`);
  }
  const facts = parseReceiptFacts(markdown);
  const audit = auditFacts(cwd, integrity.actual);
  const signature = inspectReceiptSignature(filePath, integrity.actual);
  return {
    path: filePath,
    id,
    parent,
    cycle,
    sha256: integrity.actual,
    timestamp: facts.timestamp,
    receipt: {
      ...facts,
      sha256: integrity.actual,
      failedOn: audit.failedOn ?? companionFailedOn(filePath),
      exitCode: audit.exitCode,
      signed: signature.present === true && signature.ok === true,
      hashChainPosition: audit.position,
    },
  };
}

function looksLikeSessionPackage(cwd: string, pathArg: string): boolean {
  const located = locateSessionPackage(cwd, pathArg);
  if (located.inputKind === 'manifest') return true;
  if (basename(resolve(cwd, pathArg)).endsWith('.session')) return true;
  return located.manifestExists && located.inputKind === 'directory';
}

function sessionPackageSource(cwd: string, pathArg: string): Source {
  const located = locateSessionPackage(cwd, pathArg);
  if (!located.manifestExists) fail(`session package not found: ${pathArg}`);
  let manifest;
  try {
    manifest = parseSessionManifest(JSON.parse(readFileSync(located.manifestPath, 'utf8')));
  } catch (err) {
    if (err instanceof SessionPackageUsageError) fail(err.message);
    const detail = err instanceof Error ? err.message : String(err);
    fail(`session package manifest is unreadable (${detail})`);
  }
  const loaded: Loaded[] = [];
  for (const entry of manifest.receipts) {
    const abs = resolveInside(located.packageDir, entry.path);
    if (!abs) fail(`session package receipt is missing: ${entry.path}`);
    loaded.push(loadOne(cwd, abs, entry.id, entry.parent, entry.cycle));
  }
  if (!loaded.length) fail('session package has no receipts');
  loaded.sort((a, b) => {
    const ta = a.timestamp ?? '';
    const tb = b.timestamp ?? '';
    if (ta !== tb) return ta < tb ? -1 : 1;
    return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  });
  const aliasToId = new Map<string, string>();
  for (const row of loaded) {
    aliasToId.set(row.id, row.id);
    aliasToId.set(row.sha256, row.id);
  }
  const base = basename(located.packageDir).replace(/\.session$/i, '') || basename(located.packageDir);
  return {
    loaded,
    aliasToId,
    fallbackDir: dirname(located.packageDir),
    label: base,
    besideReceipt: false,
  };
}

function localSessionSource(cwd: string, session: string): Source {
  const collected = collectSession(cwd, session);
  if (collected.empty) fail(collected.reason || `no receipts in session ${session}`);
  const loaded: Loaded[] = [];
  for (const node of collected.nodes) {
    loaded.push(loadOne(cwd, node.path, node.id, node.parent, node.cycle));
  }
  return {
    loaded,
    aliasToId: collected.aliasToId,
    fallbackDir: dirname(receiptsDir(cwd)),
    label: collected.session,
    besideReceipt: false,
  };
}

function oneSource(cwd: string, pathArg: string | undefined): Source {
  const filePath =
    !pathArg || pathArg === 'last' ? findLatestReceipt(cwd) ?? resolveReceiptPath(cwd) : resolveReceiptPath(cwd, pathArg);
  const loaded = loadOne(cwd, filePath, 'receipt', null, false);
  const aliasToId = new Map<string, string>([[loaded.id, loaded.id]]);
  return {
    loaded: [loaded],
    aliasToId,
    fallbackDir: dirname(resolve(cwd, filePath)),
    label: basename(filePath).replace(/\.md$/i, ''),
    besideReceipt: true,
  };
}

function forest(source: Source): OtlpReceipt[] {
  const byId = new Map(source.loaded.map((row) => [row.id, row]));
  const children = new Map<string, Loaded[]>();
  const roots: Loaded[] = [];
  for (const row of source.loaded) {
    const parentId = row.parent ? source.aliasToId.get(row.parent) ?? null : null;
    const parent = parentId ? byId.get(parentId) : undefined;
    if (parent && !row.cycle && !parent.cycle) {
      const list = children.get(parent.id) ?? [];
      list.push(row);
      children.set(parent.id, list);
    } else {
      roots.push(row);
    }
  }
  const build = (row: Loaded): OtlpReceipt => ({
    ...row.receipt,
    children: (children.get(row.id) ?? []).map(build),
  });
  return roots.map(build);
}

function safeStem(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
  return cleaned || 'trace';
}

function outputPath(cwd: string, out: string | undefined, fallbackName: string, fallbackDir: string): string {
  if (!out) return join(fallbackDir, fallbackName);
  const wantsDir = /[/\\]$/.test(out);
  const resolved = resolve(cwd, out);
  if (wantsDir) return join(resolved, fallbackName);
  if (existsSync(resolved)) {
    const st = lstatSync(resolved);
    if (st.isSymbolicLink()) fail(`refusing to write through a symlink: ${resolved}`);
    if (st.isDirectory()) return join(resolved, fallbackName);
  }
  return resolved;
}

function writeTrace(cwd: string, outPath: string, body: string): void {
  const abs = resolve(cwd, outPath);
  const parent = dirname(abs);
  mkdirSync(parent, { recursive: true });
  if (existsSync(abs) && lstatSync(abs).isSymbolicLink()) {
    fail(`refusing to replace a symlink: ${abs}`);
  }
  const tmp = join(parent, `.${basename(abs)}.${process.pid}.tmp`);
  try {
    writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o644 });
    renameSync(tmp, abs);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // The rename error is the one to report.
    }
    const detail = err instanceof Error ? err.message : String(err);
    fail(`could not write ${abs} (${detail})`);
  }
}

function defaultName(label: string): string {
  return `${safeStem(label)}.otlp.json`;
}

/**
 * Write one OTLP/JSON file for a receipt, `last`, a session id, or a
 * `*.session` package. Exit 2 when integrity fails. Nothing is written
 * in that case, and the audit log is not appended.
 */
export function cmdOtlpExport(cwd: string, pathArg: string | undefined, opts: OtlpExportOptions = {}): number {
  try {
    const source = opts.session
      ? localSessionSource(cwd, opts.session)
      : pathArg && pathArg !== 'last' && looksLikeSessionPackage(cwd, pathArg)
        ? sessionPackageSource(cwd, pathArg)
        : oneSource(cwd, pathArg);
    const roots = forest(source);
    const body = renderOtlp(roots, VERSION);
    const fallbackName = source.besideReceipt
      ? `${basename(source.loaded[0].path).replace(/\.md$/i, '')}.otlp.json`
      : defaultName(source.label);
    const out = outputPath(cwd, opts.out, fallbackName, source.fallbackDir);
    const dest = resolve(cwd, out);
    for (const row of source.loaded) {
      if (dest === resolve(cwd, row.path)) fail('refusing to write the trace over the receipt');
    }
    writeTrace(cwd, out, body);
    const traceId = traceIdFor(roots[0].sha256);
    let spans = 0;
    const count = (receipt: OtlpReceipt): void => {
      spans += 1 + receipt.activities.length;
      for (const child of receipt.children) count(child);
    };
    for (const root of roots) count(root);
    console.log(color.green('wrote') + ` ${dest}`);
    console.log(color.dim(`spans ${spans}`));
    console.log(color.dim(`trace ${traceId}`));
    return 0;
  } catch (err) {
    if (err instanceof OtlpIntegrityError || err instanceof ByteLimitError) {
      console.error(color.red('FAILED') + ` ${err.message}`);
      return 2;
    }
    throw err;
  }
}
