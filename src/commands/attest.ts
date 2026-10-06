/**
 * `attest` writes an in-toto Statement v1 inside a DSSE envelope.
 * One envelope per line (`.intoto.jsonl`). Narrative fields are redacted
 * before they enter the predicate. The signature is Ed25519 over the DSSE
 * PAE when a local key exists. Missing keys write an unsigned envelope and
 * warn. The private key is never written.
 *
 * `attest --verify` checks the signature, each subject digest against the
 * file on disk, and the hash-chain head against the receipt canonical sha256.
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
import { DEFAULT_MAX_RECEIPT_BYTES } from '../lib/byte-limit.js';
import { color } from '../lib/color.js';
import {
  DsseError,
  envelopeJson,
  parseEnvelope,
  signEnvelope,
  unsignedEnvelope,
  verifyEnvelopeSignatures,
  type DsseSignature,
} from '../lib/dsse.js';
import { sha256Hex } from '../lib/hash.js';
import {
  buildStatement,
  parseStatement,
  statementBytes,
  PREDICATE_RUN,
  PREDICATE_SLSA,
  type FileFact,
  type PolicyHit,
  type PredicateKind,
  type RunFacts,
  type Subject,
  type ToolCallFact,
} from '../lib/intoto.js';
import { listOutDirReceipts, parseSessionHeader, receiptIntegrity } from '../lib/link.js';
import { redactMarkdownBody, redactSecretsInText } from '../lib/redact.js';
import { redactTranscriptText } from '../lib/adapters/redact-transcript.js';
import {
  auditLogPath,
  loadAuditEvents,
  readAuditRawLines,
  verifyAuditChain,
} from '../lib/audit.js';
import { receiptsDir } from '../lib/receipt-index.js';
import { sha256FileBytes } from '../lib/share-package.js';
import { loadKeys, type LoadedKeys } from '../lib/sign.js';
import {
  isRegularFile,
  locateSessionPackage,
  parseSessionManifest,
  SessionPackageUsageError,
} from '../lib/session-package.js';
import {
  isFingerprintTrusted,
  loadTrustedFingerprints,
  trustStoreActive,
} from '../lib/trust.js';
import { VERSION } from '../lib/version.js';
import { findLatestReceipt, resolveReceiptPath } from './show.js';

const MAX_ATTEST_BYTES = 32 * 1024 * 1024;
const UNSIGNED_MISSING =
  'warning: attestation is unsigned (no local Ed25519 keys). Run `agent-receipt keygen`. The envelope was still written. Private keys are never included.';
const UNSIGNED_FLAG =
  'warning: attestation is unsigned (--no-sign). The envelope was still written. Private keys are never included.';
const TRUST_NOTE =
  'note: trust store is empty; DSSE signature accepted but not allowlisted. Run `agent-receipt trust add --self`.';

export class AttestUsageError extends Error {
  readonly exitCode = 1 as const;
  constructor(message: string) {
    super(message);
    this.name = 'AttestUsageError';
  }
}

/** Integrity, signature, digest, or hash-chain failure. Nothing was written. */
export class AttestFailError extends Error {
  readonly exitCode = 2 as const;
  constructor(message: string) {
    super(message);
    this.name = 'AttestFailError';
  }
}

export interface AttestOptions {
  out?: string;
  json?: boolean;
  predicate?: PredicateKind;
  session?: string;
  noSign?: boolean;
  trustedKeys?: string[];
}

export interface AttestVerifyOptions {
  json?: boolean;
  trustedKeys?: string[];
}

interface LineResult {
  line: number;
  ok: boolean;
  signed: boolean;
  fingerprint: string | null;
  trusted: boolean | null;
  predicateType: string | null;
  subjects: number;
  subjectsOk: boolean;
  hashChainOk: boolean;
  reason: string | null;
}

function fail(message: string): never {
  throw new AttestUsageError(message);
}

function displayName(cwd: string, filePath: string): string | null {
  const rel = relative(cwd, filePath).replace(/\\/g, '/');
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) return null;
  return rel;
}

function resolveInside(cwd: string, name: string): string | null {
  if (!name || name.includes('\0') || name.includes('\\')) return null;
  if (isAbsolute(name)) return null;
  const abs = resolve(cwd, name);
  const rel = relative(cwd, abs);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) return null;
  return abs;
}

function clip(value: string | null, max = 2000): string | null {
  if (!value) return null;
  const flat = value.replace(/[\r\n\u2028\u2029\t]+/g, ' ').replace(/ {2,}/g, ' ').trim();
  if (!flat) return null;
  if (flat.length <= max) return flat;
  return `${flat.slice(0, max - 1)}…`;
}

function narrative(value: string | null): string | null {
  if (!value) return null;
  return clip(redactSecretsInText(value));
}

function sectionAfter(text: string, heading: string): string {
  const escaped = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`^## ${escaped}\\n`, 'm').exec(text);
  if (!match) return '';
  const rest = text.slice(match.index + match[0].length);
  const next = rest.search(/^## /m);
  return next === -1 ? rest : rest.slice(0, next);
}

function fieldsOf(text: string): Record<string, string> {
  const out: Record<string, string> = { ...parseSessionHeader(text) };
  for (const label of ['Timestamp', 'Branch', 'HEAD', 'Agent', 'Session', 'Parent', 'Id', 'Message']) {
    if (out[label]) continue;
    const match = text.match(new RegExp(`^- \\*\\*${label}\\*\\*:([^\\n]*)$`, 'm'));
    if (!match) continue;
    const value = match[1].replace(/^`|`$/g, '').trim();
    if (value) out[label] = value;
  }
  return out;
}

function parseFiles(section: string): Array<{ status: string; name: string }> {
  const files: Array<{ status: string; name: string }> = [];
  for (const line of section.split('\n')) {
    const match = line.match(/^\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|/);
    if (!match) continue;
    const status = match[1].trim();
    if (!status || status === 'Status' || /^-+$/.test(status)) continue;
    files.push({ status, name: match[2] });
  }
  return files;
}

function parseTools(section: string): { toolCalls: ToolCallFact[]; commands: string[] } {
  const toolCalls: ToolCallFact[] = [];
  const commands: string[] = [];
  for (const line of section.split('\n')) {
    const match = line.match(/^- `([^`]+)`(.*)$/);
    if (!match) continue;
    const tool = clip(redactTranscriptText(match[1]), 80) || 'tool';
    const rest = match[2];
    const exitMatch = rest.match(/— exit (-?\d+)/);
    const argMatch = rest.match(/— `([^`]*)`/);
    const exitStatus = exitMatch ? Number(exitMatch[1]) : null;
    const arg = argMatch ? clip(redactTranscriptText(argMatch[1])) : null;
    toolCalls.push({ tool, exitStatus, argsSummary: arg });
    if (arg && !arg.startsWith('{') && !arg.startsWith('[')) commands.push(arg);
  }
  return { toolCalls, commands };
}

function parsePolicy(section: string): PolicyHit[] {
  const hits: PolicyHit[] = [];
  for (const line of section.split('\n')) {
    const match = line.match(/^\|\s*(\w+)\s*\|\s*`([^`]+)`\s*\|\s*(.*?)\s*\|$/);
    if (!match || match[1] === 'Sev') continue;
    hits.push({
      severity: match[1].toLowerCase(),
      code: match[2],
      detail: narrative(match[3]) || '',
    });
  }
  return hits;
}

function auditHead(cwd: string): string | null {
  if (!existsSync(auditLogPath(cwd))) return null;
  const chain = verifyAuditChain(cwd);
  if (!chain.ok) return null;
  const lines = readAuditRawLines(cwd);
  if (!lines.length) return null;
  const last = lines[lines.length - 1];
  const stripped = last.endsWith('\r') ? last.slice(0, -1) : last;
  return sha256Hex(`${stripped}\n`);
}

function auditExit(cwd: string, sha256: string): { exitCode: number | null; failedOn: boolean | null } {
  try {
    let exitCode: number | null = null;
    let failedOn: boolean | null = null;
    for (const event of loadAuditEvents(cwd)) {
      if (event.sha256 !== sha256) continue;
      if (typeof event.exitCode === 'number') exitCode = event.exitCode;
      if (typeof event.failedOn === 'boolean') failedOn = event.failedOn;
    }
    return { exitCode, failedOn };
  } catch {
    return { exitCode: null, failedOn: null };
  }
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

function readReceipt(filePath: string): string {
  if (!isRegularFile(filePath)) {
    fail(`receipt is not a regular file: ${filePath}`);
  }
  const size = lstatSync(filePath).size;
  if (size > DEFAULT_MAX_RECEIPT_BYTES) {
    fail(`receipt is ${size} bytes, over the ${DEFAULT_MAX_RECEIPT_BYTES} byte cap: ${filePath}`);
  }
  return readFileSync(filePath, 'utf8');
}

function hashRegularFile(filePath: string): string | null {
  if (!isRegularFile(filePath)) return null;
  try {
    if (lstatSync(filePath).size > DEFAULT_MAX_RECEIPT_BYTES) return null;
  } catch {
    return null;
  }
  return sha256FileBytes(filePath);
}

interface BuiltRun {
  body: Buffer;
  subjects: number;
  receiptName: string;
}

function buildRun(cwd: string, receiptPath: string, kind: PredicateKind): BuiltRun {
  const abs = resolve(cwd, receiptPath);
  const receiptName = displayName(cwd, abs);
  if (!receiptName) fail(`receipt must stay inside the working directory: ${abs}`);
  const original = readReceipt(abs);
  const integrity = receiptIntegrity(original);
  if (!integrity.ok) {
    throw new AttestFailError(`receipt failed integrity: ${integrity.reason}`);
  }
  const redacted = redactMarkdownBody(original, { maskHost: true });
  const fields = fieldsOf(redacted);
  // File names stay as written so subject paths still resolve. Narrative
  // sections are read from the redacted body, then redacted again.
  const files = parseFiles(sectionAfter(original, 'Files changed'));
  const tools = parseTools(sectionAfter(redacted, 'Tool calls'));
  const policyHits = parsePolicy(sectionAfter(redacted, 'Risk findings'));
  const fromAudit = auditExit(cwd, integrity.actual);
  const failedOn = fromAudit.failedOn ?? companionFailedOn(abs);

  const subjects: Subject[] = [];
  const fileFacts: FileFact[] = [];
  const seen = new Set<string>();
  const addSubject = (name: string, filePath: string): string | null => {
    if (seen.has(name)) {
      const existing = subjects.find((subject) => subject.name === name);
      return existing ? existing.digest.sha256 : null;
    }
    const digest = hashRegularFile(filePath);
    if (!digest) return null;
    seen.add(name);
    subjects.push({ name, digest: { sha256: digest } });
    return digest;
  };

  const receiptDigest = addSubject(receiptName, abs);
  if (!receiptDigest) fail(`receipt could not be hashed: ${receiptName}`);

  for (const file of files) {
    const fileAbs = resolveInside(cwd, file.name);
    const digest = fileAbs ? hashRegularFile(fileAbs) : null;
    if (fileAbs && digest) addSubject(displayName(cwd, fileAbs) || file.name, fileAbs);
    fileFacts.push({
      name: file.name,
      status: file.status,
      digest,
    });
  }

  const facts: RunFacts = {
    agent: narrative(fields.Agent ?? null),
    session: narrative(fields.Session ?? null),
    parent: narrative(fields.Parent ?? null),
    id: narrative(fields.Id ?? null),
    timestamp: narrative(fields.Timestamp ?? null),
    message: narrative(fields.Message ?? null),
    commands: tools.commands,
    toolCalls: tools.toolCalls,
    policyHits,
    exitCode: fromAudit.exitCode,
    failedOn,
    hashChainHead: integrity.actual,
    auditChainHead: auditHead(cwd),
    receiptName,
    branch: narrative(fields.Branch ?? null),
    head: fields.HEAD && /^[0-9a-f]{7,64}$/i.test(fields.HEAD) ? fields.HEAD.toLowerCase() : null,
    files: fileFacts,
    cliVersion: VERSION,
  };
  const statement = buildStatement(subjects, facts, kind);
  return { body: statementBytes(statement), subjects: subjects.length, receiptName };
}

function tryKeys(cwd: string): { keys: LoadedKeys | null; missing: boolean } {
  try {
    return { keys: loadKeys(cwd), missing: false };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('not found')) return { keys: null, missing: true };
    fail(message);
  }
}

function safeStem(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
  return cleaned || 'attest';
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

function writeLines(cwd: string, outPath: string, lines: string[]): void {
  if (lines.some((line) => line.includes('PRIVATE KEY'))) {
    fail('refusing to write an attestation that contains a private key');
  }
  const abs = resolve(cwd, outPath);
  const parent = dirname(abs);
  mkdirSync(parent, { recursive: true });
  if (existsSync(abs) && lstatSync(abs).isSymbolicLink()) {
    fail(`refusing to replace a symlink: ${abs}`);
  }
  const tmp = join(parent, `.${basename(abs)}.${process.pid}.tmp`);
  writeFileSync(tmp, `${lines.join('\n')}\n`, { mode: 0o644 });
  try {
    renameSync(tmp, abs);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* the failed rename already reports the destination */
    }
    const detail = err instanceof Error ? err.message : String(err);
    fail(`could not write ${abs} (${detail})`);
  }
}

interface ReceiptSource {
  paths: string[];
  /** Directory the default `<label>.intoto.jsonl` is written into. */
  fallbackDir: string;
  label: string;
}

function receiptSource(cwd: string, pathArg: string | undefined, session: string | undefined): ReceiptSource {
  if (session) {
    const want = session.trim();
    if (!want) fail('--session requires an id');
    const found: string[] = [];
    for (const filePath of listOutDirReceipts(cwd)) {
      const fields = fieldsOf(readReceipt(filePath));
      if (fields.Session === want) found.push(filePath);
    }
    if (!found.length) fail(`no local receipts for session ${JSON.stringify(want)}`);
    return {
      paths: found,
      fallbackDir: dirname(receiptsDir(cwd)),
      label: want,
    };
  }
  if (pathArg && pathArg !== 'last') {
    const located = locateSessionPackage(cwd, pathArg);
    if (located.manifestExists && (located.inputKind === 'directory' || located.inputKind === 'manifest')) {
      let manifest;
      try {
        manifest = parseSessionManifest(JSON.parse(readFileSync(located.manifestPath, 'utf8')));
      } catch (err) {
        if (err instanceof SessionPackageUsageError) fail(err.message);
        const detail = err instanceof Error ? err.message : String(err);
        fail(`session package manifest is unreadable (${detail})`);
      }
      const paths: string[] = [];
      for (const entry of manifest.receipts) {
        const abs = resolveInside(located.packageDir, entry.path);
        if (!abs || !isRegularFile(abs)) fail(`session package receipt is missing: ${entry.path}`);
        paths.push(abs);
      }
      if (!paths.length) fail('session package has no receipts');
      const base = basename(located.packageDir).replace(/\.session$/i, '') || basename(located.packageDir);
      return { paths, fallbackDir: dirname(located.packageDir), label: base };
    }
    const one = resolveReceiptPath(cwd, pathArg);
    return {
      paths: [one],
      fallbackDir: dirname(resolve(cwd, one)),
      label: basename(one).replace(/\.md$/i, ''),
    };
  }
  const latest = findLatestReceipt(cwd);
  if (!latest) {
    fail('No receipt found under the configured outDir. Run `agent-receipt capture` first, or pass a path.');
  }
  return {
    paths: [latest],
    fallbackDir: dirname(resolve(cwd, latest)),
    label: basename(latest).replace(/\.md$/i, ''),
  };
}

function printCreate(report: Record<string, unknown>, json: boolean | undefined): void {
  if (json) {
    console.log(JSON.stringify(report));
    return;
  }
  if (report.ok !== true) {
    console.error(color.red('FAILED') + ` ${report.reason}`);
    return;
  }
  console.log(color.green('wrote') + ` ${report.path}`);
  console.log(color.dim(`predicate ${report.predicateType}`));
  console.log(color.dim(`envelopes ${report.envelopes}`));
  console.log(color.dim(`subjects ${report.subjects}`));
  if (report.signed === true) {
    console.log(color.dim(`signed ${report.fingerprint}`));
  } else {
    console.log(color.yellow('unsigned'));
  }
}

export function printAttestError(message: string, command: 'attest' | 'attest-verify' = 'attest'): void {
  console.log(
    JSON.stringify({
      ok: false,
      command,
      version: VERSION,
      exitCode: 1,
      path: null,
      signed: false,
      redacted: true,
      reason: message,
    }),
  );
}

/**
 * Write `.intoto.jsonl` for one receipt, the latest receipt, a session
 * package, or every local receipt in `--session`. Exit 2 when a receipt
 * fails integrity (nothing is written). Exit 0 when the file is written,
 * including the unsigned path.
 */
export function cmdAttest(
  cwd: string,
  pathArg: string | undefined,
  opts: AttestOptions = {},
): number {
  const kind: PredicateKind = opts.predicate === 'slsa' ? 'slsa' : 'run';
  const predicateType = kind === 'slsa' ? PREDICATE_SLSA : PREDICATE_RUN;
  try {
    const source = receiptSource(cwd, pathArg, opts.session);
    const loaded = opts.noSign ? { keys: null, missing: true } : tryKeys(cwd);
    const warning = opts.noSign ? UNSIGNED_FLAG : loaded.missing ? UNSIGNED_MISSING : null;
    const lines: string[] = [];
    let subjects = 0;
    for (const receiptPath of source.paths) {
      const built = buildRun(cwd, receiptPath, kind);
      subjects += built.subjects;
      const envelope = loaded.keys
        ? signEnvelope(built.body, loaded.keys)
        : unsignedEnvelope(built.body);
      lines.push(envelopeJson(envelope));
    }
    const out = outputPath(cwd, opts.out, `${safeStem(source.label)}.intoto.jsonl`, source.fallbackDir);
    for (const receiptPath of source.paths) {
      if (resolve(cwd, out) === resolve(cwd, receiptPath)) {
        fail('refusing to write the attestation over the receipt');
      }
    }
    writeLines(cwd, out, lines);
    if (warning) console.error(color.yellow(warning));
    printCreate(
      {
        ok: true,
        command: 'attest',
        version: VERSION,
        exitCode: 0,
        path: resolve(cwd, out),
        signed: Boolean(loaded.keys),
        fingerprint: loaded.keys ? loaded.keys.fingerprint : null,
        predicateType,
        envelopes: lines.length,
        subjects,
        redacted: true,
        warning,
        reason: null,
      },
      opts.json,
    );
    return 0;
  } catch (err) {
    if (err instanceof AttestFailError || err instanceof AttestUsageError) {
      printCreate(
        {
          ok: false,
          command: 'attest',
          version: VERSION,
          exitCode: err.exitCode,
          path: null,
          signed: false,
          fingerprint: null,
          predicateType,
          envelopes: 0,
          subjects: 0,
          redacted: true,
          warning: null,
          reason: err.message,
        },
        opts.json,
      );
      return err.exitCode;
    }
    throw err;
  }
}

function publicKeyFor(
  cwd: string,
  sig: DsseSignature,
  local: LoadedKeys | null,
): string | null {
  if (sig.publicKey) return sig.publicKey;
  if (local && (!sig.keyid || local.fingerprint === sig.keyid.toLowerCase())) return local.publicKeyPem;
  return null;
}

function verifyOne(
  cwd: string,
  value: unknown,
  line: number,
  local: LoadedKeys | null,
  trustedKeys: string[] | undefined,
): LineResult {
  let parsed;
  try {
    parsed = parseEnvelope(value);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const exitCode = err instanceof DsseError ? err.exitCode : 1;
    return {
      line,
      ok: false,
      signed: false,
      fingerprint: null,
      trusted: null,
      predicateType: null,
      subjects: 0,
      subjectsOk: false,
      hashChainOk: false,
      reason: exitCode === 1 ? message : message,
    };
  }
  const sig = verifyEnvelopeSignatures(parsed.envelope, parsed.body, (item) =>
    publicKeyFor(cwd, item, local),
  );
  if (!sig.ok || !sig.fingerprint) {
    return {
      line,
      ok: false,
      signed: false,
      fingerprint: sig.fingerprint,
      trusted: null,
      predicateType: null,
      subjects: 0,
      subjectsOk: false,
      hashChainOk: false,
      reason: sig.reason,
    };
  }
  const store = loadTrustedFingerprints(cwd, { extra: trustedKeys });
  let trusted: boolean | null = null;
  if (store.reason || !isFingerprintTrusted(sig.fingerprint, store)) {
    const reason = store.reason || `fingerprint not trusted: ${sig.fingerprint}`;
    if (store.reason || trustStoreActive(store)) {
      return {
        line,
        ok: false,
        signed: true,
        fingerprint: sig.fingerprint,
        trusted: false,
        predicateType: null,
        subjects: 0,
        subjectsOk: false,
        hashChainOk: false,
        reason,
      };
    }
  } else if (trustStoreActive(store)) {
    trusted = true;
  }
  const statement = parseStatement(parsed.body);
  if (!statement.ok) {
    return {
      line,
      ok: false,
      signed: true,
      fingerprint: sig.fingerprint,
      trusted,
      predicateType: null,
      subjects: 0,
      subjectsOk: false,
      hashChainOk: false,
      reason: statement.reason,
    };
  }
  const reasons: string[] = [];
  let subjectsOk = true;
  for (const subject of statement.value.subjects) {
    const abs = resolveInside(cwd, subject.name);
    if (!abs || !isRegularFile(abs)) {
      subjectsOk = false;
      reasons.push(`subject missing: ${subject.name}`);
      continue;
    }
    let actual = '';
    try {
      if (lstatSync(abs).size > DEFAULT_MAX_RECEIPT_BYTES) {
        subjectsOk = false;
        reasons.push(`subject ${subject.name} is over the byte cap`);
        continue;
      }
      actual = sha256FileBytes(abs);
    } catch {
      subjectsOk = false;
      reasons.push(`subject missing: ${subject.name}`);
      continue;
    }
    if (actual !== subject.digest.sha256) {
      subjectsOk = false;
      reasons.push(`subject ${subject.name} digest mismatch`);
    }
  }
  let hashChainOk = false;
  const receiptAbs = resolveInside(cwd, statement.value.receiptName);
  if (!receiptAbs || !isRegularFile(receiptAbs)) {
    reasons.push(`receipt subject missing: ${statement.value.receiptName}`);
  } else {
    const text = readFileSync(receiptAbs, 'utf8');
    const integrity = receiptIntegrity(text);
    if (!integrity.ok) {
      reasons.push(`receipt failed integrity: ${integrity.reason}`);
    } else if (integrity.actual !== statement.value.hashChainHead) {
      reasons.push('hash-chain head does not match receipt');
    } else {
      hashChainOk = true;
    }
  }
  const ok = subjectsOk && hashChainOk && reasons.length === 0;
  return {
    line,
    ok,
    signed: true,
    fingerprint: sig.fingerprint,
    trusted,
    predicateType: statement.value.predicateType,
    subjects: statement.value.subjects.length,
    subjectsOk,
    hashChainOk,
    reason: ok ? null : reasons.join('; '),
  };
}

/**
 * Check every JSONL envelope. Exit 0 when each signature, subject digest,
 * and receipt hash-chain head matches. Exit 2 is fail-closed (unsigned,
 * bad signature, untrusted key, digest mismatch, or hash mismatch).
 * Exit 1 is usage or a file that is not an envelope.
 */
export function cmdAttestVerify(
  cwd: string,
  fileArg: string,
  opts: AttestVerifyOptions = {},
): number {
  if (!fileArg || !fileArg.trim()) fail('attest --verify requires a file');
  const abs = resolve(cwd, fileArg);
  if (!existsSync(abs)) fail(`attestation not found: ${abs}`);
  if (!isRegularFile(abs)) fail(`attestation is not a regular file: ${abs}`);
  const size = lstatSync(abs).size;
  if (size > MAX_ATTEST_BYTES) {
    fail(`attestation is ${size} bytes, over the ${MAX_ATTEST_BYTES} byte cap`);
  }
  const raw = readFileSync(abs);
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    fail('attestation starts with a UTF-8 BOM');
  }
  const text = raw.toString('utf8');
  const rows: Array<{ line: number; value: unknown }> = [];
  const pieces = text.split('\n');
  if (pieces.length && pieces[pieces.length - 1] === '') pieces.pop();
  for (let i = 0; i < pieces.length; i++) {
    const line = pieces[i].replace(/\r$/, '');
    if (!line.trim()) continue;
    try {
      rows.push({ line: i + 1, value: JSON.parse(line) });
    } catch {
      fail(`line ${i + 1} is not a JSON envelope`);
    }
  }
  if (!rows.length) fail('attestation file is empty');

  let local: LoadedKeys | null = null;
  try {
    local = loadKeys(cwd);
  } catch {
    local = null;
  }

  const results = rows.map((row) => verifyOne(cwd, row.value, row.line, local, opts.trustedKeys));
  const failed = results.filter((row) => !row.ok);
  const exitCode: 0 | 2 = failed.length ? 2 : 0;
  const trustedValues = results.map((row) => row.trusted);
  let trusted: boolean | null = null;
  if (trustedValues.some((value) => value === false)) trusted = false;
  else if (trustedValues.length && trustedValues.every((value) => value === true)) trusted = true;
  const note =
    exitCode === 0 && trusted === null && results.every((row) => row.signed)
      ? TRUST_NOTE
      : null;
  if (note) console.error(color.yellow(note));
  const reason = failed.map((row) => `line ${row.line}: ${row.reason}`).join('; ') || null;
  const predicateType = results.every((row) => row.predicateType === results[0].predicateType)
    ? results[0].predicateType
    : null;
  const report = {
    ok: exitCode === 0,
    command: 'attest-verify',
    version: VERSION,
    exitCode,
    path: abs,
    envelopes: results.length,
    failed: failed.length,
    signed: results.every((row) => row.signed),
    trusted,
    fingerprint: results.find((row) => row.fingerprint)?.fingerprint ?? null,
    predicateType,
    subjects: results.reduce((sum, row) => sum + row.subjects, 0),
    subjectsOk: results.every((row) => row.subjectsOk),
    hashChainOk: results.every((row) => row.hashChainOk),
    redacted: true,
    results,
    reason,
    warning: note,
  };
  if (opts.json) {
    console.log(JSON.stringify(report));
  } else if (exitCode === 0) {
    console.log(color.green('OK') + ` ${abs}`);
    console.log(color.dim(`signed ${report.fingerprint}`));
    console.log(color.dim(`subjects ${report.subjects} match`));
    console.log(color.dim('hash-chain head matches'));
    if (results.length > 1) console.log(color.dim(`envelopes ${results.length}`));
  } else {
    console.error(color.red('FAILED') + ` ${abs}`);
    for (const row of failed) {
      console.error(color.red('  ' + (row.reason || 'failed')));
    }
  }
  return exitCode;
}
