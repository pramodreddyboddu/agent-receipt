/**
 * in-toto Statement v1 for one agent-receipt run.
 *
 * Subjects are file names plus sha256 of the raw bytes. `hashChainHead` is
 * the receipt canonical-body sha256 (the hex `verify` prints), not the raw
 * file digest. The run predicate is `https://agent-receipt.dev/run/v1`.
 * SLSA Provenance v1 maps the same facts into buildDefinition / runDetails.
 *
 * Narrative fields are redacted by the caller before they are passed here.
 * This module does not read the receipt and does not sign.
 */
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const PREDICATE_RUN = 'https://agent-receipt.dev/run/v1';
export const PREDICATE_SLSA = 'https://slsa.dev/provenance/v1';
export const SLSA_BUILD_TYPE = PREDICATE_RUN;
export const SLSA_BUILDER_ID = 'https://agent-receipt.dev/builder/v1';

const HEX64 = /^[0-9a-f]{64}$/;

export type PredicateKind = 'run' | 'slsa';

export interface Subject {
  name: string;
  digest: { sha256: string };
}

export interface ToolCallFact {
  tool: string;
  exitStatus: number | null;
  argsSummary: string | null;
}

export interface PolicyHit {
  severity: string;
  code: string;
  detail: string;
}

export interface FileFact {
  name: string;
  status: string | null;
  /** Raw sha256 when the file was a regular file and was hashed. */
  digest: string | null;
}

/** Facts carried by both predicate modes. Already redacted. */
export interface RunFacts {
  agent: string | null;
  session: string | null;
  parent: string | null;
  id: string | null;
  timestamp: string | null;
  message: string | null;
  commands: string[];
  toolCalls: ToolCallFact[];
  policyHits: PolicyHit[];
  exitCode: number | null;
  failedOn: boolean | null;
  /** Canonical receipt sha256. */
  hashChainHead: string;
  /** sha256 of the last audit.jsonl line at attest time, or null. */
  auditChainHead: string | null;
  /** Subject name of the receipt file. */
  receiptName: string;
  branch: string | null;
  head: string | null;
  files: FileFact[];
  cliVersion: string;
}

export interface InTotoStatement {
  _type: typeof STATEMENT_TYPE;
  subject: Subject[];
  predicateType: string;
  predicate: Record<string, unknown>;
}

function runPredicate(facts: RunFacts): Record<string, unknown> {
  return {
    agent: facts.agent,
    session: facts.session,
    parent: facts.parent,
    id: facts.id,
    timestamp: facts.timestamp,
    message: facts.message,
    commands: facts.commands,
    toolCalls: facts.toolCalls,
    policyHits: facts.policyHits,
    exitCode: facts.exitCode,
    failedOn: facts.failedOn,
    hashChainHead: facts.hashChainHead,
    auditChainHead: facts.auditChainHead,
    receipt: { name: facts.receiptName, sha256: facts.hashChainHead },
    files: facts.files,
    redacted: true,
    cliVersion: facts.cliVersion,
  };
}

function slsaPredicate(facts: RunFacts): Record<string, unknown> {
  const externalParameters: Record<string, unknown> = {
    agent: facts.agent,
    session: facts.session,
    parent: facts.parent,
    id: facts.id,
    message: facts.message,
    commands: facts.commands,
    toolCalls: facts.toolCalls,
    policyHits: facts.policyHits,
    exitCode: facts.exitCode,
    failedOn: facts.failedOn,
    hashChainHead: facts.hashChainHead,
    auditChainHead: facts.auditChainHead,
    receiptName: facts.receiptName,
    files: facts.files,
    redacted: true,
  };
  const resolvedDependencies: Array<Record<string, unknown>> = [];
  if (facts.head && /^[0-9a-f]{7,64}$/i.test(facts.head)) {
    resolvedDependencies.push({
      name: facts.branch || 'HEAD',
      digest: { gitCommit: facts.head.toLowerCase() },
    });
  }
  const byproducts: Array<Record<string, unknown>> = [
    { name: 'hash-chain-head', digest: { sha256: facts.hashChainHead } },
  ];
  if (facts.auditChainHead) {
    byproducts.push({
      name: 'audit-chain-head',
      digest: { sha256: facts.auditChainHead },
    });
  }
  return {
    buildDefinition: {
      buildType: SLSA_BUILD_TYPE,
      externalParameters,
      internalParameters: { cliVersion: facts.cliVersion },
      resolvedDependencies,
    },
    runDetails: {
      builder: { id: SLSA_BUILDER_ID },
      metadata: {
        invocationId: facts.id || facts.hashChainHead,
        ...(facts.timestamp ? { startedOn: facts.timestamp, finishedOn: facts.timestamp } : {}),
      },
      byproducts,
    },
  };
}

export function buildStatement(
  subjects: Subject[],
  facts: RunFacts,
  kind: PredicateKind,
): InTotoStatement {
  if (!HEX64.test(facts.hashChainHead)) {
    throw new Error('hashChainHead must be 64 lowercase hex chars');
  }
  if (!facts.receiptName) throw new Error('receipt subject name is required');
  if (!subjects.length) throw new Error('statement subject is empty');
  for (const subject of subjects) {
    if (!subject.name || !HEX64.test(subject.digest.sha256)) {
      throw new Error(`subject digest is not sha256: ${subject.name || '(unnamed)'}`);
    }
  }
  if (!subjects.some((subject) => subject.name === facts.receiptName)) {
    throw new Error('receipt subject is missing from the statement');
  }
  return {
    _type: STATEMENT_TYPE,
    subject: subjects,
    predicateType: kind === 'slsa' ? PREDICATE_SLSA : PREDICATE_RUN,
    predicate: kind === 'slsa' ? slsaPredicate(facts) : runPredicate(facts),
  };
}

export function statementBytes(statement: InTotoStatement): Buffer {
  return Buffer.from(JSON.stringify(statement), 'utf8');
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export interface ParsedStatement {
  statement: InTotoStatement;
  predicateType: string;
  hashChainHead: string;
  receiptName: string;
  subjects: Subject[];
}

/**
 * Parse a statement from the verified payload bytes.
 * Returns a reason string instead of throwing so verify can fail closed.
 */
export function parseStatement(body: Buffer): { ok: true; value: ParsedStatement } | { ok: false; reason: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return { ok: false, reason: 'in-toto statement is not JSON' };
  }
  const doc = asRecord(parsed);
  if (!doc) return { ok: false, reason: 'in-toto statement must be an object' };
  if (doc._type !== STATEMENT_TYPE) {
    return { ok: false, reason: `unsupported in-toto statement _type: ${String(doc._type)}` };
  }
  if (typeof doc.predicateType !== 'string' || !doc.predicateType) {
    return { ok: false, reason: 'in-toto statement predicateType is missing' };
  }
  if (!Array.isArray(doc.subject) || doc.subject.length === 0) {
    return { ok: false, reason: 'in-toto statement subject is empty' };
  }
  const subjects: Subject[] = [];
  for (const item of doc.subject) {
    const subject = asRecord(item);
    if (!subject || typeof subject.name !== 'string' || !subject.name) {
      return { ok: false, reason: 'in-toto subject name is missing' };
    }
    const digest = asRecord(subject.digest);
    const sha = digest && typeof digest.sha256 === 'string' ? digest.sha256.toLowerCase() : '';
    if (!HEX64.test(sha)) {
      return { ok: false, reason: `subject ${subject.name} digest is not sha256` };
    }
    subjects.push({ name: subject.name, digest: { sha256: sha } });
  }
  const predicate = asRecord(doc.predicate);
  if (!predicate) return { ok: false, reason: 'in-toto statement predicate is missing' };

  const extracted = extractHash(doc.predicateType, predicate);
  if (!extracted.ok) return extracted;

  return {
    ok: true,
    value: {
      statement: {
        _type: STATEMENT_TYPE,
        subject: subjects,
        predicateType: doc.predicateType,
        predicate,
      },
      predicateType: doc.predicateType,
      hashChainHead: extracted.hashChainHead,
      receiptName: extracted.receiptName,
      subjects,
    },
  };
}

function extractHash(
  predicateType: string,
  predicate: Record<string, unknown>,
): { ok: true; hashChainHead: string; receiptName: string } | { ok: false; reason: string } {
  if (predicateType === PREDICATE_RUN) {
    const head = typeof predicate.hashChainHead === 'string' ? predicate.hashChainHead.toLowerCase() : '';
    const receipt = asRecord(predicate.receipt);
    const name = receipt && typeof receipt.name === 'string' ? receipt.name : '';
    const receiptSha = receipt && typeof receipt.sha256 === 'string' ? receipt.sha256.toLowerCase() : '';
    if (!HEX64.test(head)) return { ok: false, reason: 'run predicate hashChainHead is missing' };
    if (!name) return { ok: false, reason: 'run predicate receipt name is missing' };
    if (receiptSha && receiptSha !== head) {
      return { ok: false, reason: 'hash-chain head does not match predicate receipt sha256' };
    }
    return { ok: true, hashChainHead: head, receiptName: name };
  }
  if (predicateType === PREDICATE_SLSA) {
    const build = asRecord(predicate.buildDefinition);
    const run = asRecord(predicate.runDetails);
    const external = build ? asRecord(build.externalParameters) : null;
    const head = external && typeof external.hashChainHead === 'string' ? external.hashChainHead.toLowerCase() : '';
    const name = external && typeof external.receiptName === 'string' ? external.receiptName : '';
    if (!HEX64.test(head)) return { ok: false, reason: 'SLSA predicate hashChainHead is missing' };
    if (!name) return { ok: false, reason: 'SLSA predicate receiptName is missing' };
    const byproducts = run && Array.isArray(run.byproducts) ? run.byproducts : [];
    for (const item of byproducts) {
      const by = asRecord(item);
      if (!by || by.name !== 'hash-chain-head') continue;
      const digest = asRecord(by.digest);
      const sha = digest && typeof digest.sha256 === 'string' ? digest.sha256.toLowerCase() : '';
      if (sha && sha !== head) {
        return { ok: false, reason: 'hash-chain head does not match SLSA byproduct' };
      }
    }
    return { ok: true, hashChainHead: head, receiptName: name };
  }
  return { ok: false, reason: `unsupported predicateType: ${predicateType}` };
}
