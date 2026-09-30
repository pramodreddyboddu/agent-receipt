/**
 * Re-sign claims copied in by `session import`.
 * Keyed by the canonical receipt sha256. This is the manifest signer's
 * claim, not a second signature over the pre-export bytes. A corrupt or
 * missing file is ignored so `session` still lists the tree.
 */

import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { verifyMarkdown } from './hash.js';

export const RESIGN_PROVENANCE_REL = '.agent-receipt/resign-provenance.json';

export interface ResignClaim {
  originalFingerprint: string | null;
  resignedBy: string | null;
  signedBy: string | null;
}

interface ProvenanceFile {
  version: 1;
  receipts: Record<string, ResignClaim>;
}

const HEX64 = /^[0-9a-f]{64}$/;

function emptyClaim(): ResignClaim {
  return { originalFingerprint: null, resignedBy: null, signedBy: null };
}

function hexOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string' && HEX64.test(value)) return value;
  return null;
}

export function provenancePath(cwd: string): string {
  return join(cwd, RESIGN_PROVENANCE_REL);
}

/** Empty map when the file is missing, unreadable, or not the expected shape. */
export function loadResignProvenance(cwd: string): Map<string, ResignClaim> {
  const path = provenancePath(cwd);
  const out = new Map<string, ResignClaim>();
  if (!existsSync(path)) return out;
  try {
    if (!lstatSync(path).isFile()) return out;
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<ProvenanceFile>;
    if (!parsed || parsed.version !== 1 || !parsed.receipts || typeof parsed.receipts !== 'object') {
      return out;
    }
    for (const [sha, claim] of Object.entries(parsed.receipts)) {
      if (!HEX64.test(sha) || !claim || typeof claim !== 'object') continue;
      const next: ResignClaim = {
        originalFingerprint: hexOrNull(claim.originalFingerprint),
        resignedBy: hexOrNull(claim.resignedBy),
        signedBy: hexOrNull(claim.signedBy),
      };
      if (next.originalFingerprint || next.resignedBy || next.signedBy) out.set(sha, next);
    }
  } catch {
    return new Map();
  }
  return out;
}

export function recordResignProvenance(
  cwd: string,
  entries: Array<{ sha256: string } & ResignClaim>,
): void {
  const useful = entries.filter(
    (entry) =>
      HEX64.test(entry.sha256) &&
      (entry.originalFingerprint || entry.resignedBy || entry.signedBy),
  );
  if (!useful.length) return;
  const current = loadResignProvenance(cwd);
  for (const entry of useful) {
    const prev = current.get(entry.sha256) ?? emptyClaim();
    current.set(entry.sha256, {
      originalFingerprint: entry.originalFingerprint ?? prev.originalFingerprint,
      resignedBy: entry.resignedBy ?? prev.resignedBy,
      signedBy: entry.signedBy ?? prev.signedBy,
    });
  }
  const body: ProvenanceFile = {
    version: 1,
    receipts: Object.fromEntries([...current.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))),
  };
  const path = provenancePath(cwd);
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

/** Map receipt id → claim, using the canonical sha256 of each file. */
export function provenanceForNodes(
  cwd: string,
  nodes: Array<{ id: string; path: string }>,
): Map<string, ResignClaim> {
  const store = loadResignProvenance(cwd);
  const out = new Map<string, ResignClaim>();
  if (store.size === 0) return out;
  for (const node of nodes) {
    let text: string;
    try {
      text = readFileSync(node.path, 'utf8');
    } catch {
      continue;
    }
    const claim = store.get(verifyMarkdown(text).actual);
    if (claim) out.set(node.id, claim);
  }
  return out;
}
