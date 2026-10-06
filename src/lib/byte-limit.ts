/**
 * Size caps for session-package reads. Stat before any read so a hostile
 * multi-hundred-megabyte file never becomes a string.
 */
import { lstatSync, statSync } from 'node:fs';

/** Receipt Markdown. Diffs are large; this still refuses a 700 MB plant. */
export const DEFAULT_MAX_RECEIPT_BYTES = 32 * 1024 * 1024;
/** Ed25519 sidecar JSON. A real sidecar is a few kilobytes. */
export const DEFAULT_MAX_SIDECAR_BYTES = 256 * 1024;
/** session-manifest.json. Thousands of receipt rows still fit. */
export const DEFAULT_MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
/**
 * Transcript file passed to wrap/capture. Over this size the section is
 * skipped with a warning (exit 0). It is not a ByteLimitError.
 */
export const DEFAULT_MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024;
/** Tool-call events kept on the receipt. The rest are counted as truncated. */
export const DEFAULT_MAX_TOOL_EVENTS = 200;
/** Characters kept in one redacted args summary or shell command. */
export const DEFAULT_MAX_TOOL_ARG_CHARS = 240;
/**
 * Rendered `## Tool calls` section. Extra events are dropped and the
 * tool-calls sha256 is recomputed over what remains.
 */
export const DEFAULT_MAX_TOOL_SECTION_BYTES = 32 * 1024;

/** Oversize input. Callers map this to exit 2 and write nothing. */
export class ByteLimitError extends Error {
  readonly exitCode = 2 as const;
  constructor(message: string) {
    super(message);
    this.name = 'ByteLimitError';
  }
}

export interface ByteLimits {
  maxReceiptBytes: number;
  maxSidecarBytes: number;
  maxManifestBytes: number;
}

export function resolveByteLimits(opts: {
  maxReceiptBytes?: number;
  maxSidecarBytes?: number;
  maxManifestBytes?: number;
} = {}): ByteLimits {
  return {
    maxReceiptBytes: opts.maxReceiptBytes ?? DEFAULT_MAX_RECEIPT_BYTES,
    maxSidecarBytes: opts.maxSidecarBytes ?? DEFAULT_MAX_SIDECAR_BYTES,
    maxManifestBytes: opts.maxManifestBytes ?? DEFAULT_MAX_MANIFEST_BYTES,
  };
}

/**
 * Refuse to read `filePath` when its content is larger than `maxBytes`.
 * Uses `stat` (follows a symlink) so the size is the bytes `readFile` would
 * load. Callers that must not follow symlinks check `lstat` first.
 */
export function assertReadableSize(
  filePath: string,
  maxBytes: number,
  label: string,
  flag: string,
): void {
  let size: number;
  try {
    const st = statSync(filePath);
    if (!st.isFile()) {
      throw new ByteLimitError(`${label} is not a regular file. Refusing to read it.`);
    }
    size = st.size;
  } catch (err) {
    if (err instanceof ByteLimitError) throw err;
    const detail = err instanceof Error ? err.message : String(err);
    throw new ByteLimitError(`unreadable ${label} (${detail}). Refusing to read it.`);
  }
  if (size > maxBytes) {
    throw new ByteLimitError(
      `${label} is ${size} bytes, over the ${maxBytes} byte limit. Refusing to read it. Pass ${flag} to raise the limit.`,
    );
  }
}

/** True when `filePath` is a symlink. A missing path is false. */
export function isSymlink(filePath: string): boolean {
  try {
    return lstatSync(filePath).isSymbolicLink();
  } catch {
    return false;
  }
}
