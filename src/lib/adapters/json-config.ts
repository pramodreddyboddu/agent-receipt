import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const HOOK_MARKER = 'agent-receipt-wrap.sh';

/** First indented key in the file. A missing file stays two spaces. */
export function detectIndent(text: string): string {
  const match = text.match(/\n([ \t]+)"/);
  if (!match || !match[1]) return '  ';
  return match[1];
}

export function readJsonObject(
  filePath: string,
  rel: string,
): { ok: true; value: Record<string, unknown>; indent: string } | { ok: false; reason: string } {
  if (!existsSync(filePath)) return { ok: true, value: {}, indent: '  ' };
  const text = readFileSync(filePath, 'utf8');
  if (!text.trim()) return { ok: true, value: {}, indent: '  ' };
  try {
    const doc = JSON.parse(text);
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      return { ok: false, reason: `refusing to rewrite ${rel}: not a JSON object` };
    }
    return { ok: true, value: doc as Record<string, unknown>, indent: detectIndent(text) };
  } catch {
    return { ok: false, reason: `refusing to rewrite ${rel}: not JSON` };
  }
}

export function jsonText(value: unknown, indent = '  '): string {
  return `${JSON.stringify(value, null, indent)}\n`;
}

/** `hooks` must be an object. An array, including `[]`, is refused. */
export function requireHookObject(hooks: unknown, rel: string): Record<string, unknown> {
  if (hooks === undefined) return {};
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) {
    throw new Error(`refusing to rewrite ${rel}: hooks must be a JSON object`);
  }
  return { ...(hooks as Record<string, unknown>) };
}

/** The event we are about to merge must be an array. An object is refused. */
export function requireEventArray(existing: unknown, rel: string, event: string): unknown[] {
  if (existing === undefined) return [];
  if (!Array.isArray(existing)) {
    throw new Error(`refusing to rewrite ${rel}: hooks.${event} must be an array`);
  }
  return existing.slice();
}

/** Codex recommends a toplevel-relative command so a nested cwd still finds the script. */
export function hookCommand(rel: string): string {
  return `sh "$(git rev-parse --show-toplevel)/${rel}"`;
}

export function writeJson(filePath: string, value: unknown): void {
  mkdirSync(dirname(filePath), { recursive: true });
  const next = jsonText(value);
  if (existsSync(filePath) && readFileSync(filePath, 'utf8') === next) return;
  writeFileSync(filePath, next, 'utf8');
}

export function isOurCommand(command: unknown): boolean {
  return typeof command === 'string' && command.includes(HOOK_MARKER);
}

export function projectPath(cwd: string, rel: string): string {
  return join(cwd, rel);
}
