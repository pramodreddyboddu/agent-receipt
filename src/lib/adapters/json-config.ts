import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const HOOK_MARKER = 'agent-receipt-wrap.sh';

export function readJsonObject(
  filePath: string,
  rel: string,
): { ok: true; value: Record<string, unknown> } | { ok: false; reason: string } {
  if (!existsSync(filePath)) return { ok: true, value: {} };
  const text = readFileSync(filePath, 'utf8');
  if (!text.trim()) return { ok: true, value: {} };
  try {
    const doc = JSON.parse(text);
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      return { ok: false, reason: `refusing to rewrite ${rel}: not a JSON object` };
    }
    return { ok: true, value: doc as Record<string, unknown> };
  } catch {
    return { ok: false, reason: `refusing to rewrite ${rel}: not JSON` };
  }
}

export function jsonText(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
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
