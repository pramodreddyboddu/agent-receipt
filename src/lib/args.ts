export interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2);
  const command = args[0] && !args[0].startsWith('-') ? args[0] : 'help';
  const rest = command === 'help' && args[0]?.startsWith('-') ? args : args.slice(1);
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  // Flags that never take a value, so a following receipt path stays positional.
  // `--page` / `--one-pager` must not swallow the following receipt path.
  const valueless = new Set([
    'require-sig',
    'require-signature',
    'self',
    'page',
    'one-pager',
    'package',
    'pack',
    'dry-run',
  ]);
  // Repeatable flags are joined with commas (`--trusted-key a --trusted-key b`).
  const repeatable = new Set(['trusted-key']);

  const assignFlag = (key: string, value: string | boolean): void => {
    if (typeof value === 'string' && repeatable.has(key) && typeof flags[key] === 'string') {
      flags[key] = `${flags[key]},${value}`;
      return;
    }
    flags[key] = value;
  };

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') {
      positional.push(...rest.slice(i + 1));
      break;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) {
        assignFlag(a.slice(2, eq), a.slice(eq + 1));
      } else {
        const key = a.slice(2);
        if (valueless.has(key)) {
          assignFlag(key, true);
          continue;
        }
        const next = rest[i + 1];
        if (next && !next.startsWith('-')) {
          assignFlag(key, next);
          i++;
        } else {
          assignFlag(key, true);
        }
      }
    } else if (a.startsWith('-') && a.length === 2) {
      const key = a.slice(1);
      const next = rest[i + 1];
      if (next && !next.startsWith('-')) {
        assignFlag(key, next);
        i++;
      } else {
        assignFlag(key, true);
      }
    } else {
      positional.push(a);
    }
  }

  return { command, positional, flags };
}

export function flagString(
  flags: Record<string, string | boolean>,
  ...names: string[]
): string | undefined {
  for (const n of names) {
    const v = flags[n];
    if (typeof v === 'string') return v;
  }
  return undefined;
}

export function flagBool(
  flags: Record<string, string | boolean>,
  ...names: string[]
): boolean {
  for (const n of names) {
    const v = flags[n];
    if (v === true || v === 'true') return true;
  }
  return false;
}

export function flagNumber(
  flags: Record<string, string | boolean>,
  name: string,
): number | undefined {
  const v = flags[name];
  if (typeof v === 'string' && /^-?\d+$/.test(v)) return parseInt(v, 10);
  return undefined;
}
