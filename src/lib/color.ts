/**
 * Optional ANSI color — no hard dependency.
 * Honors NO_COLOR, FORCE_COLOR, and TTY detection.
 */
const enabled = (() => {
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  if (process.env.FORCE_COLOR === '0') return false;
  if (process.env.FORCE_COLOR) return true;
  return Boolean(process.stdout.isTTY);
})();

function wrap(code: number, s: string): string {
  if (!enabled) return s;
  return `\u001b[${code}m${s}\u001b[0m`;
}

export const color = {
  enabled,
  bold: (s: string) => wrap(1, s),
  dim: (s: string) => wrap(2, s),
  green: (s: string) => wrap(32, s),
  yellow: (s: string) => wrap(33, s),
  red: (s: string) => wrap(31, s),
  cyan: (s: string) => wrap(36, s),
};

export function severityColor(severity: string, text: string): string {
  switch (severity) {
    case 'high':
      return color.red(text);
    case 'medium':
      return color.yellow(text);
    default:
      return color.dim(text);
  }
}
