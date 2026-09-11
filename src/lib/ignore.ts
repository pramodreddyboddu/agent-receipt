/**
 * Minimal gitignore-style glob matching for path noise filters.
 * Supports: *, ?, **, and leading/trailing path segments.
 */

export function globToRegExp(pattern: string): RegExp {
  let p = pattern.replace(/\\/g, '/').trim();
  if (!p) return /^$/;

  // Normalize **/foo and foo/** forms
  const parts: string[] = [];
  let i = 0;
  while (i < p.length) {
    if (p.startsWith('**/', i)) {
      parts.push('(?:.*/)?');
      i += 3;
    } else if (p === '**' || (p.startsWith('**', i) && i + 2 === p.length)) {
      parts.push('.*');
      i += 2;
    } else if (p[i] === '*') {
      parts.push('[^/]*');
      i += 1;
    } else if (p[i] === '?') {
      parts.push('[^/]');
      i += 1;
    } else if ('.+^$()[]{}|'.includes(p[i])) {
      parts.push('\\' + p[i]);
      i += 1;
    } else {
      parts.push(p[i]);
      i += 1;
    }
  }
  return new RegExp(`^${parts.join('')}$`);
}

export function pathMatchesGlob(filePath: string, pattern: string): boolean {
  const path = filePath.replace(/\\/g, '/');
  const pat = pattern.replace(/\\/g, '/').trim();
  if (!pat) return false;

  // Bare directory name like "node_modules" → match that segment anywhere
  if (!pat.includes('*') && !pat.includes('?') && !pat.includes('/')) {
    const re = new RegExp(`(^|/)${pat.replace(/[.+^$()[\]{}|]/g, '\\$&')}(/|$)`);
    return re.test(path);
  }

  // "dist/**" style — also match the directory itself
  if (pat.endsWith('/**')) {
    const prefix = pat.slice(0, -3);
    if (path === prefix || path.startsWith(prefix + '/')) return true;
  }

  if (globToRegExp(pat).test(path)) return true;

  // Also try matching basename-only patterns against the full path's basename
  const base = path.split('/').pop() || path;
  if (!pat.includes('/')) {
    return globToRegExp(pat).test(base);
  }
  return false;
}

export function isIgnoredPath(filePath: string, patterns: string[]): boolean {
  if (!patterns.length) return false;
  return patterns.some((g) => pathMatchesGlob(filePath, g));
}

export function filterIgnored<T extends { path: string }>(
  files: T[],
  patterns: string[],
): { kept: T[]; ignored: T[] } {
  if (!patterns.length) return { kept: files, ignored: [] };
  const kept: T[] = [];
  const ignored: T[] = [];
  for (const f of files) {
    if (isIgnoredPath(f.path, patterns)) ignored.push(f);
    else kept.push(f);
  }
  return { kept, ignored };
}
