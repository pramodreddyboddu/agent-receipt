import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  unlinkSync,
  realpathSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isGitRepo, runGit } from '../lib/git.js';
import { color } from '../lib/color.js';

const MARKER_BEGIN = '# >>> agent-receipt hook >>>';
const MARKER_END = '# <<< agent-receipt hook <<<';

export interface InstallHooksOptions {
  /** Also install pre-push hook */
  prePush?: boolean;
  /** Force overwrite managed section */
  force?: boolean;
}

function hooksDir(cwd: string): string {
  try {
    const custom = runGit(['rev-parse', '--git-path', 'hooks'], cwd);
    return custom.startsWith('/') ? custom : join(cwd, custom);
  } catch {
    return join(cwd, '.git', 'hooks');
  }
}

/** POSIX single-quote a path for embedding in shell hooks. */
function shQuote(p: string): string {
  return `'${p.replace(/'/g, `'\\''`)}'`;
}

/**
 * Resolve absolute path to this package's bin/agent-receipt.js.
 * Prefers the running argv script, then package layout next to dist/.
 */
export function resolvePackageBinPath(): string | null {
  const argv1 = process.argv[1];
  if (argv1) {
    try {
      const resolved = realpathSync(argv1);
      const base = resolved.split(/[/\\]/).pop() ?? '';
      if (
        (base === 'agent-receipt.js' || base === 'agent-receipt') &&
        existsSync(resolved)
      ) {
        return resolved;
      }
    } catch {
      /* ignore */
    }
  }

  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const candidate = resolve(here, '../../bin/agent-receipt.js');
    if (existsSync(candidate)) return realpathSync(candidate);
  } catch {
    /* ignore */
  }

  return null;
}

/**
 * Build the shell command used inside installed hooks.
 * Fallback order (also mirrored at hook runtime for AGENT_RECEIPT_BIN):
 *   1. AGENT_RECEIPT_BIN at install time (embedded as default)
 *   2. Absolute path: node + this package's bin
 *   3. npx --yes agent-receipt (last resort; needs registry publish)
 */
export function resolveCliInvocation(): {
  primary: string;
  kind: 'env' | 'bin' | 'npx';
  binPath: string | null;
} {
  const binHint = process.env.AGENT_RECEIPT_BIN?.trim();
  if (binHint) {
    return {
      primary: shQuote(binHint),
      kind: 'env',
      binPath: binHint,
    };
  }

  const binPath = resolvePackageBinPath();
  if (binPath) {
    return {
      primary: `${shQuote(process.execPath)} ${shQuote(binPath)}`,
      kind: 'bin',
      binPath,
    };
  }

  return {
    primary: 'npx --yes agent-receipt',
    kind: 'npx',
    binPath: null,
  };
}

/**
 * Shell snippet that picks CLI at hook runtime:
 * AGENT_RECEIPT_BIN → embedded absolute bin → npx last.
 */
function hookCliSnippet(resolved: ReturnType<typeof resolveCliInvocation>): string {
  const lines: string[] = [
    '# Resolve CLI: AGENT_RECEIPT_BIN → installed bin → npx (last resort)',
    'agent_receipt_run() {',
    '  if [ -n "${AGENT_RECEIPT_BIN:-}" ]; then',
    '    "${AGENT_RECEIPT_BIN}" "$@"',
  ];

  if (resolved.kind === 'bin' && resolved.binPath) {
    lines.push(
      `  elif [ -f ${shQuote(resolved.binPath)} ]; then`,
      `    ${resolved.primary} "$@"`,
    );
  } else if (resolved.kind === 'env' && resolved.binPath) {
    lines.push(
      `  elif [ -f ${shQuote(resolved.binPath)} ] || [ -x ${shQuote(resolved.binPath)} ]; then`,
      `    ${shQuote(resolved.binPath)} "$@"`,
    );
  }

  lines.push(
    '  elif command -v npx >/dev/null 2>&1; then',
    '    npx --yes agent-receipt "$@"',
    '  else',
    '    return 0',
    '  fi',
    '}',
  );

  return lines.join('\n');
}

function postCommitBody(): string {
  const resolved = resolveCliInvocation();
  const runner = hookCliSnippet(resolved);
  return `${MARKER_BEGIN}
# Auto-installed by \`agent-receipt install-hooks\`.
# Captures a receipt for the commit that just landed (skips if capture fails).
${runner}
agent_receipt_run capture \\
  --commits 1 \\
  --agent "\${AGENT_RECEIPT_AGENT:-git-hook}" \\
  --message "post-commit \$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \\
  >/dev/null 2>&1 || true
${MARKER_END}
`;
}

function prePushBody(): string {
  const resolved = resolveCliInvocation();
  const runner = hookCliSnippet(resolved);
  return `${MARKER_BEGIN}
# Auto-installed by \`agent-receipt install-hooks --pre-push\`.
# Captures a receipt before push (non-blocking on failure).
${runner}
agent_receipt_run capture \\
  --commits 5 \\
  --agent "\${AGENT_RECEIPT_AGENT:-git-hook}" \\
  --message "pre-push \$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)" \\
  >/dev/null 2>&1 || true
${MARKER_END}
`;
}

function stripManaged(content: string): string {
  const begin = content.indexOf(MARKER_BEGIN);
  if (begin < 0) return content;
  const end = content.indexOf(MARKER_END, begin);
  if (end < 0) return content.slice(0, begin).replace(/\n+$/, '\n');
  const after = content.slice(end + MARKER_END.length).replace(/^\n/, '');
  return (content.slice(0, begin) + after).replace(/\n{3,}/g, '\n\n');
}

function upsertHook(
  hookPath: string,
  body: string,
  _force: boolean,
): 'created' | 'updated' {
  const shebang = '#!/bin/sh\n';
  if (!existsSync(hookPath)) {
    writeFileSync(hookPath, shebang + '\n' + body, { mode: 0o755 });
    chmodSync(hookPath, 0o755);
    return 'created';
  }
  const existing = readFileSync(hookPath, 'utf8');
  if (existing.includes(MARKER_BEGIN)) {
    const cleaned = stripManaged(existing);
    const next = cleaned.trimEnd() + '\n\n' + body;
    writeFileSync(hookPath, next.startsWith('#!') ? next : shebang + next, {
      mode: 0o755,
    });
    chmodSync(hookPath, 0o755);
    return 'updated';
  }
  // Append managed section to existing custom hook
  const next = existing.trimEnd() + '\n\n' + body;
  writeFileSync(hookPath, next, { mode: 0o755 });
  chmodSync(hookPath, 0o755);
  return 'updated';
}

function removeManaged(hookPath: string): 'removed' | 'absent' | 'untouched' {
  if (!existsSync(hookPath)) return 'absent';
  const existing = readFileSync(hookPath, 'utf8');
  if (!existing.includes(MARKER_BEGIN)) return 'untouched';
  const cleaned = stripManaged(existing).trim();
  if (!cleaned || cleaned === '#!/bin/sh' || cleaned === '#!/usr/bin/env bash') {
    try {
      unlinkSync(hookPath);
    } catch {
      writeFileSync(hookPath, '#!/bin/sh\n', { mode: 0o755 });
    }
    return 'removed';
  }
  writeFileSync(hookPath, cleaned.endsWith('\n') ? cleaned : cleaned + '\n', {
    mode: 0o755,
  });
  return 'removed';
}

export function cmdInstallHooks(cwd: string, opts: InstallHooksOptions = {}): void {
  if (!isGitRepo(cwd)) {
    throw new Error('Not a git repository. Run inside a git repo or git init first.');
  }
  const dir = hooksDir(cwd);
  mkdirSync(dir, { recursive: true });

  const resolved = resolveCliInvocation();

  const postPath = join(dir, 'post-commit');
  const postResult = upsertHook(postPath, postCommitBody(), Boolean(opts.force));
  console.log(color.green('✓') + ` post-commit hook ${postResult}: ${postPath}`);

  if (opts.prePush) {
    const prePath = join(dir, 'pre-push');
    const preResult = upsertHook(prePath, prePushBody(), Boolean(opts.force));
    console.log(color.green('✓') + ` pre-push hook ${preResult}: ${prePath}`);
  }

  console.log('');
  if (resolved.kind === 'bin' && resolved.binPath) {
    console.log(
      `Hooks prefer this install: ${process.execPath} ${resolved.binPath}`,
    );
  } else if (resolved.kind === 'env' && resolved.binPath) {
    console.log(`Hooks prefer AGENT_RECEIPT_BIN=${resolved.binPath}`);
  } else {
    console.log(
      'Hooks fall back to `npx --yes agent-receipt` (set AGENT_RECEIPT_BIN or install locally).',
    );
  }
  console.log(
    'Runtime override: AGENT_RECEIPT_BIN=/path/to/agent-receipt.js (checked first).',
  );
  console.log('Override agent label with AGENT_RECEIPT_AGENT=cursor');
  console.log('');
  console.log(
    'Uninstall:  agent-receipt uninstall-hooks' + (opts.prePush ? ' --pre-push' : ''),
  );
}

export function cmdUninstallHooks(
  cwd: string,
  opts: { prePush?: boolean } = {},
): void {
  if (!isGitRepo(cwd)) {
    throw new Error('Not a git repository. Run inside a git repo or git init first.');
  }
  const dir = hooksDir(cwd);
  const post = removeManaged(join(dir, 'post-commit'));
  console.log(`post-commit: ${post}`);
  const prePath = join(dir, 'pre-push');
  if (
    opts.prePush ||
    (existsSync(prePath) && readFileSync(prePath, 'utf8').includes(MARKER_BEGIN))
  ) {
    console.log(`pre-push: ${removeManaged(prePath)}`);
  }
  console.log(color.green('✓') + ' Managed agent-receipt hook sections removed.');
}

export {
  MARKER_BEGIN,
  MARKER_END,
  stripManaged,
  postCommitBody,
  prePushBody,
};
