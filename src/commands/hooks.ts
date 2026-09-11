import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  unlinkSync,
} from 'node:fs';
import { join } from 'node:path';
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

function resolveCliInvocation(): string {
  const binHint = process.env.AGENT_RECEIPT_BIN;
  if (binHint) return `"${binHint}"`;
  return 'npx --yes agent-receipt';
}

function postCommitBody(): string {
  const cli = resolveCliInvocation();
  return `${MARKER_BEGIN}
# Auto-installed by \`agent-receipt install-hooks\`.
# Captures a receipt for the commit that just landed (skips if capture fails).
if command -v npx >/dev/null 2>&1 || [ -n "\${AGENT_RECEIPT_BIN:-}" ]; then
  ${cli} capture \\
    --commits 1 \\
    --agent "\${AGENT_RECEIPT_AGENT:-git-hook}" \\
    --message "post-commit \$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \\
    >/dev/null 2>&1 || true
fi
${MARKER_END}
`;
}

function prePushBody(): string {
  const cli = resolveCliInvocation();
  return `${MARKER_BEGIN}
# Auto-installed by \`agent-receipt install-hooks --pre-push\`.
# Captures a receipt before push (non-blocking on failure).
if command -v npx >/dev/null 2>&1 || [ -n "\${AGENT_RECEIPT_BIN:-}" ]; then
  ${cli} capture \\
    --commits 5 \\
    --agent "\${AGENT_RECEIPT_AGENT:-git-hook}" \\
    --message "pre-push \$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)" \\
    >/dev/null 2>&1 || true
fi
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

  const postPath = join(dir, 'post-commit');
  const postResult = upsertHook(postPath, postCommitBody(), Boolean(opts.force));
  console.log(color.green('✓') + ` post-commit hook ${postResult}: ${postPath}`);

  if (opts.prePush) {
    const prePath = join(dir, 'pre-push');
    const preResult = upsertHook(prePath, prePushBody(), Boolean(opts.force));
    console.log(color.green('✓') + ` pre-push hook ${preResult}: ${prePath}`);
  }

  console.log('');
  console.log('Hooks call `npx --yes agent-receipt capture` with sensible defaults.');
  console.log('Override the binary with AGENT_RECEIPT_BIN=/path/to/agent-receipt.js');
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
