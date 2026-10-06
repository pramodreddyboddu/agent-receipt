import { relative } from 'node:path';
import { adapterForAgent, ADAPTERS, listAdapterStatus } from '../lib/adapters/index.js';
import type { AgentAdapter, InstallResult } from '../lib/adapters/types.js';

export type AdaptersAction = 'list' | 'status' | 'install' | 'uninstall';

export interface AdaptersOptions {
  json?: boolean;
  action?: AdaptersAction;
  /** Adapter name or alias. Omit to list or to install every adapter. */
  adapter?: string;
  dryRun?: boolean;
  /**
   * Claude and Cursor only. `false` skips the extra Stop hook.
   * Omit to keep the adapter default (SessionEnd and Stop).
   */
  stop?: boolean;
}

function showPath(cwd: string, filePath: string): string {
  const rel = relative(cwd, filePath);
  if (!rel || rel.startsWith('..')) return filePath;
  return rel;
}

function printStatus(cwd: string, opts: AdaptersOptions, action: AdaptersAction): number {
  let adapters = listAdapterStatus(cwd);
  if (opts.adapter) {
    const named = adapterForAgent(opts.adapter);
    if (!named) {
      throw new Error(
        `Unknown adapter "${opts.adapter}". Known adapters: ${ADAPTERS.map((item) => item.name).join(', ')}.`,
      );
    }
    adapters = adapters.filter((adapter) => adapter.name === named.name);
  }
  if (opts.json) {
    console.log(JSON.stringify({ command: 'adapters', action, dryRun: Boolean(opts.dryRun), adapters }));
    return 0;
  }
  for (const adapter of adapters) {
    const detected = adapter.detected ? 'detected' : 'not detected';
    const installed = adapter.installed ? adapter.status : 'not installed';
    console.log(`${adapter.name.padEnd(12)} ${detected}; ${installed} — ${adapter.detail}`);
  }
  return 0;
}

function selected(name: string | undefined): AgentAdapter[] {
  if (!name) return ADAPTERS.slice();
  const named = adapterForAgent(name);
  if (!named) {
    throw new Error(
      `Unknown adapter "${name}". Known adapters: ${ADAPTERS.map((item) => item.name).join(', ')}.`,
    );
  }
  return [named];
}

function runOne(cwd: string, adapter: AgentAdapter, opts: AdaptersOptions, action: 'install' | 'uninstall'): InstallResult {
  if (action === 'install') {
    return adapter.install(cwd, { dryRun: opts.dryRun, stop: opts.stop });
  }
  return adapter.uninstall(cwd, { dryRun: opts.dryRun });
}

/**
 * `list` and `status` print detection. `install` merges each agent's project
 * hook and keeps a pre-install backup. `uninstall` restores that backup.
 * `--dry-run` writes nothing.
 */
export function cmdAdapters(cwd: string, opts: AdaptersOptions = {}): number {
  const action = opts.action ?? 'list';
  if (action === 'list' || action === 'status') return printStatus(cwd, opts, action);
  const adapters = selected(opts.adapter);
  const results = adapters.map((adapter) => {
    const result = runOne(cwd, adapter, opts, action);
    return {
      name: adapter.name,
      files: result.files.map((file) => showPath(cwd, file)),
      changed: (result.changed ?? []).map((file) => showPath(cwd, file)),
    };
  });
  if (opts.json) {
    console.log(
      JSON.stringify({
        command: 'adapters',
        action,
        dryRun: Boolean(opts.dryRun),
        results,
      }),
    );
    return 0;
  }
  const verb = opts.dryRun ? `dry-run ${action}` : action;
  for (const result of results) {
    console.log(`${verb} ${result.name}`);
    const changed = new Set(result.changed);
    const rows = result.files.length ? result.files : result.changed;
    if (!rows.length) {
      console.log('  unchanged');
      continue;
    }
    for (const file of rows) {
      const mark = changed.has(file);
      const label = opts.dryRun
        ? mark
          ? action === 'uninstall'
            ? 'would restore'
            : 'would write'
          : 'unchanged'
        : mark
          ? action === 'uninstall'
            ? 'restored'
            : 'wrote'
          : 'unchanged';
      console.log(`  ${label} ${file}`);
    }
  }
  if (opts.dryRun) console.log('dry-run: no files written');
  return 0;
}
