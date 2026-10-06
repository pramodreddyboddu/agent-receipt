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
  /** Uninstall writes the snapshot back even when the user edited the file. */
  force?: boolean;
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
  return adapter.uninstall(cwd, { dryRun: opts.dryRun, force: opts.force });
}

/**
 * `list` and `status` print detection. `install` merges each agent's project
 * hook and keeps a pre-install backup. `uninstall` restores that backup when
 * the file still matches the post-install hash, and otherwise strips only
 * our hooks unless `--force` is set. `--dry-run` writes nothing.
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
      verbs: (result.verbs ?? []).map((item) => ({ path: showPath(cwd, item.path), verb: item.verb })),
      userChanged: (result.userChanged ?? []).map((file) => showPath(cwd, file)),
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
    const verbs = new Map(result.verbs.map((item) => [item.path, item.verb]));
    const rows = result.files.length ? result.files : result.changed;
    if (opts.dryRun && result.userChanged.length) console.log('  would discard user changes');
    if (!rows.length) {
      console.log('  unchanged');
      continue;
    }
    for (const file of rows) {
      const verb = verbs.get(file);
      const mark = changed.has(file);
      let label: string;
      if (verb === 'unchanged' || (!verb && !mark)) label = 'unchanged';
      else if (verb === 'stripped') label = opts.dryRun ? 'would strip' : 'stripped';
      else if (verb === 'restored') label = opts.dryRun ? 'would restore' : 'restored';
      else if (opts.dryRun) label = action === 'uninstall' ? 'would restore' : 'would write';
      else label = action === 'uninstall' ? 'restored' : 'wrote';
      console.log(`  ${label} ${file}`);
    }
  }
  if (opts.dryRun) console.log('dry-run: no files written');
  return 0;
}
