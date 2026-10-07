/**
 * `agent-receipt view` — local read-only browser for receipts and sessions.
 * The process stays up until SIGINT or SIGTERM, then closes the server.
 */
import { spawn } from 'node:child_process';
import { writeSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import type { Server } from 'node:http';
import { color } from '../lib/color.js';
import {
  buildViewerCatalog,
  createViewerServer,
  writeStaticViewer,
  type ViewerCatalog,
} from '../lib/viewer.js';
import { isLoopbackBindHost, normalizeAllowedHosts, type AllowedHost } from '../lib/viewer-host.js';

export interface ViewOptions {
  port?: number;
  host?: string;
  openBrowser?: boolean;
  receiptsDir?: string;
  json?: boolean;
  staticDir?: string;
  allowRemote?: boolean;
  /** Raw repeatable `--allowed-host` values. Normalized before listen. */
  allowedHosts?: string[];
  trustedKeys?: string[];
  requireSig?: boolean;
  noRedact?: boolean;
}

/** A pipe can hold console.log. The URL line has to be visible while we serve. */
function stdoutLine(line: string): void {
  writeSync(1, `${line}\n`);
}

function allowedHostList(allowed: readonly AllowedHost[]): string {
  return allowed.map((entry) => entry.normalized).join(', ');
}

function urlHost(host: string, port: number): string {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

function openBrowser(url: string): void {
  const platform = process.platform;
  const command = platform === 'darwin' ? 'open' : platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => {});
    child.unref();
  } catch {
    // Best-effort. A missing opener does not fail the viewer.
  }
}

function catalogFor(cwd: string, opts: ViewOptions): ViewerCatalog {
  return buildViewerCatalog({
    cwd,
    receiptsDir: opts.receiptsDir,
    trustedKeys: opts.trustedKeys,
    requireSig: opts.requireSig,
  });
}

export async function cmdView(cwd: string, opts: ViewOptions = {}): Promise<number> {
  if (opts.noRedact) {
    throw new Error('view always redacts. There is no --no-redact.');
  }
  const allowed = normalizeAllowedHosts(opts.allowedHosts ?? []);
  if (opts.staticDir !== undefined) {
    if (!opts.staticDir.trim()) throw new Error('view --static requires an output directory');
    if (
      opts.port !== undefined ||
      opts.host !== undefined ||
      opts.openBrowser ||
      opts.allowRemote ||
      allowed.length > 0
    ) {
      throw new Error(
        'view --static does not listen. Omit --port, --host, --open, --allow-remote, and --allowed-host.',
      );
    }
    const out = isAbsolute(opts.staticDir) ? opts.staticDir : resolve(cwd, opts.staticDir);
    const catalog = catalogFor(cwd, opts);
    writeStaticViewer(out, catalog.snapshot);
    const count = catalog.snapshot.receipts.length;
    if (opts.json) {
      stdoutLine(
        JSON.stringify({
          command: 'view',
          ok: true,
          static: true,
          out,
          receiptCount: count,
        }),
      );
    } else {
      stdoutLine(`Wrote ${out} (${count} receipt(s))`);
    }
    return 0;
  }

  const host = (opts.host ?? '127.0.0.1').trim();
  if (!host || /[\s/\\]/.test(host)) throw new Error('Invalid --host.');
  const port = opts.port === undefined ? 4173 : opts.port;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error('--port must be an integer from 0 to 65535');
  }
  if (!isLoopbackBindHost(host) && !opts.allowRemote) {
    throw new Error(
      `Refusing to bind ${host}. The viewer binds 127.0.0.1 unless you pass --allow-remote.`,
    );
  }
  const remoteNames = allowed.filter((entry) => !entry.loopback);
  if (remoteNames.length > 0 && !opts.allowRemote) {
    throw new Error(
      `Refusing --allowed-host ${allowedHostList(remoteNames)}. Pass --allow-remote to accept a non-loopback Host, or use only 127.0.0.1, localhost, or ::1.`,
    );
  }

  const catalog = catalogFor(cwd, opts);
  const bound = { host, port, allowedHosts: allowed };
  const server: Server = createViewerServer(catalog, bound);
  const count = catalog.snapshot.receipts.length;

  return await new Promise<number>((resolvePromise) => {
    let settled = false;
    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      resolvePromise(code);
    };
    const shutdown = () => {
      if (settled) return;
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      server.close(() => finish(0));
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    server.once('error', (err: NodeJS.ErrnoException) => {
      const message = err.code === 'EADDRINUSE' ? `Port ${port} is already in use.` : err.message;
      if (opts.json) {
        console.log(JSON.stringify({ ok: false, command: 'view', error: message }));
      } else {
        console.error(color.red('Error:') + ` ${message}`);
      }
      finish(1);
    });
    server.listen(port, host, () => {
      const addr = server.address();
      const boundPort = addr && typeof addr === 'object' ? addr.port : port;
      bound.port = boundPort;
      const url = `http://${urlHost(host, boundPort)}/`;
      if (!isLoopbackBindHost(host) && opts.allowRemote) {
        const listed = allowedHostList(allowed);
        const suffix = listed ? ` Allowed hosts: ${listed}.` : '';
        console.error(
          `warning: --allow-remote binds ${host}. The viewer is meant for 127.0.0.1.${suffix}`,
        );
      }
      if (opts.json) {
        stdoutLine(
          JSON.stringify({
            url,
            port: boundPort,
            receiptCount: count,
            pid: process.pid,
            allowedHosts: allowed.map((entry) => entry.normalized),
          }),
        );
      } else {
        stdoutLine(url);
        stdoutLine(`${count} receipt(s)`);
        console.error('Read-only. Serving redacted receipts. Ctrl+C to stop.');
      }
      if (opts.openBrowser) openBrowser(url);
    });
  });
}
