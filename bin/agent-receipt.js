#!/usr/bin/env node
import { writeSync } from 'node:fs';
import { run } from '../dist/cli.js';

function errorCode(err) {
  return err && typeof err === 'object' && typeof err.code === 'string' ? err.code : '';
}

function isBrokenPipe(err) {
  const code = errorCode(err);
  return code === 'EPIPE' || code === 'ERR_STREAM_DESTROYED';
}

// A closed pipe (`session id | head`) emits `error` with no listener and
// the process exits 1 with a stack. A full disk does the same on the drain
// write after the command already handled the first ENOSPC. Record it here.
let writeError = null;
function noteStreamError(err) {
  if (!err || isBrokenPipe(err)) return;
  if (!writeError) writeError = err;
}
process.stdout.on('error', noteStreamError);
process.stderr.on('error', noteStreamError);

let code = 0;
try {
  code = (await run(process.argv)) ?? 0;
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  try {
    writeSync(2, `Error: ${msg}\n`);
  } catch {
    /* stderr cannot accept the line */
  }
  code = 1;
}

// process.exit() does not drain a pipe. A stdout payload past 64 KiB,
// including `session --json`, was cut off. Wait until both streams flush.
// The callback receives EPIPE. The listener above keeps it from throwing.
const streams = [process.stdout, process.stderr].filter(
  (stream) => stream.writable && !stream.destroyed && !stream.writableEnded,
);
if (streams.length) {
  await new Promise((resolve) => {
    const timer = setTimeout(resolve, 5000);
    timer.unref();
    let left = streams.length;
    const done = () => {
      left -= 1;
      if (left <= 0) {
        clearTimeout(timer);
        resolve();
      }
    };
    for (const stream of streams) {
      try {
        stream.write('', done);
      } catch {
        done();
      }
    }
  });
}

if (code === 0 && writeError) {
  const msg = errorCode(writeError) === 'ENOSPC' ? 'no space left on device' : writeError.message || 'write failed';
  try {
    writeSync(2, `Error: ${msg}\n`);
  } catch {
    /* stderr cannot accept the line */
  }
  code = 1;
}
process.exit(code);
