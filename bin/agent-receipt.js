#!/usr/bin/env node
import { run } from '../dist/cli.js';

const code = (await run(process.argv)) ?? 0;

// process.exit() does not drain a pipe. A stdout payload past 64 KiB,
// including `session --json`, was cut off. Wait until both streams flush.
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
    for (const stream of streams) stream.write('', done);
  });
}
process.exit(code);
