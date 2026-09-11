#!/usr/bin/env node
import { run } from '../dist/cli.js';
const code = await run(process.argv);
process.exit(code ?? 0);
