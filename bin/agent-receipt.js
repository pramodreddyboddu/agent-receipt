#!/usr/bin/env node
import { run } from '../dist/cli.js';
const code = run(process.argv);
process.exit(code ?? 0);
