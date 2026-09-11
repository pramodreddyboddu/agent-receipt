export { run } from './cli.js';
export { cmdInit } from './commands/init.js';
export { cmdCapture } from './commands/capture.js';
export { cmdShow, resolveReceiptPath } from './commands/show.js';
export { cmdVerify } from './commands/verify.js';
export {
  appendHashFooter,
  verifyMarkdown,
  sha256Hex,
  canonicalBody,
} from './lib/hash.js';
export { analyzeRisks } from './lib/risk.js';
export { formatMarkdown, formatJson } from './lib/receipt.js';
