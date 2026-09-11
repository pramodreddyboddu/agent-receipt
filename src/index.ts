export { run } from './cli.js';
export { VERSION } from './lib/version.js';
export { cmdInit } from './commands/init.js';
export { cmdCapture } from './commands/capture.js';
export { cmdShow, resolveReceiptPath, findLatestReceipt } from './commands/show.js';
export { cmdLast } from './commands/last.js';
export { cmdVerify } from './commands/verify.js';
export { cmdInstallHooks, cmdUninstallHooks } from './commands/hooks.js';
export { cmdDoctor, runDoctorChecks } from './commands/doctor.js';
export {
  cmdCompare,
  listReceipts,
  findPreviousReceipt,
  parseReceiptGlance,
} from './commands/compare.js';
export {
  appendHashFooter,
  verifyMarkdown,
  sha256Hex,
  canonicalBody,
} from './lib/hash.js';
export { analyzeRisks, summarizeRisks, topRisks, sortRisks } from './lib/risk.js';
export { summarizeNotableChanges, formatDiffStatTable } from './lib/summary.js';
export { formatMarkdown, formatJson } from './lib/receipt.js';
export {
  loadConfig,
  validateConfig,
  parseSimpleYaml,
  DEFAULTS,
} from './lib/config.js';
export {
  globToRegExp,
  pathMatchesGlob,
  isIgnoredPath,
  filterIgnored,
} from './lib/ignore.js';
export { helpFor, globalHelp } from './lib/help.js';
