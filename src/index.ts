export { run } from './cli.js';
export { VERSION } from './lib/version.js';
export { cmdInit, writeCursorRule } from './commands/init.js';
export { cmdCapture } from './commands/capture.js';
export { cmdShow, resolveReceiptPath, findLatestReceipt } from './commands/show.js';
export { cmdLast } from './commands/last.js';
export { cmdHistory } from './commands/history.js';
export { cmdWatch, clampInterval } from './commands/watch.js';
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
export {
  analyzeRisks,
  summarizeRisks,
  topRisks,
  sortRisks,
  parseFailOn,
  meetsFailOn,
  parseRiskAllowlist,
  applyRiskAllowlist,
  shannonEntropy,
} from './lib/risk.js';
export { summarizeNotableChanges, formatDiffStatTable } from './lib/summary.js';
export { formatMarkdown, formatJson, formatTldr, buildReviewItems } from './lib/receipt.js';
export { CURSOR_RULE_MDC, CURSOR_RULE_REL } from './lib/cursor-rule.js';
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

export {
  loadIndex,
  updateIndexOnCapture,
  indexPath,
  INDEX_REL,
} from './lib/receipt-index.js';
export {
  isDirty,
  dirtyFingerprint,
  getWorkingTreeFiles,
} from './lib/git.js';
