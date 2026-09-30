export { run } from './cli.js';
export { VERSION } from './lib/version.js';
export {
  cmdInit,
  writeCursorRule,
  writeGrokIntegration,
  applyOrgPolicy,
  applyOrgPolicyYaml,
  applyRetention,
  applyRetentionYaml,
  applyAutoPrune,
  applyAutoPruneYaml,
} from './commands/init.js';
export { cmdCapture } from './commands/capture.js';
export { cmdWrap } from './commands/wrap.js';
export { cmdShare } from './commands/share.js';
export { cmdAudit } from './commands/audit.js';
export { cmdPrune } from './commands/prune.js';
export { maybeAutoPrune, autoPruneGateFields } from './lib/auto-prune.js';
export { cmdExport, cmdHtml } from './commands/export.js';
export { cmdShow, resolveReceiptPath, findLatestReceipt } from './commands/show.js';
export { cmdLast } from './commands/last.js';
export { cmdHistory } from './commands/history.js';
export { cmdWatch, clampInterval } from './commands/watch.js';
export { cmdVerify } from './commands/verify.js';
export { cmdVerifyPackage } from './commands/verify-package.js';
export { cmdImport } from './commands/import.js';
export { cmdProve } from './commands/prove.js';
export { cmdKeygen } from './commands/keygen.js';
export { cmdSign } from './commands/sign.js';
export { cmdTrust } from './commands/trust.js';
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
  hasTrailingAfterIntegrity,
} from './lib/hash.js';
export {
  fingerprint,
  loadKeys,
  ensureKeyDir,
  verifySignature,
  signaturePathFor,
  inspectReceiptSignature,
  isLocalKeyMaterialPath,
  createSignatureDocument,
  handoffMarkdownSignature,
  signIfKeys,
} from './lib/sign.js';
export {
  loadTrustedFingerprints,
  isFingerprintTrusted,
  checkTrusted,
  applyTrust,
  TRUSTED_KEYS_REL,
} from './lib/trust.js';
export {
  analyzeRisks,
  summarizeRisks,
  topRisks,
  sortRisks,
  parseFailOn,
  meetsFailOn,
  parseRiskSummaryMarkdown,
  parseRiskAllowlist,
  applyRiskAllowlist,
  shannonEntropy,
} from './lib/risk.js';
export { summarizeNotableChanges, formatDiffStatTable } from './lib/summary.js';
export { formatMarkdown, formatJson, formatTldr, extractTldr, buildReviewItems } from './lib/receipt.js';
export { finalizeGate, printGate, errorGate, gateExitCode } from './lib/gate.js';
export {
  redactSecretsInText,
  redactMarkdownBody,
  prepareRedactedBody,
  isReceiptArtifactPath,
} from './lib/redact.js';
export { markdownToHtml } from './lib/html.js';
export { renderProveHtml, defangUrls } from './lib/prove-html.js';
export { CURSOR_RULE_MDC, CURSOR_RULE_REL } from './lib/cursor-rule.js';
export {
  GROK_RULE_MD,
  GROK_RULE_REL,
  GROK_HOOK_JSON,
  GROK_HOOK_REL,
  GROK_WRAP_SCRIPT,
  GROK_WRAP_SCRIPT_REL,
} from './lib/grok-rule.js';
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
  appendAuditEvent,
  recordAuditEvent,
  verifyAuditChain,
  loadAuditEvents,
  auditLogPath,
  AUDIT_REL,
} from './lib/audit.js';
export type { AuditKind, AuditEvent } from './lib/audit.js';

export {
  loadIndex,
  updateIndexOnCapture,
  indexPath,
  INDEX_REL,
  isInsideOutDir,
  receiptsDir,
  readIndexStrict,
  writeIndexAtomic,
} from './lib/receipt-index.js';
export {
  planRetention,
  listReceiptFiles,
  resolveRetentionPolicy,
  retentionCheck,
  outDirUnderPressure,
  DISK_PRESSURE_BYTES,
  DISK_PRESSURE_COUNT,
} from './lib/retention.js';
export {
  isDirty,
  dirtyFingerprint,
  getWorkingTreeFiles,
  resolveRange,
  countCommitsAhead,
} from './lib/git.js';
