import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseNestedYaml } from './nested-yaml.js';
import { globPatternError } from './ignore.js';

export interface AgentReceiptConfig {
  outDir: string;
  defaultAgent: string;
  defaultCommits: number;
  fullDiffs: boolean;
  /** Path globs excluded from risk / summary / file tables (noise). */
  ignore: string[];
  /**
   * Risk findings to ignore: `code`, `code:pathGlob`, or `*:pathGlob`.
   * Example: `package-json-change`, `lockfile-change:*.lock`, `*:docs/**`
   */
  riskAllowlist: string[];
  /**
   * When true, capture / wrap / watch / share redact unless `--no-redact`.
   * Default false. `share` still redacts unless `--no-redact` even when this is false.
   */
  redact: boolean;
  /** Set when `redact:` is present but not a boolean. */
  redactInvalid?: boolean;
  /**
   * When true, capture / wrap / watch sign after a successful write when
   * local Ed25519 keys exist. Absent or false keeps signing opt-in.
   * CLI `--no-sign` wins, then `--sign`. Missing keys print a tip and
   * leave the receipt unsigned (that does not exit 2). share, export,
   * prove, and verify ignore this key. `init --org` does not set it.
   */
  sign?: boolean;
  /** Set when `sign:` is present but not a boolean. */
  signInvalid?: boolean;
  /**
   * When true, capture / wrap / watch run trusted prune after a successful
   * write if `maxCount` and/or `maxAgeDays` is set. Absent or false: those
   * commands never delete. `autoPrune: true` with no retention limit deletes
   * nothing. CLI `--no-prune` wins, then `--prune`. Auto-prune does not pass
   * `--force`. A broken audit chain skips the delete, warns on stderr, and
   * does not fail the capture. share, export, verify, prove, import, and
   * doctor do not delete. `init --retention` does not set this key.
   * Not a long-running daemon.
   */
  autoPrune?: boolean;
  /** Set when `autoPrune:` is present but not a boolean. */
  autoPruneInvalid?: boolean;
  /**
   * Default `--fail-on` for capture / wrap / watch / share.
   * `verify` ignores this unless `--fail-on` is passed explicitly.
   * Invalid values are kept so `doctor` / `validateConfig` can report them.
   */
  failOn?: string;
  /**
   * Keep at most this many receipts under outDir. Unset = no count cap.
   * `prune` deletes when a limit is set. capture / wrap / watch do too
   * when `autoPrune` is true (same trusted path, no `--force`).
   */
  maxCount?: number;
  /** Delete receipts strictly older than this many days. Unset = no age cap. */
  maxAgeDays?: number;
  /** Set when maxCount / maxAgeDays were present but not integers >= 1. */
  retentionInvalid?: string[];
  /**
   * Known-key allowlist (lowercase 64-hex fingerprints). Union with
   * `.agent-receipt/trusted-keys.txt`. Undefined when the key is absent.
   * An empty array means the key was set but listed nothing (allowlist inactive).
   */
  trustedFingerprints?: string[];
  /** Set when `trustedFingerprints` was present but an entry was not 64 hex. */
  trustedFingerprintsInvalid?: string;
  /**
   * Policy pack refs (`builtin:baseline` or a file path). Absent when the
   * key is not set. An empty list means the key was set and names nothing.
   */
  policyPacks?: string[];
  /**
   * Per-repo exceptions. `expires` is inclusive (YYYY-MM-DD, UTC). An
   * expired exception does not suppress a hit.
   */
  policyExceptions?: PolicyException[];
  /**
   * Set when `policyPacks` / `policyExceptions` were present but invalid.
   * Not reported by `validateConfig` (doctor's config row stays independent).
   * The gate and `doctor --strict` fail closed on this string.
   */
  policyConfigInvalid?: string;
}

export interface PolicyException {
  rule: string;
  path: string;
  reason: string;
  expires?: string;
}

const FP64 = /^[0-9a-f]{64}$/;

const DEFAULTS: AgentReceiptConfig = {
  outDir: '.agent-receipt/receipts',
  defaultAgent: 'agent',
  defaultCommits: 1,
  fullDiffs: false,
  ignore: ['node_modules/**', 'dist/**', 'coverage/**'],
  riskAllowlist: [],
  redact: false,
  sign: false,
  autoPrune: false,
};

const CONFIG_NAME = '.agent-receipt.yml';

export function configPath(cwd: string): string {
  return join(cwd, CONFIG_NAME);
}

type YamlValue = string | number | boolean | string[];

/**
 * Tiny YAML subset reader:
 * - key: value (string / bool / number)
 * - key: followed by indented `- item` list lines
 * - key: a, b, c  (comma-separated → string[])
 */
export function parseSimpleYaml(text: string): Record<string, YamlValue> {
  const out: Record<string, YamlValue> = {};
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    const stripped = raw.replace(/#.*$/, '');
    const line = stripped.trimEnd();
    const trimmed = line.trim();
    i++;
    if (!trimmed || trimmed.startsWith('---')) continue;

    const m = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    let val = m[2].trim();

    // Block list: key:\n  - a\n  - b
    if (val === '' || val === '|' || val === '>') {
      const items: string[] = [];
      while (i < lines.length) {
        const next = lines[i].replace(/#.*$/, '');
        if (!next.trim()) {
          i++;
          continue;
        }
        const listMatch = next.match(/^\s+-\s+(.*)$/);
        if (!listMatch) break;
        let item = listMatch[1].trim();
        if (
          (item.startsWith('"') && item.endsWith('"')) ||
          (item.startsWith("'") && item.endsWith("'"))
        ) {
          item = item.slice(1, -1);
        }
        items.push(item);
        i++;
      }
      out[key] = items;
      continue;
    }

    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }

    if (val === 'true') out[key] = true;
    else if (val === 'false') out[key] = false;
    else if (/^-?\d+$/.test(val)) out[key] = parseInt(val, 10);
    else if (val.includes(',') && (key === 'ignore' || key === 'riskAllowlist' || key.endsWith('Ignore'))) {
      out[key] = val.split(',').map((s) => s.trim()).filter(Boolean);
    } else if (val.startsWith('[') && val.endsWith(']')) {
      const inner = val.slice(1, -1).trim();
      out[key] = inner
        ? inner.split(',').map((s) => {
            let t = s.trim();
            if (
              (t.startsWith('"') && t.endsWith('"')) ||
              (t.startsWith("'") && t.endsWith("'"))
            ) {
              t = t.slice(1, -1);
            }
            return t;
          })
        : [];
    } else {
      out[key] = val;
    }
  }
  return out;
}

function parseRetentionInt(
  value: YamlValue | undefined,
  key: string,
  problems: string[],
): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'number' && Number.isInteger(value) && value >= 1) return value;
  problems.push(`${key} must be an integer >= 1`);
  return undefined;
}

const EXCEPTION_KEYS = new Set(['rule', 'path', 'reason', 'expires']);

function validIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split('-').map((part) => parseInt(part, 10));
  if (!year || !month || !day) return false;
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
  );
}

/**
 * Read `policyPacks` / `policyExceptions` with the nested parser.
 * Files that do not mention those keys skip it, so existing flat configs
 * keep the simple reader.
 */
function readPolicyOverlay(text: string): {
  policyPacks?: string[];
  policyExceptions?: PolicyException[];
  policyConfigInvalid?: string;
} {
  if (!/(^|\n)\s*policyPacks\s*:/.test(text) && !/(^|\n)\s*policyExceptions\s*:/.test(text)) {
    return {};
  }
  let tree: unknown;
  try {
    tree = parseNestedYaml(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { policyConfigInvalid: `policy config is invalid: ${message}` };
  }
  if (!tree || typeof tree !== 'object' || Array.isArray(tree)) {
    return { policyConfigInvalid: 'policy config is invalid: document must be a map' };
  }
  const rec = tree as Record<string, unknown>;
  let policyPacks: string[] | undefined;
  if (rec.policyPacks !== undefined) {
    const raw = rec.policyPacks;
    const items = Array.isArray(raw) ? raw : typeof raw === 'string' ? [raw] : null;
    if (!items) {
      return { policyConfigInvalid: 'policy config is invalid: policyPacks must be a list of pack names' };
    }
    const packs: string[] = [];
    for (const item of items) {
      if (typeof item !== 'string' || !item.trim()) {
        return {
          policyConfigInvalid: 'policy config is invalid: policyPacks entries must be non-empty strings',
        };
      }
      packs.push(item.trim());
    }
    policyPacks = packs;
  }
  let policyExceptions: PolicyException[] | undefined;
  if (rec.policyExceptions !== undefined) {
    if (!Array.isArray(rec.policyExceptions)) {
      return { policyConfigInvalid: 'policy config is invalid: policyExceptions must be a list' };
    }
    const exceptions: PolicyException[] = [];
    for (const entry of rec.policyExceptions) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        return { policyConfigInvalid: 'policy config is invalid: a policy exception must be a map' };
      }
      const obj = entry as Record<string, unknown>;
      for (const key of Object.keys(obj)) {
        if (!EXCEPTION_KEYS.has(key)) {
          return { policyConfigInvalid: `policy config is invalid: unknown policy exception key ${key}` };
        }
      }
      const rule = typeof obj.rule === 'string' ? obj.rule.trim() : '';
      const path = typeof obj.path === 'string' ? obj.path.trim() : '';
      const reason = typeof obj.reason === 'string' ? obj.reason.trim() : '';
      if (!rule) {
        return { policyConfigInvalid: 'policy config is invalid: policy exception rule is required' };
      }
      if (!path) {
        return { policyConfigInvalid: 'policy config is invalid: policy exception path is required' };
      }
      if (!reason) {
        return { policyConfigInvalid: 'policy config is invalid: policy exception reason is required' };
      }
      const globErr = globPatternError(path);
      if (globErr) {
        return { policyConfigInvalid: `policy config is invalid: policy exception path ${globErr}` };
      }
      let expires: string | undefined;
      if (obj.expires !== undefined && obj.expires !== null && obj.expires !== '') {
        const rawDate = typeof obj.expires === 'string' ? obj.expires.trim() : '';
        if (!validIsoDate(rawDate)) {
          return {
            policyConfigInvalid: 'policy config is invalid: policy exception expires must be YYYY-MM-DD',
          };
        }
        expires = rawDate;
      }
      exceptions.push(expires ? { rule, path, reason, expires } : { rule, path, reason });
    }
    policyExceptions = exceptions;
  }
  return { policyPacks, policyExceptions };
}

function asStringList(v: YamlValue | undefined, fallback: string[]): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string' && v.trim()) {
    return v.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return [...fallback];
}

export function loadConfig(cwd: string): AgentReceiptConfig {
  const path = configPath(cwd);
  if (!existsSync(path)) {
    return {
      ...DEFAULTS,
      ignore: [...DEFAULTS.ignore],
      riskAllowlist: [...DEFAULTS.riskAllowlist],
    };
  }
  const text = readFileSync(path, 'utf8');
  const parsed = parseSimpleYaml(text);
  const policy = readPolicyOverlay(text);
  let redact = DEFAULTS.redact;
  let redactInvalid = false;
  if (parsed.redact !== undefined) {
    if (typeof parsed.redact === 'boolean') redact = parsed.redact;
    else redactInvalid = true;
  }
  let sign = DEFAULTS.sign;
  let signInvalid = false;
  if (parsed.sign !== undefined) {
    if (typeof parsed.sign === 'boolean') sign = parsed.sign;
    else signInvalid = true;
  }
  let autoPrune = DEFAULTS.autoPrune;
  let autoPruneInvalid = false;
  if (parsed.autoPrune !== undefined) {
    if (typeof parsed.autoPrune === 'boolean') autoPrune = parsed.autoPrune;
    else autoPruneInvalid = true;
  }
  let failOn: string | undefined;
  if (parsed.failOn === undefined || parsed.failOn === false || parsed.failOn === '') {
    failOn = undefined;
  } else if (parsed.failOn === true) {
    failOn = 'high';
  } else {
    failOn = String(parsed.failOn).toLowerCase();
  }
  const retentionInvalid: string[] = [];
  const maxCount = parseRetentionInt(parsed.maxCount, 'maxCount', retentionInvalid);
  const maxAgeDays = parseRetentionInt(parsed.maxAgeDays, 'maxAgeDays', retentionInvalid);
  let trustedFingerprints: string[] | undefined;
  let trustedFingerprintsInvalid: string | undefined;
  if (parsed.trustedFingerprints !== undefined) {
    const raw = parsed.trustedFingerprints;
    let items: string[] = [];
    if (Array.isArray(raw)) items = raw.map(String);
    else if (typeof raw === 'string') {
      items = raw.split(',').map((s) => s.trim()).filter(Boolean);
    } else {
      trustedFingerprintsInvalid =
        'trustedFingerprints must be a list of 64-hex fingerprints';
    }
    if (!trustedFingerprintsInvalid) {
      const good: string[] = [];
      for (const item of items) {
        const fp = item.trim().toLowerCase();
        if (!FP64.test(fp)) {
          trustedFingerprintsInvalid = `invalid trustedFingerprints entry: expected 64 hex chars (${item})`;
          break;
        }
        good.push(fp);
      }
      if (!trustedFingerprintsInvalid) trustedFingerprints = good;
    }
  }
  return {
    outDir: String(parsed.outDir ?? DEFAULTS.outDir),
    defaultAgent: String(parsed.defaultAgent ?? DEFAULTS.defaultAgent),
    defaultCommits:
      typeof parsed.defaultCommits === 'number'
        ? parsed.defaultCommits
        : DEFAULTS.defaultCommits,
    fullDiffs:
      typeof parsed.fullDiffs === 'boolean' ? parsed.fullDiffs : DEFAULTS.fullDiffs,
    ignore: asStringList(parsed.ignore, DEFAULTS.ignore),
    riskAllowlist: asStringList(parsed.riskAllowlist, DEFAULTS.riskAllowlist),
    redact,
    redactInvalid: redactInvalid || undefined,
    sign,
    signInvalid: signInvalid || undefined,
    autoPrune,
    autoPruneInvalid: autoPruneInvalid || undefined,
    failOn,
    maxCount,
    maxAgeDays,
    retentionInvalid: retentionInvalid.length ? retentionInvalid : undefined,
    trustedFingerprints,
    trustedFingerprintsInvalid,
    policyPacks: policy.policyPacks,
    policyExceptions: policy.policyExceptions,
    policyConfigInvalid: policy.policyConfigInvalid,
  };
}

/** Validate a loaded / parsed config; returns list of human-readable problems. */
export function validateConfig(cfg: AgentReceiptConfig): string[] {
  const problems: string[] = [];
  if (!cfg.outDir || typeof cfg.outDir !== 'string') {
    problems.push('outDir must be a non-empty string');
  }
  // Same rules as --agent: free-form, one line, max 256. Spaces are allowed.
  if (typeof cfg.defaultAgent !== 'string' || !cfg.defaultAgent.trim()) {
    problems.push('defaultAgent must be a non-empty string');
  } else if (
    cfg.defaultAgent.trim().length > 256 ||
    /[\u0000-\u001f\u007f\u2028\u2029]/.test(cfg.defaultAgent)
  ) {
    problems.push(
      'defaultAgent must be a single line of at most 256 characters, with no newlines or control characters (same rules as --agent)',
    );
  }
  if (typeof cfg.defaultCommits !== 'number' || cfg.defaultCommits < 1) {
    problems.push('defaultCommits must be an integer >= 1');
  }
  if (typeof cfg.fullDiffs !== 'boolean') {
    problems.push('fullDiffs must be a boolean');
  }
  if (!Array.isArray(cfg.ignore)) {
    problems.push('ignore must be a list of globs');
  } else {
    for (const g of cfg.ignore) {
      if (typeof g !== 'string' || !g.trim()) {
        problems.push('ignore entries must be non-empty strings');
        break;
      }
    }
  }
  if (!Array.isArray(cfg.riskAllowlist)) {
    problems.push('riskAllowlist must be a list of strings');
  } else {
    for (const g of cfg.riskAllowlist) {
      if (typeof g !== 'string' || !g.trim()) {
        problems.push('riskAllowlist entries must be non-empty strings');
        break;
      }
    }
  }
  if (typeof cfg.redact !== 'boolean' || cfg.redactInvalid) {
    problems.push('redact must be true or false');
  }
  if (cfg.signInvalid || (cfg.sign !== undefined && typeof cfg.sign !== 'boolean')) {
    problems.push('sign must be true or false');
  }
  if (
    cfg.autoPruneInvalid ||
    (cfg.autoPrune !== undefined && typeof cfg.autoPrune !== 'boolean')
  ) {
    problems.push('autoPrune must be true or false');
  }
  if (
    cfg.failOn !== undefined &&
    cfg.failOn !== 'high' &&
    cfg.failOn !== 'medium' &&
    cfg.failOn !== 'low'
  ) {
    problems.push('failOn must be high, medium, or low');
  }
  if (cfg.retentionInvalid?.length) {
    problems.push(...cfg.retentionInvalid);
  }
  if (cfg.maxCount !== undefined && (!Number.isInteger(cfg.maxCount) || cfg.maxCount < 1)) {
    problems.push('maxCount must be an integer >= 1');
  }
  if (
    cfg.maxAgeDays !== undefined &&
    (!Number.isInteger(cfg.maxAgeDays) || cfg.maxAgeDays < 1)
  ) {
    problems.push('maxAgeDays must be an integer >= 1');
  }
  return problems;
}

export function writeDefaultConfig(cwd: string): { configFile: string; notesFile: string } {
  const configFile = configPath(cwd);
  const yaml = `# agent-receipt configuration
# https://github.com/pramodreddyboddu/agent-receipt

outDir: .agent-receipt/receipts
defaultAgent: agent
defaultCommits: 1
fullDiffs: false

# Path globs excluded from risk / summary / file tables (noise).
# node_modules / dist / coverage are defaults; add lockfile noise if desired:
#   - "*.lock"
#   - package-lock.json
ignore:
  - node_modules/**
  - dist/**
  - coverage/**

# Risk findings to suppress (code, code:pathGlob, or *:pathGlob).
# Examples:
#   - package-json-change
#   - "lockfile-change:*.lock"
#   - "*:docs/**"
riskAllowlist: []

# Optional org defaults (off unless set). \`agent-receipt init --org\`
# enables these two keys without replacing ignore. See examples/org-policy.yml
# and docs/business.md. share still redacts unless you pass --no-redact.
# redact: true
# failOn: high
#
# Optional signing default for capture / wrap / watch. init --org does
# not set this (keys may be absent). After \`keygen\` and \`trust add --self\`,
# uncomment the next line. CLI --no-sign overrides. Missing keys print a
# tip and leave the receipt unsigned (not exit 2). Not a CA. share,
# export, prove, and verify ignore this key. CI composite sign: true
# stays fail-closed and is independent of this key.
# sign: true  # after keygen; CLI --no-sign overrides

# Retention is opt-in. Nothing is deleted until you set maxCount and/or
# maxAgeDays. \`agent-receipt init --retention\` sets both keys
# (100 receipts / 30 days) and does not turn autoPrune on.
# \`agent-receipt prune\` applies the limits (preview with \`--dry-run\`).
# \`autoPrune: true\` (or \`init --auto-prune\`) runs that same trusted prune
# after a successful capture, wrap, or watch. Both are required.
# CLI \`--no-prune\` wins, then \`--prune\`. Auto-prune does not pass
# \`--force\`. A broken audit chain skips the delete, warns, and does
# not fail the capture. Manual \`prune --force\` is break-glass.
# Not a daemon.
# maxCount: 100
# maxAgeDays: 30
# autoPrune: true

# Fingerprint trust store (known-keys allowlist). Opt-in. Not a CA.
# Union with .agent-receipt/trusted-keys.txt (one lowercase 64-hex
# fingerprint per line; # comments and blank lines ignored).
# Empty or omitted = allowlist inactive: verify --require-sig accepts
# any cryptographically valid sidecar. Copy a committed example in
# from examples/ or docs/ when the list should stay out of this
# gitignored directory.
# trustedFingerprints: []

# Policy packs (docs/policy-packs.md). Refs are builtin:<name> or a file.
# Deny hits fail capture / wrap / share / verify / pr-comment (exit 2).
# Warn hits are reported only. A missing or invalid pack fails closed.
# policyPacks:
#   - builtin:baseline
# policyExceptions:
#   - rule: secrets-files
#     path: "**/.env.example"
#     reason: templates are not secrets
#     expires: 2099-01-01
`;
  writeFileSync(configFile, yaml, 'utf8');

  const dir = join(cwd, '.agent-receipt');
  mkdirSync(dir, { recursive: true });
  const notesFile = join(dir, 'SETUP.md');
  const notes = `# agent-receipt setup

1. Config written to \`.agent-receipt.yml\`.
2. Receipts default to \`.agent-receipt/receipts/\`.
3. Capture a receipt after an agent session:

   \`\`\`bash
   agent-receipt capture --agent cursor --message "refactor auth"
   agent-receipt history
   agent-receipt last
   agent-receipt verify
   \`\`\`

4. Optional: auto-capture on every commit (safe, uninstallable):

   \`\`\`bash
   agent-receipt install-hooks
   \`\`\`

5. Wait for the next commit, capture once (Cursor / agent wrap-up):

   \`\`\`bash
   agent-receipt watch --once --agent cursor --message "session wrap-up"
   \`\`\`

6. Cursor: \`agent-receipt init --cursor\` drops \`.cursor/rules/agent-receipt.mdc\`
   so the agent runs capture itself at session end.

7. Grok Build: \`agent-receipt init --grok\` drops \`.grok/rules/agent-receipt.md\`
   and a SessionEnd hook. After a session:

   \`\`\`bash
   agent-receipt wrap --agent grok --redact --message "what changed"
   \`\`\`

   Recipe: \`docs/grok-cli.md\` in the agent-receipt package.

8. Health check (includes a short prod-ready checklist): \`agent-receipt doctor\`
   \`agent-receipt doctor --strict\` fails when org policy is unset, even on a small outDir.
   \`agent-receipt init --org\` sets \`redact: true\` and \`failOn: high\`.
   It does not set \`sign\` (keys may be absent). After \`keygen\` and
   \`trust add --self\`, add \`sign: true\`. CLI \`--no-sign\` overrides.

9. CI / hooks that should fail on secrets. Exit 0 pass, 2 policy or verify
   failure, 1 usage error. \`--json\` on capture/wrap/share/verify prints one
   object on stdout:

   \`\`\`bash
   agent-receipt wrap --base main --fail-on high --json
   \`\`\`

10. Share a redacted HTML receipt (verifies, prints paths + TL;DR):

    \`\`\`bash
    agent-receipt share --out share.html
    agent-receipt share --md share.md --out share.html
    \`\`\`

11. Team rollout, org policy, CI gate examples, audit log, and retention:
    \`docs/business.md\` in the agent-receipt package.
    \`agent-receipt init --org\` sets \`redact: true\` and \`failOn: high\` on this file
    without replacing \`ignore\`. Copy \`examples/org-policy.yml\` when you want
    the full commented example as a starting point.

12. \`capture\`, \`watch\`, \`wrap\`, \`share\`, and \`export\` append
    \`.agent-receipt/audit.jsonl\` (experimental hash chain, not a signature).
    \`agent-receipt audit --verify\` checks it. The log has no diff bodies
    and no session \`--message\`.

13. Retention is opt-in. \`agent-receipt init --retention\` sets
    \`maxCount: 100\` and \`maxAgeDays: 30\` and does not turn
    \`autoPrune\` on. Add \`autoPrune: true\` or run
    \`agent-receipt init --auto-prune\` so capture, wrap, and watch
    delete after a successful write (same trusted prune, no \`--force\`).
    A broken audit chain skips that delete and does not fail the capture.
    Preview with \`agent-receipt prune --dry-run\`, then
    \`agent-receipt prune\`. Manual prune exits 1 on a broken chain
    (\`prune --force\` is break-glass). See \`docs/business.md\`.

14. Agent-specific tips: see \`docs/agents.md\` in the package / repo.

15. Add \`.agent-receipt/\` to git if you want receipts committed, or keep
    them local / CI-artifact-only. See retention notes in \`docs/business.md\`.
`;
  writeFileSync(notesFile, notes, 'utf8');
  return { configFile, notesFile };
}

export function ensureOutDir(cwd: string, outDir: string): string {
  const abs = outDir.startsWith('/') ? outDir : join(cwd, outDir);
  mkdirSync(abs, { recursive: true });
  return abs;
}

export { DEFAULTS, CONFIG_NAME };
