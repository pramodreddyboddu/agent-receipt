import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

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
   * Default `--fail-on` for capture / wrap / watch / share.
   * `verify` ignores this unless `--fail-on` is passed explicitly.
   * Invalid values are kept so `doctor` / `validateConfig` can report them.
   */
  failOn?: string;
  /**
   * Keep at most this many receipts under outDir. Unset = no count cap.
   * `prune` is the only command that deletes, and only when a limit is set.
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
  const parsed = parseSimpleYaml(readFileSync(path, 'utf8'));
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
    failOn,
    maxCount,
    maxAgeDays,
    retentionInvalid: retentionInvalid.length ? retentionInvalid : undefined,
    trustedFingerprints,
    trustedFingerprintsInvalid,
  };
}

/** Validate a loaded / parsed config; returns list of human-readable problems. */
export function validateConfig(cfg: AgentReceiptConfig): string[] {
  const problems: string[] = [];
  if (!cfg.outDir || typeof cfg.outDir !== 'string') {
    problems.push('outDir must be a non-empty string');
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

# Retention is opt-in. Nothing is deleted until you set one of these
# and run \`agent-receipt prune\` (preview with \`--dry-run\`).
# \`agent-receipt init --retention\` sets both keys (100 receipts / 30 days).
# Trusted prune refuses to delete when audit.jsonl exists and the chain
# is broken. \`prune --force\` deletes anyway. Capture / wrap / watch do not prune.
# maxCount: 100
# maxAgeDays: 30

# Fingerprint trust store (known-keys allowlist). Opt-in. Not a CA.
# Union with .agent-receipt/trusted-keys.txt (one lowercase 64-hex
# fingerprint per line; # comments and blank lines ignored).
# Empty or omitted = allowlist inactive: verify --require-sig accepts
# any cryptographically valid sidecar. Copy a committed example in
# from examples/ or docs/ when the list should stay out of this
# gitignored directory.
# trustedFingerprints: []
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
    \`maxCount: 100\` and \`maxAgeDays: 30\`. Preview with
    \`agent-receipt prune --dry-run\`, then \`agent-receipt prune\`.
    Trusted prune refuses to delete when the audit chain is broken
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
