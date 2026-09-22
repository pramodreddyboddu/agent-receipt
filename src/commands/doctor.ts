import { existsSync, accessSync, constants, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { getPorcelainStatus, isGitRepo, runGit } from '../lib/git.js';
import {
  loadConfig,
  validateConfig,
  configPath,
  CONFIG_NAME,
  type AgentReceiptConfig,
} from '../lib/config.js';
import { MARKER_BEGIN } from './hooks.js';
import { CURSOR_RULE_REL } from '../lib/cursor-rule.js';
import {
  GROK_HOOK_REL,
  GROK_RULE_REL,
  GROK_WRAP_SCRIPT_REL,
} from '../lib/grok-rule.js';
import { VERSION } from '../lib/version.js';
import { color } from '../lib/color.js';
import { auditLogPath, verifyAuditChain } from '../lib/audit.js';
import { outDirUnderPressure, retentionCheck } from '../lib/retention.js';

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'info';

export interface DoctorOptions {
  /**
   * Exit non-zero when org policy (redact + failOn) and/or retention is unset
   * AND outDir is under pressure (100 receipts or 20 MB). Default doctor
   * leaves those rows WARN/INFO. This is not the CI `--fail-on` risk gate.
   */
  strict?: boolean;
}

export interface DoctorCheck {
  name: string;
  status: CheckStatus;
  detail: string;
}

function nodeMajor(): number {
  const m = /^v(\d+)/.exec(process.version);
  return m ? parseInt(m[1], 10) : 0;
}

function gitAvailable(): { ok: boolean; version?: string; error?: string } {
  try {
    const v = execFileSync('git', ['--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    return { ok: true, version: v };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function hooksInstalled(cwd: string): {
  postCommit: boolean;
  prePush: boolean;
  hooksPath: string;
} {
  let hooksPath = join(cwd, '.git', 'hooks');
  try {
    const custom = runGit(['rev-parse', '--git-path', 'hooks'], cwd);
    hooksPath = custom.startsWith('/') ? custom : join(cwd, custom);
  } catch {
    /* use default */
  }
  const hasMarker = (name: string): boolean => {
    const p = join(hooksPath, name);
    if (!existsSync(p)) return false;
    try {
      return readFileSync(p, 'utf8').includes(MARKER_BEGIN);
    } catch {
      return false;
    }
  };
  return {
    postCommit: hasMarker('post-commit'),
    prePush: hasMarker('pre-push'),
    hooksPath,
  };
}

function orgPolicyUnset(cfg: AgentReceiptConfig): boolean {
  if (cfg.redactInvalid) return false;
  const failOnOk =
    cfg.failOn === 'high' || cfg.failOn === 'medium' || cfg.failOn === 'low';
  if (cfg.failOn !== undefined && !failOnOk) return false;
  return !(cfg.redact === true && failOnOk);
}

function retentionLimitsUnset(cfg: AgentReceiptConfig): boolean {
  if (cfg.retentionInvalid?.length) return false;
  return cfg.maxCount == null && cfg.maxAgeDays == null;
}

/**
 * Promote unset policy / retention to FAIL only when the receipt dir is large
 * enough that leaving them off is a prod gap. No pressure → rows stay as-is.
 */
function applyStrictPressureGate(cwd: string, checks: DoctorCheck[]): DoctorCheck[] {
  let pressured = false;
  try {
    pressured = outDirUnderPressure(cwd);
  } catch {
    pressured = false;
  }
  if (!pressured) return checks;
  const cfg = loadConfig(cwd);
  return checks.map((c) => {
    if (c.name === 'policy' && c.status !== 'fail' && orgPolicyUnset(cfg)) {
      return {
        ...c,
        status: 'fail',
        detail:
          c.detail +
          ' Strict: set redact: true and failOn while outDir is under pressure (100 receipts or 20 MB). Not a substitute for CI --fail-on.',
      };
    }
    if (
      c.name === 'retention' &&
      (c.status === 'warn' || c.status === 'info') &&
      retentionLimitsUnset(cfg)
    ) {
      return {
        ...c,
        status: 'fail',
        detail:
          c.detail +
          ' Strict: set maxCount and/or maxAgeDays while outDir is under pressure.',
      };
    }
    return c;
  });
}

export function runDoctorChecks(cwd: string, opts: DoctorOptions = {}): DoctorCheck[] {
  const checks: DoctorCheck[] = [];

  // Node version
  const major = nodeMajor();
  if (major >= 20) {
    checks.push({
      name: 'node',
      status: 'pass',
      detail: `${process.version} (>= 20 required)`,
    });
  } else {
    checks.push({
      name: 'node',
      status: 'fail',
      detail: `${process.version} — need Node.js >= 20`,
    });
  }

  // git present
  const git = gitAvailable();
  if (git.ok) {
    checks.push({
      name: 'git',
      status: 'pass',
      detail: git.version || 'git found on PATH',
    });
  } else {
    checks.push({
      name: 'git',
      status: 'fail',
      detail: `git not found on PATH (${git.error || 'missing'})`,
    });
  }

  // inside repo
  const inRepo = isGitRepo(cwd);
  if (inRepo) {
    let branch = '?';
    try {
      branch = runGit(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
    } catch {
      /* ignore */
    }
    checks.push({
      name: 'repo',
      status: 'pass',
      detail: `inside git work tree (branch: ${branch})`,
    });
  } else {
    checks.push({
      name: 'repo',
      status: 'fail',
      detail: `not a git repository (${cwd}) — run git init or pass --cwd`,
    });
  }

  // config
  const cfgFile = configPath(cwd);
  if (!existsSync(cfgFile)) {
    checks.push({
      name: 'config',
      status: 'warn',
      detail: `${CONFIG_NAME} missing — defaults will be used (run: agent-receipt init)`,
    });
  } else {
    const cfg = loadConfig(cwd);
    const problems = validateConfig(cfg);
    if (problems.length) {
      checks.push({
        name: 'config',
        status: 'fail',
        detail: `${CONFIG_NAME} invalid: ${problems.join('; ')}`,
      });
    } else {
      const redactBit = cfg.redact ? 'redact=on' : 'redact=off';
      const failBit = cfg.failOn ? `failOn=${cfg.failOn}` : 'failOn=unset';
      const retainBit =
        cfg.maxCount != null || cfg.maxAgeDays != null
          ? `maxCount=${cfg.maxCount ?? '—'}, maxAgeDays=${cfg.maxAgeDays ?? '—'}`
          : 'retention=off';
      checks.push({
        name: 'config',
        status: 'pass',
        detail: `${CONFIG_NAME} ok (outDir=${cfg.outDir}, ignore=${cfg.ignore.length} glob(s), ${redactBit}, ${failBit}, ${retainBit})`,
      });
    }
  }

  // hooks (optional)
  if (inRepo) {
    const hooks = hooksInstalled(cwd);
    if (hooks.postCommit) {
      const extra = hooks.prePush ? ' + pre-push' : '';
      checks.push({
        name: 'hooks',
        status: 'pass',
        detail: `post-commit installed${extra} under ${hooks.hooksPath}`,
      });
    } else {
      checks.push({
        name: 'hooks',
        status: 'warn',
        detail: `no managed post-commit hook — optional: agent-receipt install-hooks`,
      });
    }
  } else {
    checks.push({
      name: 'hooks',
      status: 'info',
      detail: 'skipped (not in a git repo)',
    });
  }

  // outDir writable
  const cfg = loadConfig(cwd);
  const outAbs = cfg.outDir.startsWith('/') ? cfg.outDir : join(cwd, cfg.outDir);
  try {
    const parent = join(outAbs, '..');
    if (!existsSync(outAbs)) {
      // parent of outDir should be creatable; check cwd write
      accessSync(cwd, constants.W_OK);
      checks.push({
        name: 'outDir',
        status: 'info',
        detail: `${cfg.outDir} will be created on first capture`,
      });
    } else {
      accessSync(outAbs, constants.W_OK);
      checks.push({
        name: 'outDir',
        status: 'pass',
        detail: `${cfg.outDir} exists and is writable`,
      });
    }
  } catch {
    checks.push({
      name: 'outDir',
      status: 'fail',
      detail: `cannot write under ${cfg.outDir}`,
    });
  }

  // CLI version banner as info
  checks.push({
    name: 'cli',
    status: 'info',
    detail: `agent-receipt ${VERSION}`,
  });

  // Prod-ready checklist (informational — WARN/INFO do not fail doctor).
  const cfgNow = loadConfig(cwd);
  if (cfgNow.redact) {
    const failBit = cfgNow.failOn ? ` · failOn: ${cfgNow.failOn}` : '';
    checks.push({
      name: 'redact',
      status: 'pass',
      detail: `redact: true (default on for capture/wrap/watch/share)${failBit}`,
    });
  } else {
    const failBit = cfgNow.failOn
      ? ` Config failOn: ${cfgNow.failOn} still applies to capture/wrap/watch/share.`
      : '';
    checks.push({
      name: 'redact',
      status: 'info',
      detail:
        `redact default off (optional). Set redact: true in ${CONFIG_NAME} or pass --redact.` +
        ` share still redacts unless --no-redact. See examples/org-policy.yml.${failBit}`,
    });
  }

  const failOnOk =
    cfgNow.failOn === 'high' || cfgNow.failOn === 'medium' || cfgNow.failOn === 'low';
  if (cfgNow.redactInvalid || (cfgNow.failOn !== undefined && !failOnOk)) {
    checks.push({
      name: 'policy',
      status: 'info',
      detail: `skipped until ${CONFIG_NAME} is valid`,
    });
  } else if (cfgNow.redact && failOnOk) {
    checks.push({
      name: 'policy',
      status: 'pass',
      detail: `org policy: redact on, failOn=${cfgNow.failOn} (capture/wrap/watch/share)`,
    });
  } else {
    const missing: string[] = [];
    if (!cfgNow.redact) missing.push('redact: true');
    if (!failOnOk) missing.push('failOn: high');
    checks.push({
      name: 'policy',
      status: 'info',
      detail:
        `optional — set ${missing.join(' and ')} (copy examples/org-policy.yml).` +
        ' share still redacts unless --no-redact. CI should pass --fail-on anyway.',
    });
  }

  const auditFile = auditLogPath(cwd);
  if (existsSync(auditFile)) {
    const chain = verifyAuditChain(cwd);
    if (chain.ok && chain.events > 0) {
      checks.push({
        name: 'audit',
        status: 'pass',
        detail: `${chain.events} event(s), chain OK (experimental — not a signature)`,
      });
    } else if (chain.ok) {
      checks.push({
        name: 'audit',
        status: 'info',
        detail:
          'audit log present but empty — capture, watch, wrap, share, export, and prune (when it deletes) append a line each',
      });
    } else {
      const where = chain.brokenAt ? ` at line ${chain.brokenAt}` : '';
      checks.push({
        name: 'audit',
        status: 'warn',
        detail: `chain broken${where}: ${chain.reason} (agent-receipt audit --verify)`,
      });
    }
  } else {
    let writable = true;
    const auditDir = join(cwd, '.agent-receipt');
    if (existsSync(auditDir)) {
      try {
        accessSync(auditDir, constants.W_OK);
      } catch {
        writable = false;
      }
    }
    checks.push({
      name: 'audit',
      status: writable ? 'info' : 'warn',
      detail: writable
        ? 'no audit log yet — capture, watch, wrap, share, export, and prune (when it deletes) append .agent-receipt/audit.jsonl'
        : 'cannot write .agent-receipt/audit.jsonl',
    });
  }

  checks.push(retentionCheck(cwd, cfgNow));

  if (!inRepo) {
    checks.push({
      name: 'git-clean',
      status: 'info',
      detail: 'skipped (not in a git repo)',
    });
  } else {
    const lines = getPorcelainStatus(cwd).split('\n').filter((l) => l.trim());
    if (lines.length === 0) {
      checks.push({
        name: 'git-clean',
        status: 'pass',
        detail: 'working tree clean',
      });
    } else {
      checks.push({
        name: 'git-clean',
        status: 'warn',
        detail: `working tree dirty (${lines.length} path(s)) — commit, or wrap/capture --uncommitted, before a prod snapshot`,
      });
    }
  }

  const cursorPath = join(cwd, CURSOR_RULE_REL);
  if (existsSync(cursorPath)) {
    checks.push({
      name: 'cursor',
      status: 'pass',
      detail: `rule installed (${CURSOR_RULE_REL})`,
    });
  } else {
    checks.push({
      name: 'cursor',
      status: 'info',
      detail: 'not installed (optional) — agent-receipt init --cursor',
    });
  }

  const grokFiles = [GROK_RULE_REL, GROK_HOOK_REL, GROK_WRAP_SCRIPT_REL];
  const grokPresent = grokFiles.filter((rel) => existsSync(join(cwd, rel)));
  if (grokPresent.length === grokFiles.length) {
    checks.push({
      name: 'grok',
      status: 'pass',
      detail: 'rule + SessionEnd hook installed (stdin drained, then closed — open pipe cannot hang wrap)',
    });
  } else if (grokPresent.length > 0) {
    const missing = grokFiles.filter((rel) => !grokPresent.includes(rel));
    checks.push({
      name: 'grok',
      status: 'warn',
      detail: `partial init — missing ${missing.join(', ')} (re-run: agent-receipt init --grok)`,
    });
  } else {
    checks.push({
      name: 'grok',
      status: 'info',
      detail: 'not installed (optional) — agent-receipt init --grok',
    });
  }

  if (!opts.strict) return checks;
  return applyStrictPressureGate(cwd, checks);
}

function icon(status: CheckStatus): string {
  switch (status) {
    case 'pass':
      return color.green('PASS');
    case 'fail':
      return color.red('FAIL');
    case 'warn':
      return color.yellow('WARN');
    case 'info':
      return color.dim('INFO');
  }
}

const ENV_CHECKS = new Set(['node', 'git', 'repo', 'outDir', 'cli']);
const PROD_CHECKS = [
  'config',
  'hooks',
  'redact',
  'policy',
  'audit',
  'retention',
  'git-clean',
  'cursor',
  'grok',
];

function printCheck(c: DoctorCheck): void {
  console.log(`  [${icon(c.status)}] ${c.name.padEnd(10)} ${c.detail}`);
}

/**
 * Run environment health checks.
 * Exit 0 if no FAIL, exit 1 otherwise.
 * WARN/INFO are non-fatal, including unset org policy and retention.
 * `--strict` promotes those two rows to FAIL only when outDir is under
 * pressure (100 receipts or 20 MB). CI `--fail-on` remains the risk gate.
 */
export function cmdDoctor(cwd: string, opts: DoctorOptions = {}): number {
  console.log(color.bold(`agent-receipt doctor`) + color.dim(` (${VERSION})`));
  console.log(color.dim(`cwd: ${cwd}`));
  if (opts.strict) {
    console.log(
      color.dim(
        'strict: unset org policy (redact + failOn) and/or retention fail only when outDir is under pressure (100 receipts or 20 MB). CI --fail-on is still the risk gate.',
      ),
    );
  }
  console.log('');

  const checks = runDoctorChecks(cwd, opts);
  let fails = 0;
  let warns = 0;
  for (const c of checks) {
    if (c.status === 'fail') fails++;
    if (c.status === 'warn') warns++;
  }

  console.log(color.bold('Environment'));
  for (const c of checks) {
    if (ENV_CHECKS.has(c.name)) printCheck(c);
  }

  console.log('');
  console.log(color.bold('Prod ready'));
  for (const name of PROD_CHECKS) {
    const c = checks.find((item) => item.name === name);
    if (c) printCheck(c);
  }

  console.log('');
  if (fails === 0) {
    console.log(
      color.green('✓') +
        ` Ready` +
        (warns ? color.dim(` (${warns} warning${warns === 1 ? '' : 's'})`) : ''),
    );
    return 0;
  }
  console.log(
    color.red('✗') +
      ` ${fails} check${fails === 1 ? '' : 's'} failed — fix the FAIL items above.`,
  );
  return 1;
}
