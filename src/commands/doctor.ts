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
import { retentionCheck } from '../lib/retention.js';
import { loadKeys, privateKeyPath, publicKeyPath } from '../lib/sign.js';
import { inspectTrustForDoctor } from '../lib/trust.js';

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'info';

export interface DoctorOptions {
  /**
   * Exit non-zero when the audit chain is broken, when org policy
   * (`redact: true` and a valid `failOn`) is unset, and when retention
   * (`maxCount` / `maxAgeDays`) is unset — on any outDir size.
   * Default doctor leaves a broken chain as WARN and leaves unset policy
   * and retention as WARN/INFO (retention stays pressure-gated). This is
   * not the CI `--fail-on` risk gate.
   */
  strict?: boolean;
  /**
   * One JSON object on stdout. Does not change the exit code.
   * Human checklist stays the default when this is omitted.
   */
  json?: boolean;
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
 * Known-keys allowlist is opt-in. Missing stays INFO and does not fail
 * default doctor or `--strict`. A configured-but-empty store is WARN.
 * Invalid lines are WARN, and FAIL under `--strict`.
 */
function trustStoreCheck(cwd: string, strict: boolean): DoctorCheck {
  const view = inspectTrustForDoctor(cwd);
  if (view.kind === 'absent') {
    return { name: 'trust', status: 'info', detail: view.detail };
  }
  if (view.kind === 'ok') {
    return { name: 'trust', status: 'pass', detail: view.detail };
  }
  if (view.kind === 'empty') {
    return { name: 'trust', status: 'warn', detail: view.detail };
  }
  return {
    name: 'trust',
    status: strict ? 'fail' : 'warn',
    detail: strict
      ? `${view.detail}. Strict: an invalid trust store fails doctor.`
      : view.detail,
  };
}

/**
 * Local Ed25519 keys are optional. Missing keys stay INFO and do not fail
 * default doctor or `--strict`. A half pair or unreadable files are WARN.
 */
function signingKeysCheck(cwd: string): DoctorCheck {
  const havePriv = existsSync(privateKeyPath(cwd));
  const havePub = existsSync(publicKeyPath(cwd));
  if (!havePriv && !havePub) {
    return {
      name: 'keys',
      status: 'info',
      detail:
        'no local Ed25519 keys — optional: agent-receipt keygen (verify stays hash-only)',
    };
  }
  if (havePub && !havePriv) {
    return {
      name: 'keys',
      status: 'warn',
      detail: 'public key present but private key missing — agent-receipt keygen --force',
    };
  }
  if (havePriv && !havePub) {
    return {
      name: 'keys',
      status: 'warn',
      detail: 'private key present but public key missing — agent-receipt keygen --force',
    };
  }
  try {
    const keys = loadKeys(cwd);
    return {
      name: 'keys',
      status: 'pass',
      detail: `local Ed25519 key fingerprint ${keys.fingerprint}`,
    };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return {
      name: 'keys',
      status: 'warn',
      detail: `Ed25519 keys unreadable (${detail})`,
    };
  }
}

/**
 * Under `--strict`, unset org policy and unset retention are always FAIL
 * (any outDir size). A configured limit that would still delete stays WARN.
 * Default doctor does not call this.
 */
function applyStrictGates(cwd: string, checks: DoctorCheck[]): DoctorCheck[] {
  const cfg = loadConfig(cwd);
  return checks.map((c) => {
    if (c.name === 'policy' && c.status !== 'fail' && orgPolicyUnset(cfg)) {
      return {
        ...c,
        status: 'fail',
        detail:
          c.detail +
          ' Strict: set redact: true and failOn (agent-receipt init --org). Not a substitute for CI --fail-on.',
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
          ' Strict: set maxCount and/or maxAgeDays (agent-receipt init --retention). Unset retention fails --strict on any outDir.',
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
      const detail = `chain broken${where}: ${chain.reason} (agent-receipt audit --verify)`;
      // Broken chain is WARN by default. `--strict` promotes it to FAIL
      // even when outDir is small. Unset policy and unset retention fail
      // under --strict with no pressure gate. Default retention stays
      // pressure-gated.
      checks.push({
        name: 'audit',
        status: opts.strict ? 'fail' : 'warn',
        detail: opts.strict
          ? `${detail}. Strict: a broken audit chain fails doctor.`
          : detail,
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

  checks.push(signingKeysCheck(cwd));
  checks.push(trustStoreCheck(cwd, opts.strict === true));

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
  return applyStrictGates(cwd, checks);
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
  'keys',
  'trust',
  'retention',
  'git-clean',
  'cursor',
  'grok',
];

/** Human sections: Environment, then Prod ready. JSON `checks` uses this order. */
function checksInDisplayOrder(checks: DoctorCheck[]): DoctorCheck[] {
  const byName = new Map(checks.map((c) => [c.name, c]));
  const ordered: DoctorCheck[] = [];
  const take = (name: string) => {
    const c = byName.get(name);
    if (!c) return;
    ordered.push(c);
    byName.delete(name);
  };
  for (const name of ENV_CHECKS) take(name);
  for (const name of PROD_CHECKS) take(name);
  for (const c of checks) {
    if (byName.has(c.name)) ordered.push(c);
  }
  return ordered;
}

function printCheck(c: DoctorCheck): void {
  console.log(`  [${icon(c.status)}] ${c.name.padEnd(10)} ${c.detail}`);
}

/**
 * Run environment health checks.
 * Exit 0 if no FAIL, exit 1 otherwise.
 * WARN/INFO are non-fatal, including unset org policy and retention.
 * `--strict` promotes a broken audit chain, unset org policy
 * (redact + failOn), and unset retention (maxCount / maxAgeDays) to FAIL
 * on any outDir size. Default doctor still pressure-gates unset retention
 * (100 receipts or 20 MB). CI `--fail-on` remains the risk gate.
 * `--json` prints one object on stdout and does not change the exit code.
 */
export function cmdDoctor(cwd: string, opts: DoctorOptions = {}): number {
  const checks = runDoctorChecks(cwd, opts);
  let fails = 0;
  let warns = 0;
  for (const c of checks) {
    if (c.status === 'fail') fails++;
    if (c.status === 'warn') warns++;
  }
  const exitCode = fails === 0 ? 0 : 1;
  const ordered = checksInDisplayOrder(checks);

  if (opts.json) {
    console.log(
      JSON.stringify({
        ok: exitCode === 0,
        command: 'doctor',
        version: VERSION,
        exitCode,
        strict: opts.strict === true,
        checks: ordered.map((c) => ({
          id: c.name,
          status: c.status,
          detail: c.detail,
        })),
      }),
    );
    return exitCode;
  }

  console.log(color.bold(`agent-receipt doctor`) + color.dim(` (${VERSION})`));
  console.log(color.dim(`cwd: ${cwd}`));
  if (opts.strict) {
    console.log(
      color.dim(
        'strict: a broken audit chain fails. Unset org policy (redact + failOn) fails even when outDir is small (init --org). Unset retention (maxCount / maxAgeDays) fails on any outDir (init --retention). CI --fail-on is still the risk gate.',
      ),
    );
  }
  console.log('');

  console.log(color.bold('Environment'));
  for (const c of ordered) {
    if (ENV_CHECKS.has(c.name)) printCheck(c);
  }

  console.log('');
  console.log(color.bold('Prod ready'));
  for (const c of ordered) {
    if (PROD_CHECKS.includes(c.name)) printCheck(c);
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
  return exitCode;
}
