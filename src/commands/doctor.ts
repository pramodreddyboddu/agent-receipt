import { existsSync, accessSync, constants, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { isGitRepo, runGit } from '../lib/git.js';
import {
  loadConfig,
  validateConfig,
  configPath,
  CONFIG_NAME,
} from '../lib/config.js';
import { MARKER_BEGIN } from './hooks.js';
import { VERSION } from '../lib/version.js';
import { color } from '../lib/color.js';

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'info';

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

export function runDoctorChecks(cwd: string): DoctorCheck[] {
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
      checks.push({
        name: 'config',
        status: 'pass',
        detail: `${CONFIG_NAME} ok (outDir=${cfg.outDir}, ignore=${cfg.ignore.length} glob(s))`,
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

  return checks;
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

/**
 * Run environment health checks. Returns exit code: 0 if no FAIL, 1 otherwise.
 */
export function cmdDoctor(cwd: string): number {
  console.log(color.bold(`agent-receipt doctor`) + color.dim(` (${VERSION})`));
  console.log(color.dim(`cwd: ${cwd}`));
  console.log('');

  const checks = runDoctorChecks(cwd);
  let fails = 0;
  let warns = 0;
  for (const c of checks) {
    if (c.status === 'fail') fails++;
    if (c.status === 'warn') warns++;
    console.log(`  [${icon(c.status)}] ${c.name.padEnd(8)} ${c.detail}`);
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
