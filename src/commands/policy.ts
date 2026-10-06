/**
 * `policy list|show|lint|test`. `--json` prints one object on stdout.
 * Lint exits 1 on schema errors. Test exits 2 on a deny hit or an expired
 * exception, and 1 when the pack or a receipt path is missing.
 */
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { VERSION } from '../lib/version.js';
import { color } from '../lib/color.js';
import { listReceipts } from './compare.js';
import {
  evaluatePolicyRefs,
  lintPolicyPack,
  listBuiltinPacks,
  receiptDisplayPath,
  showPolicyPack,
  type PolicyPackHit,
  type PolicyPackSummary,
} from '../lib/policy.js';

export type PolicyActionName = 'list' | 'show' | 'lint' | 'test';

export interface PolicyCommandOptions {
  action: PolicyActionName;
  pack?: string;
  receipts?: string[];
  json?: boolean;
}

function printJson(body: Record<string, unknown>): void {
  console.log(JSON.stringify(body));
}

export function printPolicyError(message: string): void {
  printJson({
    ok: false,
    command: 'policy',
    version: VERSION,
    exitCode: 1,
    reason: message,
  });
}

function ruleLine(rule: { id: string; severity: string; action: string; description: string }): string {
  return `  ${rule.id}  ${rule.severity}  ${rule.action}  ${rule.description}`;
}

function printPack(pack: PolicyPackSummary): void {
  const extend = pack.extends.length ? `  extends ${pack.extends.join(', ')}` : '';
  console.log(`${pack.ref}  ${pack.name}  ${pack.description}${extend}`);
  for (const rule of pack.rules) console.log(ruleLine(rule));
}

function resolveReceipt(cwd: string, spec: string): string {
  const abs = isAbsolute(spec) ? spec : resolve(cwd, spec);
  if (!existsSync(abs)) throw new Error(`receipt not found: ${spec}`);
  let st;
  try {
    st = lstatSync(abs);
  } catch {
    throw new Error(`receipt is unreadable: ${spec}`);
  }
  if (st.isSymbolicLink() || !st.isFile()) throw new Error(`receipt is not a regular file: ${spec}`);
  return abs;
}

export function cmdPolicy(cwd: string, opts: PolicyCommandOptions): number {
  const json = Boolean(opts.json);
  const action = opts.action;

  if (action === 'list') {
    const packs = listBuiltinPacks(cwd);
    if (json) {
      printJson({
        ok: true,
        command: 'policy',
        action: 'list',
        version: VERSION,
        exitCode: 0,
        packs: packs.map((pack) => ({
          ref: pack.ref,
          name: pack.name,
          description: pack.description,
          rules: pack.rules.map((rule) => ({
            id: rule.id,
            severity: rule.severity,
            action: rule.action,
            description: rule.description,
          })),
        })),
      });
      return 0;
    }
    for (const pack of packs) {
      printPack(pack);
      console.log('');
    }
    return 0;
  }

  const packRef = opts.pack?.trim();
  if (!packRef) throw new Error(`policy ${action} requires a pack name or file`);

  if (action === 'show') {
    const pack = showPolicyPack(cwd, packRef);
    if (json) {
      printJson({
        ok: true,
        command: 'policy',
        action: 'show',
        version: VERSION,
        exitCode: 0,
        ref: pack.ref,
        name: pack.name,
        description: pack.description,
        extends: pack.extends,
        rules: pack.rules,
      });
      return 0;
    }
    printPack(pack);
    return 0;
  }

  if (action === 'lint') {
    const result = lintPolicyPack(cwd, packRef);
    const exitCode: 0 | 1 = result.errors.length ? 1 : 0;
    if (json) {
      printJson({
        ok: exitCode === 0,
        command: 'policy',
        action: 'lint',
        version: VERSION,
        exitCode,
        path: result.path,
        errors: result.errors,
        rules: result.rules,
      });
      return exitCode;
    }
    console.log(`policy lint: ${result.path}`);
    if (!result.errors.length) {
      console.log(color.green('✓') + ` ok (${result.rules} rule(s))`);
      return 0;
    }
    for (const error of result.errors) console.error(color.red('✗') + ` ${error}`);
    return 1;
  }

  const explicit = (opts.receipts ?? []).map((file) => file.trim()).filter(Boolean);
  const paths = explicit.length ? explicit.map((file) => resolveReceipt(cwd, file)) : listReceipts(cwd);
  const targets = paths.map((file) => ({
    receipt: receiptDisplayPath(cwd, file),
    markdown: readFileSync(file, 'utf8'),
    absolutePath: file,
  }));
  const evaluated = evaluatePolicyRefs(cwd, [packRef], targets);
  const exitCode: 0 | 2 = evaluated.policyDenied ? 2 : 0;
  if (json) {
    printJson({
      ok: exitCode === 0,
      command: 'policy',
      action: 'test',
      version: VERSION,
      exitCode,
      pack: packRef,
      packs: evaluated.policyPacks,
      rules: evaluated.rules,
      receipts: targets.length,
      hits: evaluated.policyPackHits,
      denied: evaluated.policyDenied,
      expired: evaluated.expired,
      reason: evaluated.reason,
    });
    return exitCode;
  }
  if (!evaluated.policyPackHits.length && !evaluated.expired.length) {
    console.log(`policy test: ${packRef}  0 hit(s) on ${targets.length} receipt(s)`);
    return 0;
  }
  for (const hit of evaluated.policyPackHits) printHit(hit);
  for (const expired of evaluated.expired) {
    console.error(
      color.red('✗') + ` expired exception ${expired.rule} ${expired.path} (${expired.expires})`,
    );
  }
  const line = `${evaluated.policyPackHits.length} hit(s), ${evaluated.policyDenied ? 'denied' : 'warn'}`;
  console.log(evaluated.policyDenied ? color.red(line) : line);
  return exitCode;
}

function printHit(hit: PolicyPackHit): void {
  const line = `${hit.action}  ${hit.severity}  ${hit.rule}  ${hit.receipt}  ${hit.evidence}`;
  if (hit.action === 'deny') console.error(color.red(line));
  else console.log(line);
}
