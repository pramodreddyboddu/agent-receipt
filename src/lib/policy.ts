/**
 * Declarative policy packs. A small deterministic matcher over receipt
 * fields. No Rego and no eval. Packs fail closed: a missing, unreadable,
 * or invalid pack throws. Deny hits fail the gate (exit 2). Warn hits
 * are reported and do not change the exit code.
 */
import { lstatSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, type PolicyException } from './config.js';
import { parseNestedYaml } from './nested-yaml.js';
import { globPatternError, globToRegExp, pathMatchesGlob } from './ignore.js';
import { meetsFailOn, parseRiskSummaryMarkdown, type Severity } from './risk.js';
import { redactSecretsInText } from './redact.js';
import { canonicalBody, appendHashFooter, extractEmbeddedHash } from './hash.js';
import { inspectReceiptSignature } from './sign.js';

export const POLICY_API = 'agent-receipt/policy/v1';
export const BUILTIN_PACKS = ['baseline', 'supply-chain', 'ci-protect', 'strict'] as const;
const MAX_PACK_BYTES = 256 * 1024;
const MAX_REGEX = 200;
const MAX_REGEX_INPUT = 4000;
const MAX_EXTEND_DEPTH = 8;
const EVIDENCE_LIMIT = 180;

const PACK_KEYS = new Set(['apiVersion', 'name', 'description', 'extends', 'rules']);
const RULE_KEYS = new Set(['id', 'description', 'severity', 'action', 'match']);
const MATCH_KEYS = new Set([
  'command',
  'commands',
  'files',
  'file',
  'tool',
  'tools',
  'adapter',
  'network',
  'packageInstall',
  'publish',
  'exitCode',
  'exitCodes',
  'risk',
  'agent',
  'unsigned',
  'redactionDisabled',
  'maxFiles',
  'maxBytes',
  'maxCommands',
  'maxToolCalls',
]);
const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const ACTIONS = new Set(['deny', 'warn']);
const RISK_LEVELS = new Set(['low', 'medium', 'high']);

const NETWORK_RE =
  /(?:^|&&|\|\||;|\|)\s*(?:sudo\s+)?(?:curl|wget|nc|ncat|socat|ssh|scp|sftp|ftp|telnet)\b/;
const INSTALL_RE =
  /(?:^|&&|\|\||;|\|)\s*(?:sudo\s+)?(?:npm\s+(?:install|i|ci)|pnpm\s+(?:install|i|add)|yarn\s+(?:add|install)|bun\s+(?:install|i|add)|pip3?\s+install|pipx\s+install|cargo\s+install|gem\s+install|go\s+install|composer\s+(?:install|require)|apt(?:-get)?\s+install|brew\s+install)\b/;
const PUBLISH_RE =
  /(?:^|&&|\|\||;|\|)\s*(?:sudo\s+)?(?:(?:npm|pnpm|yarn|bun|cargo)\s+publish|twine\s+upload|gem\s+push|poetry\s+publish|dotnet\s+nuget\s+push)\b/;

export class PolicyPackError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyPackError';
  }
}

export type PolicySeverity = 'low' | 'medium' | 'high' | 'critical';
export type PolicyAction = 'deny' | 'warn';

export interface PolicyPackHit {
  rule: string;
  pack: string;
  severity: PolicySeverity;
  action: PolicyAction;
  evidence: string;
  receipt: string;
}

export interface PolicyGateResult {
  policyPacks: string[];
  policyPackHits: PolicyPackHit[];
  policyDenied: boolean;
  reason: string | null;
  expired: Array<{ rule: string; path: string; expires: string }>;
  rules: number;
}

export interface PolicyTarget {
  /** Display path stored on the hit. */
  receipt: string;
  markdown: string;
  /** Absolute path used to read a signature sidecar. Omit before the file exists. */
  absolutePath?: string;
  /** Override unsigned when the sidecar is not written yet. */
  unsigned?: boolean;
  /** Byte length used for maxBytes. Defaults to the markdown byte length. */
  bytes?: number;
}

interface Pattern {
  kind: 'glob' | 'regex';
  source: string;
  re?: RegExp;
}

interface ExitSpec {
  kind: 'any' | 'nonzero' | 'set';
  values?: number[];
}

interface CompiledMatch {
  commands?: Pattern[];
  files?: string[];
  tools?: string[];
  adapters?: string[];
  network?: true;
  packageInstall?: true;
  publish?: true;
  exit?: ExitSpec;
  risk?: Severity;
  agents?: string[];
  unsigned?: true;
  redactionDisabled?: true;
  maxFiles?: number;
  maxBytes?: number;
  maxCommands?: number;
  maxToolCalls?: number;
}

interface CompiledRule {
  id: string;
  description: string;
  severity: PolicySeverity;
  action: PolicyAction;
  pack: string;
  match: Record<string, unknown>;
  compiled: CompiledMatch;
}

interface CompiledPack {
  ref: string;
  name: string;
  description: string;
  extends: string[];
  rules: CompiledRule[];
}

interface ReceiptFacts {
  receipt: string;
  files: string[];
  commands: string[];
  tools: string[];
  adapters: string[];
  exitCodes: number[];
  risk: Severity | null;
  agent: string | null;
  unsigned: boolean;
  redactionDisabled: boolean;
  bytes: number;
  fileCount: number;
  commandCount: number;
  toolCount: number;
}

interface InternalHit extends PolicyPackHit {
  paths: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function builtinDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, '..', '..', 'policies'),
    join(here, '..', 'policies'),
    join(here, '..', '..', '..', 'policies'),
  ];
  for (const dir of candidates) {
    if (existsSync(join(dir, 'baseline.yml'))) return dir;
  }
  throw new PolicyPackError(
    'built-in policy packs are missing from this install (policies/baseline.yml)',
  );
}

export function utcToday(): string {
  return new Date().toISOString().slice(0, 10);
}

export function exceptionExpired(expires: string | undefined, today = utcToday()): boolean {
  if (!expires) return false;
  return expires < today;
}

export function activePolicyRefs(cwd: string, flagRefs?: string[]): string[] {
  const cfg = loadConfig(cwd);
  if (cfg.policyConfigInvalid) throw new PolicyPackError(cfg.policyConfigInvalid);
  const out: string[] = [];
  const add = (ref: string): void => {
    const trimmed = ref.trim();
    if (trimmed && !out.includes(trimmed)) out.push(trimmed);
  };
  for (const ref of flagRefs ?? []) add(ref);
  for (const ref of cfg.policyPacks ?? []) add(ref);
  return out;
}

function displayRef(ref: string): string {
  return ref.trim();
}

function resolvePackFile(ref: string, baseDir: string): { id: string; file: string; display: string } {
  const display = displayRef(ref);
  if (display.startsWith('builtin:')) {
    const name = display.slice('builtin:'.length);
    if (!BUILTIN_PACKS.includes(name as (typeof BUILTIN_PACKS)[number])) {
      throw new PolicyPackError(`unknown built-in policy pack: ${display}`);
    }
    return { id: `builtin:${name}`, file: join(builtinDir(), `${name}.yml`), display };
  }
  if (!display) throw new PolicyPackError('policy pack name is empty');
  const file = resolve(baseDir, display);
  return { id: file, file, display };
}

function readPackText(file: string, display: string): string {
  let st;
  try {
    st = lstatSync(file);
  } catch {
    throw new PolicyPackError(`policy pack not found: ${display}`);
  }
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new PolicyPackError(`policy pack is not a regular file: ${display}`);
  }
  if (st.size > MAX_PACK_BYTES) {
    throw new PolicyPackError(`policy pack is too large: ${display}`);
  }
  try {
    return readFileSync(file, 'utf8');
  } catch {
    throw new PolicyPackError(`policy pack is unreadable: ${display}`);
  }
}

function parsePackText(text: string, file: string): unknown {
  const trimmed = text.trim();
  if (file.endsWith('.json') || trimmed.startsWith('{')) {
    try {
      return JSON.parse(text);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new PolicyPackError(`policy pack is invalid JSON (${message})`);
    }
  }
  try {
    return parseNestedYaml(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new PolicyPackError(`policy pack is invalid YAML (${message})`);
  }
}

function asNonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function stringList(value: unknown, label: string, errors: string[]): string[] | null {
  if (typeof value === 'string') {
    const one = value.trim();
    if (!one) {
      errors.push(`${label} is empty`);
      return null;
    }
    return [one];
  }
  if (!Array.isArray(value) || value.length === 0) {
    errors.push(`${label} must be a non-empty string or list`);
    return null;
  }
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || !item.trim()) {
      errors.push(`${label} entries must be non-empty strings`);
      return null;
    }
    out.push(item.trim());
  }
  return out;
}

function compileRegex(source: string, flags: string, label: string, errors: string[]): RegExp | null {
  if (!source) {
    errors.push(`${label} regex is empty`);
    return null;
  }
  if (source.length > MAX_REGEX) {
    errors.push(`${label} regex is longer than ${MAX_REGEX} characters`);
    return null;
  }
  if (!/^[ims]*$/.test(flags)) {
    errors.push(`${label} regex flags must be a combination of i, m, s`);
    return null;
  }
  try {
    return new RegExp(source, flags);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    errors.push(`${label} regex is invalid (${message})`);
    return null;
  }
}

function compileCommand(pattern: string, label: string, errors: string[]): Pattern | null {
  if (pattern.startsWith('regex:')) {
    const re = compileRegex(pattern.slice('regex:'.length), '', label, errors);
    return re ? { kind: 'regex', source: pattern, re } : null;
  }
  const slash = pattern.match(/^\/(.+)\/([a-z]*)$/);
  if (slash) {
    const re = compileRegex(slash[1], slash[2], label, errors);
    return re ? { kind: 'regex', source: pattern, re } : null;
  }
  const globErr = globPatternError(pattern);
  if (globErr) {
    errors.push(`bad glob: ${pattern} (${globErr})`);
    return null;
  }
  return { kind: 'glob', source: pattern };
}

function compileGlobs(patterns: string[], label: string, errors: string[]): string[] | null {
  const out: string[] = [];
  let ok = true;
  for (const pattern of patterns) {
    const globErr = globPatternError(pattern);
    if (globErr) {
      errors.push(`bad glob: ${pattern} (${globErr})`);
      ok = false;
      continue;
    }
    out.push(pattern);
  }
  if (!ok) return null;
  return out;
}

function requireTrue(value: unknown, label: string, errors: string[]): true | undefined {
  if (value !== true) {
    errors.push(`${label} must be true`);
    return undefined;
  }
  return true;
}

function compileMatch(raw: unknown, errors: string[]): { match: Record<string, unknown>; compiled: CompiledMatch } | null {
  if (!isRecord(raw)) {
    errors.push('match must be a map');
    return null;
  }
  const keys = Object.keys(raw);
  if (!keys.length) {
    errors.push('match is empty');
    return null;
  }
  for (const key of keys) {
    if (!MATCH_KEYS.has(key)) errors.push(`unknown key ${key}`);
  }
  const aliasClash = (a: string, b: string): void => {
    if (raw[a] !== undefined && raw[b] !== undefined) {
      errors.push(`use only one of ${a} and ${b}`);
    }
  };
  aliasClash('command', 'commands');
  aliasClash('files', 'file');
  aliasClash('tool', 'tools');
  aliasClash('exitCode', 'exitCodes');

  const compiled: CompiledMatch = {};
  const match: Record<string, unknown> = {};
  const takeList = (primary: string, alias: string): string[] | null => {
    const value = raw[primary] !== undefined ? raw[primary] : raw[alias];
    if (value === undefined) return null;
    return stringList(value, primary, errors);
  };

  const commands = takeList('command', 'commands');
  if (commands) {
    const compiledCommands: Pattern[] = [];
    for (const pattern of commands) {
      const compiledPattern = compileCommand(pattern, 'command', errors);
      if (compiledPattern) compiledCommands.push(compiledPattern);
    }
    compiled.commands = compiledCommands;
    match.command = commands;
  }

  const files = takeList('files', 'file');
  if (files) {
    const globs = compileGlobs(files, 'files', errors);
    if (globs) compiled.files = globs;
    match.files = files;
  }

  const tools = takeList('tool', 'tools');
  if (tools) {
    const globs = compileGlobs(tools, 'tool', errors);
    if (globs) compiled.tools = globs;
    match.tool = tools;
  }

  if (raw.adapter !== undefined) {
    const adapters = stringList(raw.adapter, 'adapter', errors);
    if (adapters) {
      const globs = compileGlobs(adapters, 'adapter', errors);
      if (globs) compiled.adapters = globs;
      match.adapter = adapters;
    }
  }

  if (raw.agent !== undefined) {
    const agents = stringList(raw.agent, 'agent', errors);
    if (agents) {
      const globs = compileGlobs(agents, 'agent', errors);
      if (globs) compiled.agents = globs;
      match.agent = agents;
    }
  }

  if (raw.network !== undefined) {
    const flag = requireTrue(raw.network, 'network', errors);
    if (flag) {
      compiled.network = true;
      match.network = true;
    }
  }
  if (raw.packageInstall !== undefined) {
    const flag = requireTrue(raw.packageInstall, 'packageInstall', errors);
    if (flag) {
      compiled.packageInstall = true;
      match.packageInstall = true;
    }
  }
  if (raw.publish !== undefined) {
    const flag = requireTrue(raw.publish, 'publish', errors);
    if (flag) {
      compiled.publish = true;
      match.publish = true;
    }
  }
  if (raw.unsigned !== undefined) {
    const flag = requireTrue(raw.unsigned, 'unsigned', errors);
    if (flag) {
      compiled.unsigned = true;
      match.unsigned = true;
    }
  }
  if (raw.redactionDisabled !== undefined) {
    const flag = requireTrue(raw.redactionDisabled, 'redactionDisabled', errors);
    if (flag) {
      compiled.redactionDisabled = true;
      match.redactionDisabled = true;
    }
  }

  if (raw.risk !== undefined) {
    if (raw.risk === 'critical') {
      errors.push('risk must be low, medium, or high');
    } else if (typeof raw.risk !== 'string' || !RISK_LEVELS.has(raw.risk)) {
      errors.push('risk must be low, medium, or high');
    } else {
      compiled.risk = raw.risk as Severity;
      match.risk = raw.risk;
    }
  }

  const exitRaw = raw.exitCode !== undefined ? raw.exitCode : raw.exitCodes;
  if (exitRaw !== undefined) {
    const exit = compileExit(exitRaw, errors);
    if (exit) {
      compiled.exit = exit;
      match.exitCode = exitRaw;
    }
  }

  for (const key of ['maxFiles', 'maxBytes', 'maxCommands', 'maxToolCalls'] as const) {
    if (raw[key] === undefined) continue;
    const value = raw[key];
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      errors.push(`${key} must be an integer >= 0`);
      continue;
    }
    compiled[key] = value;
    match[key] = value;
  }

  if (!Object.keys(compiled).length) return null;
  return { match, compiled };
}

function compileExit(value: unknown, errors: string[]): ExitSpec | null {
  const one = (item: unknown): number | 'any' | 'nonzero' | null => {
    if (typeof item === 'number' && Number.isInteger(item)) return item;
    if (typeof item !== 'string') return null;
    const text = item.trim().toLowerCase();
    if (text === 'any') return 'any';
    if (text === 'nonzero' || text === 'non-zero') return 'nonzero';
    if (/^-?\d+$/.test(text)) return parseInt(text, 10);
    return null;
  };
  const items = Array.isArray(value) ? value : [value];
  if (!items.length) {
    errors.push('exitCode must be a number, nonzero, any, or a list');
    return null;
  }
  const numbers: number[] = [];
  let any = false;
  let nonzero = false;
  for (const item of items) {
    const parsed = one(item);
    if (parsed === null) {
      errors.push('exitCode must be a number, nonzero, any, or a list');
      return null;
    }
    if (parsed === 'any') any = true;
    else if (parsed === 'nonzero') nonzero = true;
    else numbers.push(parsed);
  }
  if (any) return { kind: 'any' };
  if (nonzero && !numbers.length) return { kind: 'nonzero' };
  if (nonzero) return { kind: 'nonzero' };
  return { kind: 'set', values: numbers };
}

function lintDocument(raw: unknown): { errors: string[]; rules: CompiledRule[]; name: string; description: string; extends: string[] } {
  const errors: string[] = [];
  if (!isRecord(raw)) {
    return { errors: ['policy pack must be a map'], rules: [], name: '', description: '', extends: [] };
  }
  for (const key of Object.keys(raw)) {
    if (!PACK_KEYS.has(key)) errors.push(`unknown key ${key}`);
  }
  if (raw.apiVersion !== POLICY_API) {
    errors.push(`apiVersion must be ${POLICY_API}`);
  }
  const name = asNonEmptyString(raw.name);
  if (!name) errors.push('name is required');
  const description = asNonEmptyString(raw.description);
  if (!description) errors.push('description is required');
  let extendRefs: string[] = [];
  if (raw.extends !== undefined) {
    const parsed = stringList(raw.extends, 'extends', errors);
    extendRefs = parsed ?? [];
  }
  const hasRules = raw.rules !== undefined;
  if (!hasRules && raw.extends === undefined) {
    errors.push('pack needs rules or extends');
  }
  const own: CompiledRule[] = [];
  if (hasRules) {
    if (!Array.isArray(raw.rules)) {
      errors.push('rules must be a list');
    } else if (!raw.rules.length && raw.extends === undefined) {
      errors.push('pack needs rules or extends');
    } else {
      const seen = new Set<string>();
      for (const entry of raw.rules) {
        if (!isRecord(entry)) {
          errors.push('rule must be a map');
          continue;
        }
        for (const key of Object.keys(entry)) {
          if (!RULE_KEYS.has(key)) errors.push(`unknown key ${key}`);
        }
        const id = asNonEmptyString(entry.id);
        if (!id) errors.push('rule id is required');
        else if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) errors.push(`rule id must be kebab-case (${id})`);
        else if (seen.has(id)) errors.push(`duplicate rule id ${id}`);
        else seen.add(id);
        const ruleDescription = asNonEmptyString(entry.description);
        if (!ruleDescription) errors.push(`description is required${id ? ` (${id})` : ''}`);
        const severity = entry.severity;
        if (typeof severity !== 'string' || !SEVERITIES.has(severity)) {
          errors.push('severity must be low, medium, high, or critical');
        }
        const action = entry.action;
        if (typeof action !== 'string' || !ACTIONS.has(action)) {
          errors.push('action must be deny or warn');
        }
        const compiled = compileMatch(entry.match, errors);
        if (
          id &&
          ruleDescription &&
          typeof severity === 'string' &&
          SEVERITIES.has(severity) &&
          typeof action === 'string' &&
          ACTIONS.has(action) &&
          compiled
        ) {
          own.push({
            id,
            description: ruleDescription,
            severity: severity as PolicySeverity,
            action: action as PolicyAction,
            pack: name || '',
            match: compiled.match,
            compiled: compiled.compiled,
          });
        }
      }
    }
  }
  return {
    errors,
    rules: own,
    name: name || '',
    description: description || '',
    extends: extendRefs,
  };
}

function loadCompiled(cwd: string, ref: string, stack: string[], depth: number, baseDir: string): CompiledPack {
  if (depth > MAX_EXTEND_DEPTH) {
    throw new PolicyPackError(`policy pack extends too deep (max ${MAX_EXTEND_DEPTH}): ${displayRef(ref)}`);
  }
  const located = resolvePackFile(ref, baseDir);
  if (stack.includes(located.id)) {
    throw new PolicyPackError(`cycle in policy pack extends: ${[...stack, located.id].join(' -> ')}`);
  }
  const text = readPackText(located.file, located.display);
  let parsed: unknown;
  try {
    parsed = parsePackText(text, located.file);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new PolicyPackError(`policy pack is invalid: ${located.display}: ${message.replace(/^policy pack is invalid (?:JSON|YAML) \(/, '').replace(/\)$/, '')}`);
  }
  const doc = lintDocument(parsed);
  if (doc.errors.length) {
    throw new PolicyPackError(`policy pack is invalid: ${located.display}: ${doc.errors.join('; ')}`);
  }
  const nextStack = [...stack, located.id];
  const map = new Map<string, CompiledRule>();
  for (const ext of doc.extends) {
    const parent = loadCompiled(cwd, ext, nextStack, depth + 1, dirname(located.file));
    for (const rule of parent.rules) map.set(rule.id, rule);
  }
  for (const rule of doc.rules) {
    map.set(rule.id, { ...rule, pack: doc.name });
  }
  return {
    ref: located.display,
    name: doc.name,
    description: doc.description,
    extends: doc.extends,
    rules: [...map.values()],
  };
}

export function loadPolicyPack(cwd: string, ref: string): CompiledPack {
  return loadCompiled(cwd, ref, [], 1, cwd);
}

function loadPolicyPacks(cwd: string, refs: string[]): CompiledPack[] {
  return refs.map((ref) => loadPolicyPack(cwd, ref));
}

export function lintPolicyPack(cwd: string, ref: string): { path: string; errors: string[]; rules: number; name: string } {
  try {
    const pack = loadPolicyPack(cwd, ref);
    return { path: pack.ref, errors: [], rules: pack.rules.length, name: pack.name };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const errors = message.startsWith('policy pack is invalid: ')
      ? message.replace(/^policy pack is invalid: [^:]+:\s*/, '').split('; ').filter(Boolean)
      : [message];
    return { path: displayRef(ref), errors, rules: 0, name: '' };
  }
}

export interface PolicyPackSummary {
  ref: string;
  name: string;
  description: string;
  extends: string[];
  rules: Array<{
    id: string;
    description: string;
    severity: PolicySeverity;
    action: PolicyAction;
    pack: string;
    match: Record<string, unknown>;
  }>;
}

function summarize(pack: CompiledPack): PolicyPackSummary {
  return {
    ref: pack.ref,
    name: pack.name,
    description: pack.description,
    extends: pack.extends,
    rules: pack.rules.map((rule) => ({
      id: rule.id,
      description: rule.description,
      severity: rule.severity,
      action: rule.action,
      pack: rule.pack,
      match: rule.match,
    })),
  };
}

export function listBuiltinPacks(cwd: string): PolicyPackSummary[] {
  return BUILTIN_PACKS.map((name) => summarize(loadPolicyPack(cwd, `builtin:${name}`)));
}

export function showPolicyPack(cwd: string, ref: string): PolicyPackSummary {
  return summarize(loadPolicyPack(cwd, ref));
}

function sectionBody(markdown: string, heading: string): string {
  const start = markdown.indexOf(`\n${heading}\n`);
  const at = start >= 0 ? start + 1 : markdown.startsWith(heading) ? 0 : -1;
  if (at < 0) return '';
  const rest = markdown.slice(at + heading.length);
  const next = rest.search(/\n## /);
  return next < 0 ? rest : rest.slice(0, next);
}

function unquote(token: string): string {
  const trimmed = token.trim();
  if (trimmed.startsWith('`') && trimmed.endsWith('`') && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function unique(items: string[]): string[] {
  const out: string[] = [];
  for (const item of items) {
    if (item && !out.includes(item)) out.push(item);
  }
  return out;
}

function readFacts(target: PolicyTarget): ReceiptFacts {
  const files: string[] = [];
  const fileSection = sectionBody(target.markdown, '## Files changed');
  for (const line of fileSection.split('\n')) {
    const match = line.match(/^\|[^|]*\|\s*`([^`]+)`\s*\|/);
    if (match) files.push(match[1]);
  }
  const commands: string[] = [];
  const tools: string[] = [];
  const exitCodes: number[] = [];
  const toolSection = sectionBody(target.markdown, '## Tool calls');
  let toolCount = 0;
  for (const line of toolSection.split('\n')) {
    if (!line.startsWith('- `')) continue;
    toolCount++;
    const parts = line.slice(2).split(' — ');
    const tool = unquote(parts[0] ?? '');
    if (tool) tools.push(tool);
    for (const part of parts.slice(1)) {
      const exit = part.match(/^exit (-?\d+)$/);
      if (exit) {
        exitCodes.push(parseInt(exit[1], 10));
        continue;
      }
      if (part.startsWith('files:')) {
        for (const found of part.matchAll(/`([^`]+)`/g)) files.push(found[1]);
        continue;
      }
      if (part.startsWith('`')) {
        const inner = unquote(part);
        if (inner && !inner.startsWith('{') && !inner.startsWith('[')) commands.push(inner);
      }
    }
  }
  const adapters: string[] = [];
  const adapter = toolSection.match(/^- \*\*Adapter\*\*:\s*(.+)$/m);
  if (adapter?.[1]?.trim()) adapters.push(adapter[1].trim());
  const session = sectionBody(target.markdown, '## Session');
  const agent = session.match(/^- \*\*Agent\*\*:\s*(.+)$/m)?.[1]?.trim() || null;
  const risk = parseRiskSummaryMarkdown(target.markdown).maxSeverity;
  const uniqueFiles = unique(files);
  let unsigned = target.unsigned;
  if (unsigned === undefined) {
    const hash = extractEmbeddedHash(target.markdown);
    if (!target.absolutePath || !hash) unsigned = true;
    else {
      const inspected = inspectReceiptSignature(target.absolutePath, hash);
      unsigned = !(inspected.present && inspected.ok === true);
    }
  }
  return {
    receipt: target.receipt,
    files: uniqueFiles,
    commands,
    tools,
    adapters,
    exitCodes,
    risk,
    agent,
    unsigned,
    redactionDisabled: !target.markdown.includes('**Redacted**'),
    bytes: target.bytes ?? Buffer.byteLength(target.markdown, 'utf8'),
    fileCount: uniqueFiles.length,
    commandCount: commands.length,
    toolCount,
  };
}

function clipEvidence(text: string): string {
  const redacted = redactSecretsInText(text);
  const flat = redacted.replace(/[\r\n\u2028\u2029\t|]+/g, ' ').replace(/ {2,}/g, ' ').trim();
  if (!flat) return '';
  if (flat.length <= EVIDENCE_LIMIT) return flat;
  return `${flat.slice(0, EVIDENCE_LIMIT - 1)}…`;
}

function patternHits(values: string[], patterns: Pattern[]): string[] {
  const hits: string[] = [];
  for (const value of values) {
    const sample = value.slice(0, MAX_REGEX_INPUT);
    const matched = patterns.some((pattern) => {
      if (pattern.kind === 'regex' && pattern.re) return pattern.re.test(sample);
      return globToRegExp(pattern.source).test(sample);
    });
    if (matched) hits.push(value);
  }
  return hits;
}

function globHits(values: string[], patterns: string[], files: boolean): string[] {
  const hits: string[] = [];
  for (const value of values) {
    const matched = patterns.some((pattern) =>
      files ? pathMatchesGlob(value, pattern) : globToRegExp(pattern).test(value) || pathMatchesGlob(value, pattern),
    );
    if (matched) hits.push(value);
  }
  return hits;
}

function commandBlobHits(commands: string[], re: RegExp): string[] {
  return commands.filter((command) => re.test(command.slice(0, MAX_REGEX_INPUT)));
}

function matchRule(rule: CompiledRule, facts: ReceiptFacts): InternalHit | null {
  const compiled = rule.compiled;
  const evidence: string[] = [];
  let paths: string[] = [];
  const take = (items: string[]): void => {
    for (const item of items) {
      if (evidence.length >= 3) return;
      const clipped = clipEvidence(item);
      if (clipped) evidence.push(clipped);
    }
  };

  if (compiled.files) {
    const hits = globHits(facts.files, compiled.files, true);
    if (!hits.length) return null;
    paths = hits;
    take(hits);
  }
  if (compiled.commands) {
    const hits = patternHits(facts.commands, compiled.commands);
    if (!hits.length) return null;
    take(hits);
  }
  if (compiled.tools) {
    const hits = globHits(facts.tools, compiled.tools, false);
    if (!hits.length) return null;
    take(hits.map((tool) => `tool ${tool}`));
  }
  if (compiled.adapters) {
    const hits = globHits(facts.adapters, compiled.adapters, false);
    if (!hits.length) return null;
    take(hits.map((adapter) => `adapter ${adapter}`));
  }
  if (compiled.network) {
    const hits = commandBlobHits(facts.commands, NETWORK_RE);
    if (!hits.length) return null;
    take(hits);
  }
  if (compiled.packageInstall) {
    const hits = commandBlobHits(facts.commands, INSTALL_RE);
    if (!hits.length) return null;
    take(hits);
  }
  if (compiled.publish) {
    const hits = commandBlobHits(facts.commands, PUBLISH_RE);
    if (!hits.length) return null;
    take(hits);
  }
  if (compiled.exit) {
    const spec = compiled.exit;
    const ok =
      spec.kind === 'any'
        ? facts.exitCodes.length > 0
        : spec.kind === 'nonzero'
          ? facts.exitCodes.some((code) => code !== 0)
          : facts.exitCodes.some((code) => spec.values?.includes(code));
    if (!ok) return null;
    take([`exit ${facts.exitCodes.join(',')}`]);
  }
  if (compiled.risk) {
    if (!facts.risk || !meetsFailOn(facts.risk, compiled.risk)) return null;
    take([`risk ${facts.risk}`]);
  }
  if (compiled.agents) {
    if (!facts.agent || !globHits([facts.agent], compiled.agents, false).length) return null;
    take([`agent ${facts.agent}`]);
  }
  if (compiled.unsigned) {
    if (!facts.unsigned) return null;
    take(['unsigned receipt']);
  }
  if (compiled.redactionDisabled) {
    if (!facts.redactionDisabled) return null;
    take(['redaction disabled']);
  }
  if (compiled.maxFiles !== undefined) {
    if (!(facts.fileCount > compiled.maxFiles)) return null;
    take([`${facts.fileCount} files > ${compiled.maxFiles}`]);
  }
  if (compiled.maxBytes !== undefined) {
    if (!(facts.bytes > compiled.maxBytes)) return null;
    take([`${facts.bytes} bytes > ${compiled.maxBytes}`]);
  }
  if (compiled.maxCommands !== undefined) {
    if (!(facts.commandCount > compiled.maxCommands)) return null;
    take([`${facts.commandCount} commands > ${compiled.maxCommands}`]);
  }
  if (compiled.maxToolCalls !== undefined) {
    if (!(facts.toolCount > compiled.maxToolCalls)) return null;
    take([`${facts.toolCount} tool calls > ${compiled.maxToolCalls}`]);
  }

  return {
    rule: rule.id,
    pack: rule.pack,
    severity: rule.severity,
    action: rule.action,
    evidence: clipEvidence(evidence.join('; ')),
    receipt: clipEvidence(facts.receipt),
    paths,
  };
}

function applyExceptions(hit: InternalHit, exceptions: PolicyException[], files: string[]): InternalHit | null {
  const active = exceptions.filter((ex) => ex.rule === hit.rule && !exceptionExpired(ex.expires));
  if (!active.length) return hit;
  if (hit.paths.length) {
    const kept = hit.paths.filter((file) => !active.some((ex) => pathMatchesGlob(file, ex.path)));
    if (!kept.length) return null;
    if (kept.length === hit.paths.length) return hit;
    return { ...hit, paths: kept, evidence: clipEvidence(kept.slice(0, 3).join('; ')) };
  }
  const suppressed = active.some((ex) => {
    if (ex.path === '**' || ex.path === '*') return true;
    return files.length > 0 && files.every((file) => pathMatchesGlob(file, ex.path));
  });
  return suppressed ? null : hit;
}

function policyReasonText(
  hits: PolicyPackHit[],
  expired: Array<{ rule: string; expires: string }>,
): string | null {
  const parts: string[] = [];
  const denied = hits.filter((hit) => hit.action === 'deny');
  if (denied.length) {
    const ids = unique(denied.map((hit) => hit.rule)).slice(0, 5);
    parts.push(`policy pack deny: ${ids.join(', ')}`);
  }
  if (expired.length) {
    const bits = expired.slice(0, 3).map((ex) => `${ex.rule} (${ex.expires})`);
    parts.push(`expired policy exception: ${bits.join(', ')}`);
  }
  return parts.length ? parts.join('; ') : null;
}

export function evaluatePolicyRefs(
  cwd: string,
  refs: string[],
  targets: PolicyTarget[],
): PolicyGateResult {
  const packs = loadPolicyPacks(cwd, refs);
  const map = new Map<string, CompiledRule>();
  for (const pack of packs) {
    for (const rule of pack.rules) map.set(rule.id, rule);
  }
  const rules = [...map.values()];
  const exceptions = loadConfig(cwd).policyExceptions ?? [];
  const expired = exceptions
    .filter((ex) => ex.expires && exceptionExpired(ex.expires))
    .map((ex) => ({ rule: ex.rule, path: ex.path, expires: ex.expires as string }));
  const hits: PolicyPackHit[] = [];
  for (const target of targets) {
    const facts = readFacts(target);
    for (const rule of rules) {
      const hit = matchRule(rule, facts);
      if (!hit) continue;
      const kept = applyExceptions(hit, exceptions, facts.files);
      if (!kept) continue;
      hits.push({
        rule: kept.rule,
        pack: kept.pack,
        severity: kept.severity,
        action: kept.action,
        evidence: kept.evidence,
        receipt: kept.receipt,
      });
    }
  }
  const policyDenied = hits.some((hit) => hit.action === 'deny') || expired.length > 0;
  return {
    policyPacks: packs.map((pack) => pack.name),
    policyPackHits: hits,
    policyDenied,
    reason: policyReasonText(hits, expired),
    expired,
    rules: rules.length,
  };
}

/**
 * Union of `--policy-pack` and config `policyPacks`. Null when nothing
 * is configured, so callers omit the gate keys. Throws when a configured
 * pack or the policy block in config is missing or invalid.
 */
export function evaluateActivePolicy(
  cwd: string,
  flagRefs: string[] | undefined,
  targets: PolicyTarget[],
): PolicyGateResult | null {
  const refs = activePolicyRefs(cwd, flagRefs);
  if (!refs.length) return null;
  return evaluatePolicyRefs(cwd, refs, targets);
}

export function policyGateFields(
  result: PolicyGateResult | null | undefined,
): {
  policyPacks?: string[];
  policyPackHits?: PolicyPackHit[];
  policyDenied?: boolean;
} {
  if (!result) return {};
  return {
    policyPacks: result.policyPacks,
    policyPackHits: result.policyPackHits,
    policyDenied: result.policyDenied,
  };
}

export function renderReceiptPolicySection(hits: PolicyPackHit[]): string {
  const lines = ['## Policy packs', ''];
  if (!hits.length) {
    lines.push('_None._', '');
    return lines.join('\n');
  }
  lines.push('| Action | Sev | Rule | Evidence |');
  lines.push('|--------|-----|------|----------|');
  for (const hit of hits) {
    lines.push(`| ${hit.action} | ${hit.severity} | \`${hit.rule}\` | ${hit.evidence} |`);
  }
  lines.push('');
  return lines.join('\n');
}

/** Insert `## Policy packs` before the hash footer and re-hash. */
export function stampPolicySection(markdown: string, hits: PolicyPackHit[]): string {
  const body = canonicalBody(markdown).replace(/\s+$/, '');
  const section = renderReceiptPolicySection(hits).replace(/\s+$/, '');
  return appendHashFooter(`${body}\n\n${section}\n`);
}

export function policyDoctorDetail(cwd: string): { problem: boolean; detail: string } {
  const cfg = loadConfig(cwd);
  const clip = (text: string): string => {
    const flat = redactSecretsInText(text).replace(/\s+/g, ' ').trim();
    return flat.length > 300 ? `${flat.slice(0, 299)}…` : flat;
  };
  if (cfg.policyConfigInvalid) {
    return { problem: true, detail: `policy packs: ${clip(cfg.policyConfigInvalid)}` };
  }
  const refs = cfg.policyPacks ?? [];
  if (refs.length) {
    try {
      loadPolicyPacks(cwd, refs);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { problem: true, detail: `policy packs: ${clip(message)}` };
    }
  }
  const expired = (cfg.policyExceptions ?? []).filter((ex) => ex.expires && exceptionExpired(ex.expires));
  if (expired.length) {
    const bits = expired
      .slice(0, 3)
      .map((ex) => `${ex.rule} (${ex.expires})`)
      .join(', ');
    return { problem: true, detail: `policy packs: expired exception ${bits}` };
  }
  if (!refs.length) return { problem: false, detail: 'policy packs: none configured' };
  try {
    const names = loadPolicyPacks(cwd, refs)
      .map((pack) => pack.name)
      .join(', ');
    return { problem: false, detail: `policy packs: ${names}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { problem: true, detail: `policy packs: ${clip(message)}` };
  }
}

export function receiptDisplayPath(cwd: string, filePath: string): string {
  const rel = relative(cwd, filePath).replace(/\\/g, '/');
  if (!rel || rel === '..' || rel.startsWith('../')) return filePath;
  return rel;
}

export function targetsFromMarkdown(cwd: string, files: Array<{ path: string; markdown: string }>): PolicyTarget[] {
  return files.map((file) => ({
    receipt: receiptDisplayPath(cwd, file.path),
    markdown: file.markdown,
    absolutePath: file.path,
  }));
}
