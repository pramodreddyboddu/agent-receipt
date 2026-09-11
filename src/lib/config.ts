import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

export interface AgentReceiptConfig {
  outDir: string;
  defaultAgent: string;
  defaultCommits: number;
  fullDiffs: boolean;
  /** Path globs excluded from risk / summary / file tables (noise). */
  ignore: string[];
}

const DEFAULTS: AgentReceiptConfig = {
  outDir: '.agent-receipt/receipts',
  defaultAgent: 'agent',
  defaultCommits: 1,
  fullDiffs: false,
  ignore: ['node_modules/**', 'dist/**', 'coverage/**'],
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
    else if (val.includes(',') && (key === 'ignore' || key.endsWith('Ignore'))) {
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

function asStringList(v: YamlValue | undefined, fallback: string[]): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string' && v.trim()) {
    return v.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return [...fallback];
}

export function loadConfig(cwd: string): AgentReceiptConfig {
  const path = configPath(cwd);
  if (!existsSync(path)) return { ...DEFAULTS, ignore: [...DEFAULTS.ignore] };
  const parsed = parseSimpleYaml(readFileSync(path, 'utf8'));
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

7. Health check: \`agent-receipt doctor\`

8. CI / hooks that should fail on secrets:

   \`\`\`bash
   agent-receipt capture --fail-on high
   \`\`\`

9. Agent-specific tips: see \`docs/agents.md\` in the package / repo.

10. Add \`.agent-receipt/receipts/\` to git if you want receipts committed,
    or keep them local / artifact-only.
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
