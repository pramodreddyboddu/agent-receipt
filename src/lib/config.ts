import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

export interface AgentReceiptConfig {
  outDir: string;
  defaultAgent: string;
  defaultCommits: number;
  fullDiffs: boolean;
}

const DEFAULTS: AgentReceiptConfig = {
  outDir: '.agent-receipt/receipts',
  defaultAgent: 'agent',
  defaultCommits: 1,
  fullDiffs: false,
};

const CONFIG_NAME = '.agent-receipt.yml';

export function configPath(cwd: string): string {
  return join(cwd, CONFIG_NAME);
}

/** Tiny YAML subset reader (key: value, booleans, numbers, strings). */
export function parseSimpleYaml(text: string): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line || line.startsWith('---')) continue;
    const m = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    let val = m[2].trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (val === 'true') out[key] = true;
    else if (val === 'false') out[key] = false;
    else if (/^-?\d+$/.test(val)) out[key] = parseInt(val, 10);
    else out[key] = val;
  }
  return out;
}

export function loadConfig(cwd: string): AgentReceiptConfig {
  const path = configPath(cwd);
  if (!existsSync(path)) return { ...DEFAULTS };
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
  };
}

export function writeDefaultConfig(cwd: string): { configFile: string; notesFile: string } {
  const configFile = configPath(cwd);
  const yaml = `# agent-receipt configuration
# https://github.com/pramodreddyboddu/agent-receipt

outDir: .agent-receipt/receipts
defaultAgent: agent
defaultCommits: 1
fullDiffs: false
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
   npx agent-receipt capture --agent claude --message "refactor auth"
   \`\`\`

4. Verify integrity later:

   \`\`\`bash
   npx agent-receipt verify
   \`\`\`

5. Add \`.agent-receipt/receipts/\` to git if you want receipts committed,
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
