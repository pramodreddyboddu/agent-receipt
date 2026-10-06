/**
 * One tool call parsed from an agent transcript.
 * `files` are cwd-relative paths the call mentioned.
 * `writes` are the subset from an explicit file-write tool.
 * A shell command is not scanned for paths.
 */
export interface ToolCallEvent {
  tool: string;
  argsSummary: string;
  files: string[];
  writes: string[];
  command: string | null;
  exitStatus: number | null;
  timestamp: string | null;
}

/** `ok` with an empty `events` list is a real zero-call transcript. */
export interface ParseResult {
  ok: boolean;
  events: ToolCallEvent[];
  reason?: string;
}

export interface InstallOptions {
  /** Also install the optional Stop hook. Claude, Codex, and Cursor honor this. */
  stop?: boolean;
  /** Report the paths and write nothing, including no backup. */
  dryRun?: boolean;
}

export interface UninstallOptions {
  /** Report the paths and write nothing. */
  dryRun?: boolean;
  /**
   * Write the snapshot bytes back even when the file changed after install.
   * Without this flag a changed file is stripped instead of restored.
   */
  force?: boolean;
}

export interface FileVerb {
  path: string;
  verb: 'restored' | 'stripped' | 'wrote' | 'unchanged';
}

export interface InstallResult {
  /** Paths this adapter manages, in a stable order. */
  files: string[];
  /** Subset whose bytes changed, or would change on a dry-run. */
  changed?: string[];
  /** How uninstall described each path. Install leaves this unset. */
  verbs?: FileVerb[];
  /** Absolute paths whose bytes differ from the post-install snapshot. */
  userChanged?: string[];
}

export type AdapterInstallStatus = 'full' | 'partial' | 'absent';

export interface AdapterStatus {
  name: string;
  detected: boolean;
  installed: boolean;
  status: AdapterInstallStatus;
  detail: string;
}

export interface AgentAdapter {
  name: string;
  detect(cwd: string): boolean;
  status(cwd: string): AdapterStatus;
  install(cwd: string, opts?: InstallOptions): InstallResult;
  uninstall(cwd: string, opts?: UninstallOptions): InstallResult;
  parseTranscript(filePath: string, cwd?: string): ParseResult;
}
