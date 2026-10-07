import { VERSION } from './version.js';

const TOPICS: Record<string, string> = {
  init: `agent-receipt init — write config + setup notes

Usage:
  agent-receipt init [--cursor] [--grok] [--claude] [--codex] [--org] [--retention] [--auto-prune] [--cwd <path>]

Options:
  --cursor               Drop .cursor/rules/agent-receipt.mdc and sessionEnd and stop hooks
  --grok                 Drop .grok rule + SessionEnd hook (dirty-tree wrap, --redact)
  --claude               Drop Claude Code SessionEnd and Stop hooks plus a project rule
  --codex                Drop Codex SessionEnd and Stop hooks plus a marked AGENTS.md block
  --org                  Set redact: true and failOn: high (alias: --policy)
  --policy               Alias of --org
  --retention            Set maxCount: 100 and maxAgeDays: 30 (does not set autoPrune)
  --auto-prune           Set autoPrune: true (does not replace ignore, redact, or limits)

\`--org\` and \`--policy\` are the same path. No network.

Missing \`.agent-receipt.yml\`: write the usual init file with \`redact: true\`
and \`failOn: high\` enabled (not commented), plus setup notes.

Existing file: merge in place. Every active \`redact\` / \`failOn\` line is set
to those values. A commented \`# redact:\` or \`# failOn:\` line is uncommented
only when that key has no active line. A missing key is appended.
\`ignore\`, \`riskAllowlist\`, \`outDir\`, retention keys (\`maxCount\`,
\`maxAgeDays\`), \`sign\`, and other comments stay. Re-running when both keys are
already set exits 0 and does not rewrite them.

\`init --org\` does not set \`sign\`. Keys may be absent. After
\`agent-receipt keygen\` and \`agent-receipt trust add --self\`, add
\`sign: true\` so capture, wrap, and watch sign. CLI \`--no-sign\` overrides.
Missing keys print a tip and leave the receipt unsigned (not exit 2).

Prints the config path and whether each key was set or unchanged, then
suggests \`doctor --strict\`. See examples/org-policy.yml for the full
example — do not copy it over a local ignore list.

\`--retention\` is the same merge style for the two retention keys
(\`maxCount: 100\`, \`maxAgeDays: 30\` — the disk-pressure / org-policy
tips). A missing file is a normal init config with those keys enabled.
An existing file rewrites only those keys. \`ignore\`, \`redact\`,
\`failOn\`, \`outDir\`, \`autoPrune\`, and comments stay. Re-running when both are
already set exits 0 and does not rewrite them. Prints whether each key
was set or unchanged, then suggests \`prune --dry-run\`. No network.
Trusted prune still refuses to delete when the audit chain is broken.
\`--retention\` does not turn \`autoPrune\` on.

\`--auto-prune\` sets \`autoPrune: true\` the same way. It does not replace
\`ignore\`, \`redact\`, \`failOn\`, or the retention limits, and it does not
delete anything by itself. Combine with \`--retention\` when you want both.
Capture, wrap, and watch then run trusted prune after a successful write
when a limit is set. That path does not pass \`--force\`. A broken audit
chain skips the delete and does not fail the capture. \`--no-prune\` overrides
for one run. Not a daemon.

Creates:
  .agent-receipt.yml          config (outDir, agent, ignore globs, …)
  .agent-receipt/SETUP.md     short next-steps (when the config is created)
  .cursor/rules/…             only with --cursor
  .grok/rules/…               only with --grok (loaded every Grok session)
  .grok/hooks/…               only with --grok (SessionEnd; needs grok --trust)
  .claude/settings.json       only with --claude (SessionEnd and Stop)
  .codex/hooks.json           only with --codex (SessionEnd and Stop; AGENTS.md markers)

\`init --claude\`, \`init --codex\`, \`init --cursor\`, and \`init --grok\` call the same installers as \`adapters install\`. The first install snapshots the previous file bytes. A later install refreshes that snapshot when the file changed. See \`help adapters\`.

Examples:
  agent-receipt init
  agent-receipt init --org
  agent-receipt init --policy
  agent-receipt init --retention
  agent-receipt init --auto-prune
  agent-receipt init --retention --auto-prune
  agent-receipt init --cursor
  agent-receipt init --grok
  agent-receipt init --claude
  agent-receipt init --codex
  agent-receipt init --cwd ~/code/my-app
`,

  adapters: `agent-receipt adapters — native capture hooks for Claude Code, Cursor, Grok, and Codex

Usage:
  agent-receipt adapters [list|status|install|uninstall] [name] [--dry-run] [--json] [--stop|--no-stop] [--force]

\`list\` (default) and \`status\` print whether each agent command is on PATH and whether this repo has the project hook. \`install\` merges the hook into the project config. \`uninstall\` puts the pre-install bytes back when the file is unchanged since install.

Names: \`claude-code\` (alias \`claude\`), \`cursor\`, \`grok\`, \`codex\`. Omit the name to install or uninstall every adapter.

The first install copies each file it is about to change. The copy lives under the git dir (\`git rev-parse --git-path\`), keyed to the project root, not the process cwd. A later install refreshes that snapshot when the file changed after install. Uninstall restores the snapshot when the file still matches the post-install hash. When it does not, uninstall strips only this adapter's hooks and prints \`stripped\`. \`--force\` restores the snapshot anyway. With no snapshot, uninstall strips and does not say \`restored\`. A dry-run that would drop those edits prints \`would discard user changes\`. Existing keys and other hooks stay. Invalid JSON is refused and is not rewritten. \`hooks\` must be a JSON object, and each event we install must be an array. A symlink is refused. A read-only file fails with \`permission denied\` and leaves no snapshot.

\`--dry-run\` reports the paths and writes nothing, including no snapshot.
\`--no-stop\` skips the extra Stop hook on Claude Code, Codex, and Cursor. SessionEnd stays. Codex installs SessionEnd and Stop. Grok uses SessionEnd only.
\`--json\` prints one object: \`list\` / \`status\` use \`adapters\`; \`install\` / \`uninstall\` use \`results\` (\`files\`, \`changed\`).

Hook scripts exit 0. They wrap only when the tree is dirty, ignoring the receipt out dir and the store index and audit log wrap itself writes. Wrap stdout is discarded, and the hook stops waiting after 120 seconds. They pass \`--redact\`, and pass \`--transcript\` when the host sends \`transcript_path\`. Hook commands use \`git rev-parse --show-toplevel\`.

Examples:
  agent-receipt adapters
  agent-receipt adapters status --json
  agent-receipt adapters install claude-code --dry-run
  agent-receipt adapters install cursor --no-stop
  agent-receipt adapters uninstall grok
`,

  capture: `agent-receipt capture — snapshot a git range into a Markdown receipt

Usage:
  agent-receipt capture [options]

Options:
  --base <ref>           Changes vs a base branch/ref (e.g. main); shows commits ahead
  --since <ref>          Diff range start (e.g. main, HEAD~5, abc123)
  --commits <N>          Last N commits (default: config or 1)
  --uncommitted          Snapshot dirty working tree (staged+unstaged+untracked)
  --message <text>       Session message. Multiple lines are kept, quoted and indented
                         so they cannot form header fields
  --agent <name>         Agent label (default: config or "agent"). Free-form;
                         spaces allowed. No newlines or control characters.
  --session <id>         Session id. Same values as 1.0.27, including spaces
                         and slashes, stored as one line. \`new\` generates s- + 16 hex.
  --parent <ref>         Parent receipt: r- id, sha256, or a path to a receipt file
  --host <label>         Host label. Omitted unless this flag or AGENT_RECEIPT_HOST
  --out <path>           Output Markdown path
  --full                 Include full diffs (no truncation)
  --json                 Write companion .json AND print one CI gate object on stdout
                         (human progress goes to stderr). See docs/business.md.
  --diff-stat            Include diff-stat overview (default: on)
  --no-diff-stat         Omit the diff-stat overview
  --top-risks <N>        Max risk rows in findings table (default: 20)
  --redact               Mask high/secret findings for safer sharing (re-hashed)
  --no-redact            Force redact off (overrides config redact: true)
  --fail-on [high|medium|low]
                         Exit 2 after writing if max severity meets threshold.
                         Bare --fail-on means high. Overrides config failOn.
                         Exit codes: 0 pass, 2 policy failure, 1 usage error.
  --sign                 After a successful write, if local Ed25519 keys
                         exist, write *.sig.json beside the receipt
                         (same sidecar as \`sign\`). Also on when config
                         \`sign: true\`. Missing keys print a tip and leave
                         the file unsigned. That does not exit 2.
                         Not a CA. CI composite sign: true fails closed
                         without keys (docs/ci-signed-gate.md).
  --no-sign              Force signing off (overrides config sign: true)
  --prune                After a successful write, run trusted prune when
                         maxCount and/or maxAgeDays is set. Also on when
                         config autoPrune: true. Does not pass --force.
                         A broken audit chain skips the delete, warns on
                         stderr, and does not change this command's exit code.
  --no-prune             Force auto-prune off (overrides config and --prune)
  --transcript <file>    Record tool calls from this transcript (JSONL or JSON)
  --adapter <name>       Parser: claude-code, cursor, grok, or codex
  --policy-pack <name>   Evaluate a policy pack (repeatable). builtin:baseline
                         or a file. A comma-separated list is rejected;
                         repeat the flag. Union with config policyPacks.
                         Deny hits exit 2. Warn hits are reported. A missing
                         or invalid pack exits 1. See \`help policy\`.
  --cwd <path>           Run as if started in this directory

\`--transcript\` adds a \`## Tool calls\` section inside the hashed body.
MCP calls (\`mcp__server__tool\`, CallMcpTool, Codex \`mcp_tool_call\`,
JSON-RPC \`tools/call\`) are labeled \`mcp:<server>/<tool>\`. Arguments
are redacted before they are stringified: object keys matching
pass, pwd, secret, token, key, auth, cred, cookie, or session become
\`[REDACTED]\`, then the same secret patterns as \`--redact\` run, including
token prefixes after \`_\`, a high-entropy pass, and internal hosts such
as \`.corp\` and \`.lan\`. That happens even when \`--redact\` is off.
A shell command is not scanned for paths. A missing
or unparseable file warns on stderr, omits the section, and still exits 0.
An unknown \`--adapter\` exits 1. Omit \`--adapter\` and the transcript
is sniffed (Codex, Cursor, JSON-RPC, or Claude). An ambiguous file uses
\`--agent\` when that label is a known adapter. The companion JSON adds
\`toolCalls\`. Those companion fields are not covered by the receipt
integrity hash or the Ed25519 sidecar. Trust the hashed \`## Tool calls\`
section. Low-severity risks: \`tool-call-unmentioned-diff\` (a diff path
no call mentions) and \`tool-call-write-not-in-diff\` (a write tool whose
path is absent from the diff).

\`--no-prune\` wins, then \`--prune\`, then config \`autoPrune: true\`.
Absent or false: this command does not delete. \`autoPrune: true\` with no
retention limit deletes nothing. share, export, verify, prove, import,
and doctor do not auto-prune. Not a daemon.

Config \`.agent-receipt.yml\` may set \`redact: true\`, \`failOn: high\`, and
\`sign: true\` (see examples/org-policy.yml). Those apply when the flags
above are omitted. \`sign: true\` covers capture, wrap, and watch only.
\`init --org\` does not set \`sign\` (keys may be absent). After \`keygen\`
and \`trust add --self\`, add \`sign: true\`. \`--no-sign\` overrides.
Missing keys tip and leave the receipt unsigned (not exit 2).

Link fields (session, parent, agent, host, and an r- id) are written into the
\`## Session\` header block only when a flag or env var is set. Flags win over
AGENT_RECEIPT_SESSION, AGENT_RECEIPT_PARENT, AGENT_RECEIPT_AGENT, and
AGENT_RECEIPT_HOST. \`--agent\` is a free-form label (spaces allowed; no
newlines, control characters, or more than 256 characters). Config
\`defaultAgent\` uses the same rules. \`--session\` accepts the values 1.0.27
stored, including spaces and slashes, as a single line of at most 256
characters. Generated ids are \`s-\` + 16 hex. \`--host\` is 1–64 of
[A-Za-z0-9._:-]. \`--parent\` is an r- id, a 64-hex sha256, or a path that
parses as a receipt file (not an arbitrary file). \`--message\` may span
lines; continuation lines are quoted and indented so they are not header
fields. Invalid link values fail before a file is written. Host is privacy-sensitive
and is not recorded unless you pass --host or set AGENT_RECEIPT_HOST.
\`share\` keeps session, parent, and agent, and masks host unless
--include-host. A local \`capture --redact\` keeps an explicitly requested host.

Each capture under outDir updates .agent-receipt/index.json (stable receipt index).
Captures with --out outside outDir are not indexed (so they do not become newest)
and are not listed by \`session\`.
Appends one line to \`.agent-receipt/audit.jsonl\` (no diff body, no --message).
See \`help audit\`. Wrap records a wrap line instead of a second capture line.

Examples:
  agent-receipt capture --agent cursor --message "ship auth"
  agent-receipt capture --base main --agent cursor --message "PR branch"
  agent-receipt capture --uncommitted --agent cursor --message "wip"
  agent-receipt capture --since main --full --json --session s-42
  agent-receipt capture --commits 3 --no-diff-stat
  agent-receipt capture --redact --out share.md
  agent-receipt capture --fail-on high
`,

  wrap: `agent-receipt wrap — one-shot end-of-session capture + TL;DR + verify

Usage:
  agent-receipt wrap [options] [-- command ...]

If the working tree is dirty (and --base is not set), captures with --uncommitted;
otherwise captures commits (optionally vs --base). Explicit --base always uses a
commit range even if the tree is dirty. Prints TL;DR + path, then verifies.

Options:
  --agent <name>         Agent label (default: wrap). Free-form; spaces allowed
  --session <id>         Session id. \`--session new\` generates s- + 16 hex.
                         Other values may include spaces and slashes (1.0.27).
  --parent <ref>         Parent receipt: r- id, sha256, or a path to a receipt file
  --host <label>         Host label (strict charset). Omitted unless set
  --link                 Record a session (reuse env, or generate) and run the
                         command after -- with this receipt as its parent
  --message <text>       Session message (default: "session wrap"). Multiple lines are allowed
  --base <ref>           When clean, capture vs this base branch/ref
  --uncommitted          Require dirty-tree capture (error if clean)
  --redact               Mask high/secret findings in the written receipt
  --no-redact            Force redact off (overrides config redact: true)
  --fail-on [high|medium|low]
                         Exit 2 after writing if max severity meets threshold.
                         Bare --fail-on means high. Overrides config failOn.
  --json                 Companion .json plus one CI gate object on stdout
                         (human progress on stderr). Exit codes stay 0 / 2 / 1.
  --full                 Include full diffs
  --sign                 After capture, write *.sig.json when local keys
                         exist (same as \`sign\`). Also on when config
                         \`sign: true\`. Missing keys print a tip and leave
                         the receipt unsigned. Not exit 2. Not a CA.
                         CI composite sign: true fails closed without keys
                         (docs/ci-signed-gate.md).
  --no-sign              Force signing off (overrides config sign: true)
  --prune                After a successful write, run trusted prune when
                         retention is enabled (also on when config
                         autoPrune: true). No --force. A broken audit chain
                         warns and does not change the exit code.
  --no-prune             Force auto-prune off (overrides config and --prune)
  --transcript <file>    Record tool calls from this transcript (same as capture)
  --adapter <name>       Parser: claude-code, cursor, grok, or codex
  --cwd <path>           Run as if started in this directory

\`--transcript\` and \`--adapter\` match \`capture\`. Tool arguments are
redacted even when \`--redact\` is off. A missing transcript warns and
the receipt is still written. An unknown adapter exits 1.

\`--no-prune\` wins, then \`--prune\`, then config \`autoPrune: true\`.
\`--json\` adds \`autoPrune\`, \`pruned\`, and \`pruneReason\` only when this
run attempted auto-prune. Those keys are omitted when it was off.
\`pruneReason\` is null when the trusted prune ran, or \`failed-run\`
(fail-on or verify failure: nothing deleted), \`retention-off\`,
\`chain-broken\`, or \`error\`.

\`sign: true\` in \`.agent-receipt.yml\` signs this command when neither
flag is passed. \`init --org\` does not set \`sign\` (keys may be absent).
Add it after \`keygen\` and \`trust add --self\`. \`--no-sign\` overrides.
share, export, prove, and verify do not read config \`sign\`.

Exit codes: 0 OK, 2 fail-on threshold or verify failure, 1 usage/runtime error.
\`--json\` does not change those codes. Both failures still exit 2; the gate
object sets \`failedOn\` and \`verified\` so CI can tell them apart.
A line is appended to \`.agent-receipt/audit.jsonl\` (see \`help audit\`).

Linking (\`help session\`):
  --link, or an explicit --session (including \`new\`), writes a session id
  and an r- id into this receipt. When a command follows \`--\`, wrap exports
  AGENT_RECEIPT_SESSION and AGENT_RECEIPT_PARENT (this receipt's id) and
  runs that command. The child starts in the process working directory,
  not in \`--cwd\` — pass \`--cwd\` on the child when the parent used it.
  The child's exit code is printed and does not change wrap's exit code.
  Do not combine \`--json\` with a child that also prints JSON (stdout would
  mix). A nested wrap with no --link and no --session still records the
  exported session and parent. Pass --link on that child as well when it
  should export its own id to a grandchild. With no --link and no --session,
  arguments after \`--\` are ignored and no link fields are written.
  Auto-prune can delete the parent later; \`session\` then flags the child
  as an orphan. Receipts outside outDir are not listed.

Examples:
  agent-receipt wrap --agent cursor --message "done with auth"
  agent-receipt wrap --link --session new --agent parent -- node agent-receipt wrap --agent child
  agent-receipt wrap --agent grok --redact --message "grok session"
  agent-receipt wrap --agent grok --redact --uncommitted --message "wip"
  agent-receipt wrap --agent cursor --base main
  agent-receipt wrap --fail-on high
  agent-receipt wrap --json --fail-on high
`,

  share: `agent-receipt share — redact, write HTML (+ optional Markdown), verify

Usage:
  agent-receipt share [path] [--out <html>] [--md [file]] [--package] [--no-redact] [--fail-on …] [--json]

One shot for handing a receipt to someone else. Reuses export / html / verify /
redact (share-safety from 1.0.3: credential URLs, nested receipt bodies).

Defaults:
  - Newest receipt under outDir when path is omitted
  - --redact is ON unless you pass --no-redact (config redact: false does not turn this off)
  - HTML next to the receipt (sibling .html)
  - Optional Markdown only when --md / --markdown is set
  - --package (alias --pack) writes both HTML and Markdown into a directory
  - Refuses to overwrite the source receipt
  - Does not write anything if the source receipt fails verify (no re-hash of a tampered body)

Prints TL;DR, html path, optional md path, optional sig path, source path, then verify.
\`--package\` also prints \`package: <dir>\` and a tip to verify the Markdown inside it.

Markdown sidecar handoff (HTML is never signed):
  - Published Markdown sha256 matches the source, and a valid source
    \`*.sig.json\` exists → that sidecar is copied beside the published \`.md\`.
  - Redact (or any rewrite) changes the sha256 → the old sidecar is not copied.
    When local keys exist, the published Markdown is re-signed. When they do
    not, the file is left unsigned and a short \`keygen\` / \`sign\` tip is printed.
    That does not exit 2 by itself.
  - HTML-only share writes no signature. Peers verify and sign the Markdown.

\`--package\` / \`--pack\` (portable handoff directory):
  - Default directory is the sibling \`<stem>.share/\` (\`foo.md\` → \`foo.share/\`).
  - \`--out\` overrides that directory when it names an existing directory or
    ends with \`/\`. Any other \`--out\` leaves the sibling \`<stem>.share/\`.
  - Always writes \`receipt.html\` and \`receipt.md\` (implies \`--md\`). A separate
    \`--md\` path is not a second file.
  - Applies the same Markdown sidecar handoff to \`receipt.sig.json\`.
  - Writes \`manifest.json\` (kind \`agent-receipt-share\`, receipt sha256, per-file
    byte hashes, fingerprint, signed). See \`docs/share-package.schema.json\`.
  - When local keys load, also writes \`manifest.sig.json\` — the same Ed25519
    sidecar shape as \`sign\`, over the UTF-8 hex sha256 of the manifest bytes.
    Missing keys omit \`manifest.sig.json\`. That does not exit 2.
  - The HTML body stays unsigned. The package is signed via \`receipt.sig.json\`
    and the optional manifest sidecar.
  - \`last\`, \`history\`, and \`prune\` ignore \`*.share/\` directories. \`manifest.json\`
    and the files inside the package are not receipts.
  - \`--json\` adds \`packagePath\` and points \`htmlPath\` / \`markdownPath\` / \`sigPath\`
    at the files inside the package. Without \`--package\`, those fields stay
    as they are today and \`packagePath\` is omitted.
  - Peers check the directory with \`verify --package\` (alias \`--pack\`) or
    copy the proved Markdown with \`import\`. See \`help verify\` and \`help import\`.

Options:
  --out <path>           HTML output (default: sibling .html). With --package,
                         the package directory when <path> is an existing
                         directory or ends with /.
  --md [path]            Also write Markdown (default name: sibling .redacted.md)
  --markdown [path]      Alias for --md
  --package              Write <stem>.share/ with receipt.html, receipt.md,
                         manifest.json, and optional sidecars. Implies Markdown.
  --pack                 Alias for --package
  --redact               Accepted; this is already the default
  --no-redact            Write HTML/Markdown without masking
  --fail-on [high|medium|low]
                         Exit 2 if the source summary meets the threshold
                         (counts are not cleared by redaction). Bare = high.
                         Config failOn applies when the flag is omitted.
  --json                 One CI gate object on stdout (progress on stderr).
                         Adds sigPath (string or null) when Markdown was written.
                         Adds packagePath when --package wrote a directory.
  --include-host         Keep the Host label. Default share masks it as
                         [REDACTED]. Session, parent, and agent always stay.
                         --no-redact skips masking, so host remains too.
  --cwd <path>           Run as if started in this directory

Exit codes: 0 OK, 2 verify failure or --fail-on, 1 usage/runtime error.
Share does not enable \`verify --require-sig\`. A missing sidecar on a
rewritten Markdown file is a tip, not exit 2.
Appends \`.agent-receipt/audit.jsonl\` (experimental hash chain; see \`help audit\`).
One \`share\` event. The inner export is not a second line.

Examples:
  agent-receipt share
  agent-receipt share --out share.html --md share.md
  agent-receipt share --package
  agent-receipt share --pack receipt.md
  agent-receipt share receipt.md --fail-on high --json
`,

  attest: `agent-receipt attest — in-toto Statement v1 in a DSSE envelope

Usage:
  agent-receipt attest [path|last] [--out <file>] [--predicate run|slsa] [--slsa] [--session <id>] [--no-sign] [--json]
  agent-receipt attest [path|last] --keyless [--identity-token <file|->] [--fulcio-url <url>] [--rekor-url <url>] [--json]
  agent-receipt attest --verify <file.intoto.jsonl> [--trusted-key <fp>] [--json]
  agent-receipt attest --verify <file.sigstore.json> --certificate-identity <id> --certificate-oidc-issuer <issuer> [--trusted-root <file>] [--json]
  agent-receipt attest verify <file.intoto.jsonl>
  agent-receipt export [path] --format intoto

Writes one DSSE envelope per line (\`.intoto.jsonl\`). Payload type is
\`application/vnd.in-toto+json\`. The statement \`_type\` is
\`https://in-toto.io/Statement/v1\`. The default predicate is
\`https://agent-receipt.dev/run/v1\` (agent, session, commands, tool calls,
policy hits, exit code, hash-chain head). \`--slsa\` or \`--predicate slsa\`
uses \`https://slsa.dev/provenance/v1\` (\`buildDefinition\` and \`runDetails\`).

Subjects are the receipt file and changed files that are still regular files
under the byte cap, each with a sha256 of the raw bytes. The hash-chain head
is the receipt canonical sha256 (the hex \`verify\` prints), not the raw file
digest. Paths are relative to the working directory. Host and workspace are
omitted. Narrative fields are redacted before they enter the predicate.
There is no \`--no-redact\`.

A local Ed25519 key signs the DSSE pre-authentication encoding (PAE), not
the receipt sha256 hex. \`keyid\` is the same fingerprint as \`sign\`. The
envelope also carries the SPKI public key so a peer can check it. The
private key is never written. Missing keys write an unsigned envelope, warn,
and exit 0. \`--no-sign\` does the same. A corrupt key file exits 1 and
writes nothing. A receipt that fails integrity exits 2 and writes nothing.
\`sign --keyless\` is not a command. Keyless signing is \`attest --keyless\`.

\`attest --keyless\` signs one receipt with an ephemeral P-256 key that is
never stored. The OIDC token comes from \`--identity-token <file>\` (use
\`-\` for stdin), else \`SIGSTORE_ID_TOKEN\`, else the GitHub Actions
ambient token (\`ACTIONS_ID_TOKEN_REQUEST_URL\` with audience \`sigstore\`).
Fulcio (default \`https://fulcio.sigstore.dev\`, \`--fulcio-url\`) issues a
short-lived certificate. Rekor (default \`https://rekor.sigstore.dev\`,
\`--rekor-url\`) records the entry. The bundle is
\`application/vnd.dev.sigstore.bundle.v0.3+json\`, written as
\`<stem>.sigstore.json\` beside the \`.intoto.jsonl\`. The token is never
written and never logged. A network error, HTTP error, or timeout exits 1
and writes nothing. \`--keyless\` conflicts with \`--no-sign\` and signs
one receipt only. See \`docs/keyless.md\`.

\`attest --verify\` checks the signature, each subject digest against the
file on disk, and the hash-chain head against the receipt. Unsigned, a bad
signature, an untrusted fingerprint (when the allowlist is active), a
digest mismatch, or a hash mismatch exits 2. A missing file exits 1.
An empty trust store accepts any cryptographically valid signature and
prints a note (\`trusted\` is null). This is not a CA.

A \`.sigstore.json\` bundle is checked offline. Pass exactly one of
\`--certificate-identity\` or \`--certificate-identity-regexp\`, and
\`--certificate-oidc-issuer\`. Missing identity or issuer exits 1. The
certificate must chain to the trusted root (embedded public-good Fulcio
and Rekor, or \`--trusted-root\`), be valid at the Rekor integrated time,
match the SAN and issuer, and the DSSE, signed entry timestamp, and
inclusion proof must verify. A bad signature, identity, issuer, or time
exits 2. The Ed25519 allowlist is not consulted for a bundle. An ECDSA
signature inside \`.intoto.jsonl\` is not a substitute for the bundle.

One receipt writes \`<stem>.intoto.jsonl\` beside that receipt. A session
package writes \`<id>.intoto.jsonl\` beside the package. \`--session <id>\`
writes \`<id>.intoto.jsonl\` beside \`outDir\`. \`--out\` is a file, or a
directory when it exists or the path ends with \`/\`. The command does not
append the audit log.

Options:
  --out <path>           Output file or directory (default: beside the input)
  --predicate <run|slsa> Predicate (default: run). \`--slsa\` is the short form
  --session <id>         Every local receipt in that session, one envelope each
  --no-sign              Write an unsigned envelope even when keys exist
  --keyless              Sign with Sigstore (ephemeral P-256, Fulcio, Rekor)
  --identity-token <f>   OIDC token file, or \`-\` for stdin (else env, else Actions)
  --fulcio-url <url>     Fulcio base URL (default: public-good Fulcio)
  --rekor-url <url>      Rekor base URL (default: public-good Rekor)
  --verify <file>        Check a \`.intoto.jsonl\` or a \`.sigstore.json\` bundle
  --certificate-identity <id>     Required SAN (email or URI) for a bundle
  --certificate-identity-regexp <re>  Full-match SAN pattern. Not with --certificate-identity
  --certificate-oidc-issuer <url> Required OIDC issuer for a bundle
  --trusted-root <file>  Sigstore trusted_root.json. Replaces the embedded root
  --trusted-key <fp>     Extra fingerprint for an Ed25519 verify only
  --json                 One JSON object on stdout. Warnings stay on stderr
  --cwd <path>           Run as if started in this directory

Exit codes: 0 written, or every envelope verified. 2 integrity, signature,
digest, or hash-chain failure. 1 usage, a missing file, or a corrupt key.

Examples:
  agent-receipt attest
  agent-receipt attest last --slsa --json
  agent-receipt attest --session my-session
  agent-receipt attest .agent-receipt/my-session.session
  agent-receipt attest --verify .agent-receipt/receipts/receipt.intoto.jsonl
  agent-receipt attest --keyless --identity-token oidc.jwt
  agent-receipt attest --verify receipt.sigstore.json --certificate-identity https://github.com/org/repo --certificate-oidc-issuer https://token.actions.githubusercontent.com
  agent-receipt export --format intoto
`,

  export: `agent-receipt export — write a shareable HTML (or Markdown) receipt

Usage:
  agent-receipt export [path] [--out <file>] [--redact] [--format html|markdown]
  agent-receipt export [path] --format intoto

If path is omitted, exports the newest receipt under outDir.
Default format is self-contained HTML (no external CSS/JS) — open in a browser
or share as a single file.

\`--format intoto\` (aliases \`in-toto\`, \`dsse\`) writes the same
\`.intoto.jsonl\` DSSE envelope as \`attest\`. It always redacts the
predicate and does not append the audit log. See \`help attest\`.

Options:
  --out <path>           Output path (default: sibling .html next to the receipt)
  --redact               Mask high/secret findings before writing
  --include-host         With --redact, keep the Host label (default: mask it).
                         Not accepted with \`--format intoto\` (Host is omitted).
  --format <html|markdown|md|intoto>
                         Output format (default: html)
  --cwd <path>           Run as if started in this directory

Markdown output uses the same sidecar rule as \`share\`: copy a valid source
sidecar when the sha256 is unchanged, or re-sign the published file when
local keys exist and the body was rewritten. HTML stays unsigned. Peers
verify and sign the Markdown.

HTML and Markdown append \`.agent-receipt/audit.jsonl\` (event \`export\`).
\`--format intoto\` does not. \`share\` records \`share\` instead, so an
export made by share is not a second line. The line stores the output path
and the markdown body's sha256 — not the HTML bytes and not a diff.

Examples:
  agent-receipt export
  agent-receipt export --out share.html --redact
  agent-receipt export receipt.md --format markdown --redact --out safe.md
  agent-receipt export --format intoto
`,

  html: `agent-receipt html — alias for export as self-contained HTML

Usage:
  agent-receipt html [path] [--out <file>] [--redact]

Examples:
  agent-receipt html
  agent-receipt html --out session.html --redact
`,

  show: `agent-receipt show — print a receipt body

Usage:
  agent-receipt show [path]

If path is omitted, shows the newest receipt under configured outDir.

Examples:
  agent-receipt show
  agent-receipt show .agent-receipt/receipts/receipt-….md
`,

  last: `agent-receipt last — path + glance of the newest receipt

Usage:
  agent-receipt last [--path] [--json]

Options:
  --path                 Print only the absolute path (scripting)
  --json                 One JSON object on stdout (not the CI gate):
                           { ok, command: "last", version, path, sha256,
                             agent, message, timestamp, failedOn,
                             uncommitted, tldr }
                         ok is true. No receipt still exits 1 (stderr),
                         same as the human command.
                         Agent, failedOn, uncommitted, and sha256 prefer
                         the index row when that receipt is listed. Otherwise
                         they come from the Markdown glance. failedOn on an
                         older row (no stored bit) is high severity only.
                         With both --json and --path, --json wins.

Examples:
  agent-receipt last
  agent-receipt last --json
  agent-receipt last --path | xargs agent-receipt verify
`,

  history: `agent-receipt history — list recent receipts

Usage:
  agent-receipt history [--limit <N>] [--json] [--agent <name>] [--uncommitted] [--failed]
  agent-receipt ls [--limit <N>] [--json] [--agent <name>] [--uncommitted] [--failed]

Shows newest-first: time, agent, risk counts, short summary.
Uncommitted (dirty-tree) receipts get a visible [uncommitted] badge.
Receipts that failed the gate get a visible [failed] badge.
'--json' prints a JSON array (prefers .agent-receipt/index.json when present;
otherwise scans outDir). The scan applies the same filters. Each row includes
\`failedOn\`. Scan rows also include \`uncommitted\`.

Listing filters (optional; \`ls\` accepts the same flags):

  \`--agent <name>\`   exact, case-sensitive match on the \`agent\` field.
                     Receipts with \`agent: null\` (or a missing agent) do not
                     match any \`--agent\` filter.
  \`--uncommitted\`    keep receipts where \`uncommitted\` is true
  \`--failed\`         keep receipts that failed the gate. An index row with
                     \`failedOn\` uses that boolean (a stored \`false\` stays
                     out even when risk is high). Older rows, which omit the
                     field, match when \`risk.high > 0\` or \`risk.maxSeverity\`
                     is \`high\`. A scan matches a high-severity risk row.
                     Medium or low alone does not match.

Filter order: load receipts → \`--agent\` (if set) → \`--uncommitted\` (if set)
→ \`--failed\` (if set) → \`--limit\` (newest N of the filtered set) → print.
Human listing is newest first. \`--json\` prints that same slice.

No matches is exit 0: an empty human listing, or \`[]\` with \`--json\`.
Not an error. An empty receipt store (nothing under outDir, so no filter
would help) still errors, same as \`history\` with no flags.
\`--agent\` requires a name. \`--failed\` does not take a value. An unknown flag exits 1.

Known flags: \`--limit\`, \`--json\`, \`--agent\`, \`--uncommitted\`, \`--failed\`, \`--cwd\`.

Options:
  --limit <N>            Max rows after filters (default: 20)
  --json                 Machine-readable JSON array
  --agent <name>         Exact agent match (case-sensitive)
  --uncommitted          Dirty-tree snapshots only
  --failed               Gate failures only (takes no value)
  --cwd <path>           Run as if started in this directory

Examples:
  agent-receipt history
  agent-receipt history --json --limit 5
  agent-receipt history --agent cursor
  agent-receipt history --uncommitted --json
  agent-receipt history --failed
  agent-receipt history --agent ci --failed --json
  agent-receipt history --agent ci --uncommitted --limit 5
  agent-receipt ls --agent ci --limit 5
`,

  ls: `See: agent-receipt help history`,

  watch: `agent-receipt watch — poll git and auto-capture on commits or dirty tree

Usage:
  agent-receipt watch [--interval <sec>] [--once] [--commits-only] [--agent <name>] [--message <text>] [--fail-on …] [--sign] [--no-sign] [--prune] [--no-prune]

Defaults: poll every 5 seconds; watch **commits + dirty tree** until Ctrl+C.
Dirty-tree captures are labeled **uncommitted**.
--commits-only: restore v0.4 HEAD-only behavior.
--once: wait for the next change, capture once, exit (Cursor / agent “run after session”).

Options:
  --interval <sec>       Poll interval (default: 5, min 1, max 3600)
  --once                 Capture after the next change, then exit
  --commits-only         Only watch HEAD commits (ignore dirty tree)
  --agent <name>         Agent label (default: watch)
  --session <id>         Session id recorded on each capture in this watch
                         (1.0.27 values allowed; one line)
  --parent <ref>         Parent receipt: r- id, sha256, or a local receipt path
  --host <label>         Host label. Omitted unless this flag or AGENT_RECEIPT_HOST
  --message <text>       Session message
  --fail-on [high|medium|low]
                         After capture, exit 2 when --once if threshold met
  --json                 Also write companion .json on each capture
                         (human stdout stays; CI gates use capture/wrap/share/verify --json)
  --sign                 Sign each capture when local keys exist (also on
                         when config sign: true). Missing keys tip and leave
                         the receipt unsigned. Not exit 2. Not a CA.
  --no-sign              Force signing off (overrides config sign: true)
  --prune                After each successful capture, run trusted prune
                         when retention is enabled (also on when config
                         autoPrune: true). No --force. A broken chain warns
                         and does not change the exit code.
  --no-prune             Force auto-prune off (overrides config and --prune)
  --cwd <path>           Run as if started in this directory

\`--no-prune\` wins, then \`--prune\`, then config \`autoPrune: true\`.
Config \`sign: true\` is passed through to each capture. \`init --org\` does
not set \`sign\`. \`--no-sign\` overrides. share, export, prove, and verify
do not read this key. Auto-prune runs after the watch audit line. Not a daemon.

When HEAD moves A → B, capture uses --since A so all commits in the interval are included.
When the working tree changes (and HEAD did not), capture uses --uncommitted.
Each successful capture appends one \`watch\` line to \`.agent-receipt/audit.jsonl\`
(not a second \`capture\` line). The session \`--message\` is not stored in the log.

Cursor / agent wrap-up:
  agent-receipt watch --once --interval 2 --agent cursor --message "session wrap-up"

Long session (leave a terminal running):
  agent-receipt watch --interval 5 --agent cursor

Examples:
  agent-receipt watch
  agent-receipt watch --once --agent cursor
  agent-receipt watch --commits-only --once
  agent-receipt watch --interval 10 --fail-on high
`,

  session: `agent-receipt session — list, export, or import one multi-agent session

Usage:
  agent-receipt session <id> [--json] [--cwd <path>]
  agent-receipt session export <id> [--out <dir>] [--include-host] [--resign] [--json]
  agent-receipt session pack <id>                  # alias of export
  agent-receipt session import <packageDir> [--dry-run] [--json] [--require-sig]
  agent-receipt session merge <packageDir>         # alias of import

List:
Scans the configured outDir for receipts whose Session header field equals
<id> and prints a parent/child tree. Link fields are read only from the
writer's \`## Session\` block, not from diffs or messages. Each line shows
the receipt id, pass/fail, exit 0 or 2, agent label, timestamp, and
verified or unverified.
\`orphan\` means the parent ref is not a receipt in this outDir (it may
live on another machine, or auto-prune deleted it). \`cycle\` means the
parent links loop inside this session. Orphans and cycles do not by
themselves change the exit code. A parent in a different local session
is not an orphan; the child is marked \`warnings=cross-session-parent\`.
A child whose local parent fails verify is \`warnings=parent-unverified\`.
A receipt with no Session line whose parent is in this session is listed
with \`warnings=missing-session\`.

\`--json\` for the list prints one object: command, ok, version, exitCode,
session, receipts[] (id, parent, agent, verified, exitCode, plus orphan,
cycle, warnings, timestamp, status, path), and reason. Parent is the
stored ref, or null. \`warnings\` is an array of those codes, or empty.

Exit 0 when every listed receipt verifies and no local parent fails verify.
Cross-session parents and a missing Session line do not by themselves
change the exit code.
Exit 1 when any receipt fails verify, when a local parent fails verify,
when the session has no local receipts, or on usage errors (missing id,
control characters, longer than 256 characters, unknown flag).
A receipt's own exitCode in the tree is 0 or 2. That is separate from
this command's exit code. Usage errors print on stderr. An empty session
with --json still prints the object on stdout and exits 1.

Receipts written with --out outside outDir are not listed.

Export (\`session export\`, alias \`session pack\`):
Writes a portable directory for every receipt the list would show,
including orphans and cycles. The default directory is the sibling of
outDir: \`.agent-receipt/receipts\` becomes
\`.agent-receipt/<id>.session/\`. A session id that is not one safe path
segment (spaces or slashes, such as \`old sess/1\`) is packed as
\`session-<sha256-12>.session\`. The manifest stores the real id.
\`--out <dir>\` is that directory. An existing path is refused and nothing
is written.
The package contains \`session-manifest.json\`, \`receipts/<basename>.md\`
for each receipt, and \`receipts/<basename>.sig.json\` when a sidecar was
copied or re-signed. See \`docs/session-package.schema.json\`.
Unless \`--include-host\`, export uses share's redaction function: secret
values are masked, a nested receipt or index diff body is replaced with
\`[REDACTED — nested receipt/index body omitted]\`, and the header Host
line becomes \`[REDACTED]\`. Session, parent, and agent stay. The receipt
is re-hashed. \`--include-host\` keeps the original bytes, including Host
and any secrets. \`share --include-host\` still masks secrets and nested
bodies; only session export's flag skips the pipeline.
A valid source sidecar is copied when the bytes do not change. A rewrite
whose sidecar fingerprint is the local key is re-signed when keys load,
and left unsigned (no stale sidecar) when they do not. A rewrite whose
sidecar was signed by a different key exits 2 and writes nothing.
\`--resign\` re-signs with the local key, prints both fingerprints on
stderr, and sets manifest \`resignedBy\`. \`originalFingerprint\` is the
source sidecar fingerprint, or null. \`fingerprint\` is the packaged
sidecar. An unsigned source whose bytes change is signed with the
exporter key when keys load. The manifest records that as \`signedBy\`
(equal to \`fingerprint\`) with \`originalFingerprint\` null, and export
warns on stderr. That signature is the exporter's, not the original
author's. A same-key rewrite leaves \`signedBy\` null. When keys load, \`session-manifest.sig.json\` is the same Ed25519
SignatureDocument as \`sign\`, over the UTF-8 hex sha256 of the manifest
bytes, including those fingerprint fields. Missing keys omit that file
and do not exit 2.
A receipt over 32 MiB, a sidecar over 256 KiB, or a manifest over 8 MiB
exits 2 before the file is read. \`--max-receipt-bytes\`,
\`--max-sidecar-bytes\`, and \`--max-manifest-bytes\` raise those caps.
Manifest \`warnings\` may include \`orphan\`, \`cycle\`,
\`cross-session-parent\`, \`parent-unverified\`, and \`missing-session\`.
Those receipts are still packed. A listed receipt that fails verify
exits 2 and writes nothing. An empty session exits 1 and writes nothing.
\`--json\` prints one object (command \`session-export\`) with packagePath,
manifestSigPath, receiptCount, warnings, and receipts[].
Export does not append the audit log and does not edit the index.
\`last\`, \`history\`, and \`prune\` ignore \`*.session/\` directories.

Import (\`session import\`, alias \`session merge\`):
Verifies the package, then copies each receipt and its sidecar into
outDir. The basename is kept when it is a safe \`*.md\` name
(\`receipts/foo.md\` → \`foo.md\`). Same id and same canonical sha256 skips
(idempotent) and does not rewrite a sidecar. Same id, or the same
basename compared case-insensitively, with a different sha256 refuses
the whole import and writes nothing. On start, a non-dry-run import
deletes stale \`.import-staging-*\` directories inside outDir only when
they contain this tool's marker file and are older than the current run.
A directory without that marker is never deleted. A stray \`.sig.json\` is a conflict
unless the bytes are identical. An unreadable destination, including
mode 0200, is a conflict. A symlink at the destination or at a parent
inside outDir, including a dangling symlink and a symlink outDir, exits
2 and writes nothing. Files are staged in a directory inside outDir and
published with an exclusive no-overwrite link. A name that already
exists is left in place. A failed copy removes the stage and any file
this import published.
\`--dry-run\` plans the copy and writes nothing. \`--json\` files[] include
\`fingerprint\`, \`originalFingerprint\`, \`resignedBy\`, and \`signedBy\`.
Human output after import names \`originalFingerprint\` and \`resignedBy\`.
\`session <id>\` repeats those claims from
\`.agent-receipt/resign-provenance.json\` when import recorded them.
\`originalFingerprint\` is the manifest signer's claim, covered by
\`session-manifest.sig.json\` when that sidecar verifies. It is not a
second signature over the pre-export bytes.
\`--require-sig\` requires a valid receipt sidecar and a valid manifest
signature. When a known-keys allowlist is active, those fingerprints
must be trusted. The same 32 MiB / 256 KiB / 8 MiB caps as export apply,
and the same \`--max-*-bytes\` flags raise them. \`stat\` runs first.
Malformed manifest (kind, version, required fields, lowercase hex) exits 1.
A file hash mismatch, a receipt that fails verify, a canonical sha256
that does not match the manifest, a present invalid sidecar, or an
invalid manifest signature exits 2. An absent receipt sidecar is fine
when the entry is unsigned. An absent manifest signature is fine unless
\`--require-sig\` is set.
\`--json\` prints one object (command \`session-import\`) with copied,
skipped, conflicts, files[] (action copy, skip, conflict, or symlink),
and manifestSig. Human output prints VERIFIED or FAILED, the paths that
would be written or were written, and the skip and conflict counts.
Import does not append the audit log and does not add an index row.
\`history\` keeps using the index, so a fresh import is absent there
while the index has rows. \`session <id>\` scans outDir and lists the
merged tree. \`last\` follows mtime, so a file just copied can become last.

Examples:
  agent-receipt session s-0123456789abcdef
  agent-receipt session ci-link --json
  agent-receipt session export s-0123456789abcdef
  agent-receipt session pack ci-link --include-host --json
  agent-receipt session import .agent-receipt/ci-link.session
  agent-receipt session merge .agent-receipt/ci-link.session --dry-run --json
  agent-receipt session import .agent-receipt/ci-link.session --require-sig
`,

  report: `agent-receipt report — signed one-page HTML report

Usage:
  agent-receipt report <receipt|last> [--out <path>] [--include-host] [--no-redact] [--json]
  agent-receipt report --session <id> [--out <path>] [--json]
  agent-receipt report <path/to/name.session> [--out <path>]
  agent-receipt report verify <file.html> [more.html ...] [--receipts <dir>] [--require-sig] [--json]

Writes one self-contained HTML file a reviewer can open offline. Inline CSS
only. No images, fonts, or network requests. JavaScript is not required to
read the page. The embedded \`<script type="application/json">\` blocks are
data. The Content-Security-Policy is
\`default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'\`.
\`style-src 'unsafe-inline'\` is the stylesheet inside the file. There is no
external CSS to hash, and a style hash would change on every edit without
adding a boundary the opened file does not already have. \`script-src 'none'\`
blocks executable script.

The default path is the sibling of outDir:
\`.agent-receipt/receipts\` becomes \`.agent-receipt/<stem>.report.html\`.
A receipt stem that is not a safe filename becomes
\`report-<sha256-12>.report.html\`. A session id that is one safe path
segment becomes \`<id>.report.html\`; anything else becomes
\`session-<sha256-12>.report.html\`. \`--out <file>\` is that file. An
existing directory, or a path that ends with \`/\`, receives
\`<stem>.report.html\`. The report is never written over the source receipt.
\`*.report.html\` is not a receipt. \`last\`, \`history\`, and \`prune\` ignore it.
A file that contains the report payload block is already a report, including
one renamed to \`.md\`. \`report\` on that file exits 1.

The page shows a verdict banner (VERIFIED, FAILED, UNSIGNED, UNTRUSTED),
what the agent did (summary, commands, files, risk flags, What to review),
the session tree for a session report, commits and range, signer
fingerprints and trust per receipt (including originalFingerprint,
resignedBy, and signedBy), the CLI version, and the exact commands to
re-verify offline. Those commands use basenames.

Redaction uses the same \`publishRedactedReceipt\` pipeline as share and
session export (secrets, nested receipt/index bodies, and Host).
\`--include-host\` keeps Host and still masks secrets, the same as share.
\`--no-redact\` skips the pipeline and wins over \`--include-host\`. Either
opt-out prints a loud UNREDACTED marker on the page.

The page is a pure function of the canonical JSON payload and the
signature document. The signature is the UTF-8 hex SHA-256 of that JSON
(sorted keys, no whitespace), the same SignatureDocument as \`sign\`. It is
not a signature over the HTML bytes. The payload holds every string the
page shows: verdict, banner, pills, agent, fingerprints, trust, the
signature status line, the title, the UNREDACTED state, and the narrative
(branch, message, summary, files, diff, commits, risk, session tree).
Sign the payload, then render with the signature block at a fixed place.
A detached \`<report>.html.sig.json\` is written beside the HTML when keys
load. The embedded signature block is JSON \`null\` when the report is
unsigned, and the page says UNSIGNED. Missing keys exit 0. Keys that
exist but cannot be loaded exit 1. A receipt that fails verify, a present
invalid receipt signature, or a session whose root or any receipt fails
verification still writes the page with verdict FAILED and exits 2.
UNTRUSTED means an active allowlist rejected a fingerprint. Generation
still exits 0.

\`report verify\` finds exactly one payload block and exactly one signature
block outside HTML comments (a strict scan, not a regex). Zero, a
duplicate, or a block inside a comment exits 2. A payload that is present
but fails the schema exits 2. It then checks the signature, re-renders the
page, and requires the same bytes. A single missing trailing newline is
ignored. Any other difference exits 2 with
"page content does not match signed payload". CRLF (a CR followed by LF)
exits 2 with "page has CRLF line endings" and names \`core.autocrlf\`.
A lone CR exits 2 with "page has CR line endings". A leading UTF-8 BOM
exits 2. Add \`*.report.html -text\` and \`.agent-receipt/** -text\` to
\`.gitattributes\`. Those bytes are not rewritten. The report page is not
normalized. \`audit.jsonl\` is a separate check: exactly one trailing CR on each
line is stripped before the chain hash. A second trailing CR fails the chain.
Invalid UTF-8 exits 2. \`renderVersion\` selects the
renderer. Version 2 is this page and includes the tool-call section when the receipt has one. Version 1 stays for pages written before that. An empty tool-call section is omitted from the payload. 1.0.30 rejects a payload that includes \`toolCalls\`, and it rejects renderVersion 2, so this page is a forward-compat break for 1.0.30. An unknown renderVersion exits 2. Bidi controls in rendered
fields, including agent names, are shown as \`\\uXXXX\`. Share HTML uses the same escape.

Candidate receipts come from outDir. \`--receipts <dir>\` searches that
directory instead, including subdirectories, and does not fall back to
outDir. The candidate walk has a depth of 4. It applies equally to a page
from report last, \`report verify\`, or report --session. The start
directory is depth 0. A file four directories down is still read. A file
at depth 5 or deeper is not a candidate. For each payload
receipt, every candidate must be acceptable. A candidate is any file whose
parsed id equals that receipt, or whose raw sha256 or embedded hash is the
recorded sha256, redactedSha256, or originalSha256. The file name, subdirectory, and session
do not matter. \`.md\` is matched case-insensitively, so \`file.MD\` is a
candidate. A symlink candidate exits 2 ("receipt <id> at <path> is a symlink").

A candidate is acceptable only when it passes receipt integrity (the
embedded hash is correct) and its bytes match. A present sidecar that
does not verify is "signature mismatch" before any hash is accepted.
On every acceptance path (raw sha256, raw sha256 equal to redactedSha256,
and redact-then-hash), when the payload records that receipt as signed
(a fingerprint or originalFingerprint is present), a valid sidecar whose
fingerprint matches is required, with or without \`--require-sig\`.
A raw or redactedSha256 byte match uses the payload fingerprint when it
is set, otherwise originalFingerprint. When the payload is unsigned
(neither fingerprint nor originalFingerprint), a valid stray sidecar is
ignored. An invalid sidecar is never ignored. A file whose raw sha256
equals the recorded redactedSha256 is a byte match in a local-store
report and in a session-package report, because that hash is a signed
value, and the sidecar rule above still applies. Computing
\`publishRedactedReceipt\` and comparing that hash is limited to a
session-package report (\`manifestSha256\` is set, as with
\`report <package>.session\`). A local-store report, including
\`--include-host\`, \`--no-redact\`, and \`report --session\`, does not
accept that redact-then-hash stand-in. On the redact-then-hash path, a
non-null originalFingerprint (or the recorded fingerprint when signedBy
is null) requires a valid sidecar whose fingerprint equals it, with or
without \`--require-sig\`. When originalFingerprint is null and signedBy
is set, an unsigned source is allowed. That is why the unredacted original
still verifies in the exporter's repo, and why deleting its sidecar after
a host edit and a re-hash does not.

An unacceptable file exits 2 with the path:
"receipt <id> at <path> fails integrity",
"receipt <id> at <path> signature mismatch", or
"receipt <id> at <path> differs from the signed payload".
One matching copy does not hide another same-id file.
With \`--receipts\`, a referenced receipt that is absent exits 2
("receipt <id> referenced by report not found in --receipts").
Without \`--receipts\`, a missing receipt that is still listed in
\`.agent-receipt/index.json\` or \`.agent-receipt/audit.jsonl\` exits 2
("still lists it"). The newest audit event for that sha256, originalSha256,
or path wins. When that event is \`prune\`, or a prune event removed the
index row, a missing capture, wrap, or watch event for that receipt is
not tampering. The result is exit 0 and the reason is
"receipt absent; audit.jsonl (unsigned) records a prune", under the headline
"VERIFIED (payload only; 1 receipt not checked)" or "N receipts not checked". Exit 2 only when a
capture, wrap, or watch event for that receipt does exist and the prune
is timestamped more than 5 seconds before it. Clock skew of up to 5
seconds stays payload-only. An unparseable prune or capture timestamp,
when a capture event exists, exits 2 with "receipt <id> prune timestamp is not a date".
That reason does not say "timestamped before its capture". A real earlier
date still uses the before-capture reason.
audit.jsonl is not signed.
Anyone with write access can extend it, so that reason does not mean the
prune was legitimate. When the store has no retention config (\`maxCount\`,
\`maxAgeDays\`, or \`autoPrune\`) and the newest prune line is not
\`source\` \`command\`, verify also warns
"audit.jsonl is unsigned; no retention config and no recorded prune command".
\`source\` \`retention\` does not silence that warning unless that config
is present. When \`source\` is \`retention\` and the config is absent, the
warning adds "(retention source claimed but no retention config found)".
If this store does not list it at all, the page can still be exit 0 with
that same headline. \`--json\` then uses verdict \`VERIFIED_PAYLOAD_ONLY\`
and \`notChecked\`. It does not print a plain VERIFIED. When \`audit.jsonl\`
exists in the store being searched, verify checks its hash chain the same
way \`doctor --strict\` does and exits 2 with "audit log hash chain is broken"
on a break. \`--receipts\` pointing elsewhere does not use an unrelated
audit.jsonl in the current directory. One trailing CR is stripped from
each audit line before the hash, so a \`core.autocrlf\` checkout of the
log still verifies. A second trailing CR is not stripped and fails the
chain. If the chain still fails and the failing line itself ends in CR,
the reason names CRLF and \`core.autocrlf\`. A CR on another line does
not add that hint. Add \`.agent-receipt/** -text\`
next to \`*.report.html -text\` in \`.gitattributes\`. A store with no
\`audit.jsonl\` is not a chain failure. A chain-only failure still counts
as failed, so the line is not "failed: 0" beside FAILED. On failure the
counts are checked, skipped, and failed, and the reason lists every
problem, not only the first.
A leading UTF-8 BOM (EF BB BF) exits 2 ("page starts with a UTF-8 BOM").
The decoder is created with \`ignoreBOM: true\` and the bytes are checked
explicitly. A CR that is part of CRLF is "page has CRLF line endings".
A lone CR is "page has CR line endings".
Exit 0 only when every found candidate is acceptable and the page and
signature rules above pass. Several HTML files are allowed; the exit code
is the worst of them. \`last\` still picks the newest receipt by mtime, so
a planted copy can win. That is unchanged.

Exit codes:
  0  signature valid, page matches, verdict VERIFIED, every candidate acceptable
  0  VERIFIED page whose receipts are not listed in this store
     (printed "VERIFIED (payload only; 1 receipt not checked)" or "N receipts not checked")
  0  no --require-sig, page matches, verdict UNSIGNED
     (printed UNSIGNED, or "UNSIGNED (1 receipt not checked)" / "N receipts not checked"
     when this store does not list the receipt)
  1  missing file, unreadable file, or --receipts is not a readable directory
  2  bad or missing blocks, schema, signature, page bytes, BOM, CR or CRLF,
     an unacceptable candidate, a receipt deleted while the index or audit
     log still lists it, a broken audit hash chain, a missing --receipts entry, verdict FAILED, verdict
     UNTRUSTED, or UNSIGNED with --require-sig (printed "FAILED (unsigned)")
A non-zero exit never prints VERIFIED. A failing unsigned page prints
"FAILED (unsigned)", not UNSIGNED. \`--require-sig\` enforces the
trust allowlist when one is configured. Removing the page key from a
store that still lists another key exits 2 (\`fingerprint not trusted\`).
An empty allowlist is inactive. With no trust store,
\`--require-sig\` accepts any valid self-signed page and prints a one-line
note. Use a trust allowlist (\`agent-receipt trust add --self\`) so a
reviewer accepts only known keys. originalFingerprint, resignedBy, and
signedBy are the manifest signer's claims. A trusted key holder can
re-sign an altered narrative. Trust means trusting the signer. \`report
verify\` checks the signature and the page bytes. It does not prove the
narrative matches an earlier unsigned draft. This is not a certificate authority.

\`--json\` prints one object (command \`report\` or \`report-verify\`).
The report does not append the audit log and does not add an index row.

Examples:
  agent-receipt report last
  agent-receipt report last --json
  agent-receipt report --session s-0123456789abcdef
  agent-receipt report .agent-receipt/s-0123456789abcdef.session
  agent-receipt report verify .agent-receipt/*.report.html
  agent-receipt report verify review.report.html --require-sig --receipts .agent-receipt/receipts
`,

  verify: `agent-receipt verify — hash-check tamper-evident integrity

Usage:
  agent-receipt verify [path]
  agent-receipt verify --package <dir>
  agent-receipt verify --pack <dir>

Recomputes SHA-256 over the Markdown body (everything except the Integrity
section / hash marker) and compares it to the embedded marker.
Exit 0 = OK, exit 2 = mismatch / missing hash (or --fail-on met), exit 1 = usage error.

\`--package\` (alias \`--pack\`) checks a share package directory from
\`share --package\` instead of a single receipt. A path to \`manifest.json\`
resolves to its parent directory. A directory that already contains
\`manifest.json\` with kind \`agent-receipt-share\` is detected without the
flag. \`--package\` forces package mode and exits 1 when the path is not a
package. A normal \`.md\` path stays a plain receipt verify.

Package checks, fail closed:
  - \`manifest.json\` kind \`agent-receipt-share\`, version 1, required fields,
    and lowercase hex shapes. Malformed is exit 1.
  - Every \`manifest.files\` entry exists and matches \`sha256FileBytes\`.
    \`signed: true\` requires \`receipt.sig.json\`. \`signed: false\` rejects
    that sidecar. A byte mismatch is exit 2.
  - \`receipt.md\` is verified with the same hash as \`verify\`. The canonical
    sha256 must equal \`manifest.sha256\`.
  - A present \`receipt.sig.json\` is inspected. Valid is reported. Invalid
    exits 2 even without \`--require-sig\`. Missing is fine when the manifest
    is unsigned. \`--require-sig\` requires a valid sidecar and, when a
    known-keys allowlist is active, a trusted fingerprint.
  - A present \`manifest.sig.json\` must verify over the hex SHA-256 of the
    current \`manifest.json\` bytes. Absent is fine. Invalid exits 2.
  - HTML is a file hash only. The HTML body is not signed.

Human stdout prints VERIFIED or FAILED, the package path, sha256, signed,
fingerprint, file-hash, receipt verify, signature, manifestSig, and a tip
to open \`receipt.html\`.

\`--json\` stays command \`"verify"\` and adds packagePath, signed, fingerprint,
filesOk, manifestOk, manifestSig, and signature. Required gate keys are
unchanged. Plain \`verify --json\` on a \`.md\` file omits those fields.
Exit 2 is an integrity or signature-policy failure. Exit 1 is usage,
missing, or malformed.

By design, trailing appends after ## Integrity are ignored by the hash (they
do not affect verify). A note is printed when such trailing content is present.

--fail-on is opt-in here. Config failOn does NOT change plain verify, so
existing hooks stay integrity-only. Pass the flag to also exit 2 when the
receipt Summary risk meets the threshold.

--json prints one CI gate object on stdout (ok, exitCode, verified, failedOn,
sha256, risk, trailingIgnored). trailingIgnored is a boolean: true when
content after ## Integrity was ignored by the hash. Exit codes are unchanged.
Wrap and share set the same field when they verified a body. Capture leaves
it null (capture does not report a verify result).

Default verify of a Markdown receipt stays hash-only. It does not require
or check a signature sidecar. On a plain \`.md\` path, unsigned receipts
still pass, including when a sidecar is missing or invalid. Package verify
is different: a present invalid sidecar exits 2. \`prove\` reports signature
status when a \`.sig.json\` file is present. \`sign\` writes that sidecar.

--require-sig (alias --require-signature) is opt-in. The hash check runs
first. A hash failure still exits 2 and does not soften. After a matching
hash, a valid \`*.sig.json\` beside the receipt is required
(\`inspectReceiptSignature\` / \`verifySignature\`). Missing sidecar exits 2
with reason "signature required: signature absent". A present sidecar that
is invalid, mismatched, or malformed exits 2 with the signature reason.
A valid sidecar for the current sha256 exits 0 unless --fail-on also trips.
There is no config key for this flag. capture, wrap, and share do not
turn it on.

--json with --require-sig adds signature { present, ok, alg, fingerprint, reason, trusted }
after the hash passes. Without --require-sig, a plain receipt gate omits
signature. \`verify --package --json\` always includes signature.
\`trusted\` is true when a non-empty known-keys allowlist lists the sidecar
fingerprint, false when that allowlist rejects it, and null when the
allowlist is inactive.

Fingerprint trust store (known-keys allowlist, not a CA). After the hash
matches and the sidecar is cryptographically valid, \`--require-sig\` checks
the fingerprint when a store is configured:
  - \`.agent-receipt/trusted-keys.txt\` — one lowercase 64-hex fingerprint
    per line. \`#\` comments and blank lines are ignored. An invalid line
    fails closed (exit 2) instead of being skipped.
  - \`.agent-receipt.yml\` key \`trustedFingerprints:\` (YAML list). Union
    with the file. Either source alone is enough.
  - \`--trusted-key <fp>\` (repeatable, or comma-separated) adds fingerprints
    for this invocation only.
Empty or missing file and config (and no \`--trusted-key\`) means the
allowlist is inactive: any cryptographically valid sidecar still passes,
same as 1.0.17. A non-empty store that does not list the sidecar
fingerprint exits 2 (\`fingerprint not trusted\`, fingerprint included).

\`trust list\`, \`trust add <fp>\`, \`trust add --self\`, and \`trust rm <fp>\` edit the file.
\`trust show\` (alias \`trust status\`) only reads it.
Teams may commit a copy under examples/ or docs/ and copy it into
\`.agent-receipt/\` (that directory stays gitignored, so local keys and
the default list stay private).

Examples:
  agent-receipt verify
  agent-receipt verify receipt.md
  agent-receipt verify --json
  agent-receipt verify --require-sig
  agent-receipt verify --require-sig receipt.md --json
  agent-receipt verify --require-sig --trusted-key <64-hex-fingerprint>
  agent-receipt verify --fail-on high --json
  agent-receipt verify --package foo.share
  agent-receipt verify --pack foo.share --json
  agent-receipt verify foo.share
  agent-receipt verify --package foo.share/manifest.json --require-sig
`,

  import: `agent-receipt import — copy a verified share package into the local store

Usage:
  agent-receipt import <packageDir> [--dry-run] [--json]
  agent-receipt import <packageDir> --require-sig

Runs the same checks as \`verify --package\`. On success, copies \`receipt.md\`
and \`receipt.sig.json\` (when that sidecar is in the package) into the
configured outDir as \`receipt-import-<sha256-12>.md\` and a sibling
\`.sig.json\`. The name uses the first 12 hex chars of the canonical receipt
sha256. HTML and \`manifest.json\` are not copied and are not receipts.

A failed verify does not copy. \`--dry-run\` prints the planned paths and
writes nothing. \`--json\` is command \`"import"\` and adds importPath,
importSigPath, and dryRun. Those paths are null when verify failed.

Import does not append the audit log and does not add an index row. It is
verify plus copy, not a local capture. The copied Markdown keeps the source
integrity footer, so it is a receipt file under outDir. \`history\` lists
\`index.json\` when that catalog has rows, so the import does not appear
there unless the index is empty (the directory scan). \`last\` follows mtime
and can show a fresh import. \`prune\` can delete \`receipt-import-*.md\`
with other receipts. Not a CA. The HTML body stays unsigned.

Examples:
  agent-receipt import foo.share
  agent-receipt import foo.share --dry-run
  agent-receipt import foo.share --json
  agent-receipt import foo.share --require-sig
`,

  keygen: `agent-receipt keygen — create a local Ed25519 keypair

Usage:
  agent-receipt keygen [--force] [--json] [--cwd <path>]

Writes a keypair under \`.agent-receipt/keys/\` (already gitignored):

  ed25519.private    PKCS8 PEM private key (mode 0600)
  ed25519.public     SPKI PEM public key

The key fingerprint is the lowercase hex SHA-256 of the DER SPKI bytes
(64 hex chars). No network. No CA, no PKI, no key escrow. The private
key is never printed and is never copied into a receipt or sidecar.

When both files already exist, keygen exits 0 and prints the fingerprint
plus "unchanged". It does not rewrite them. \`--force\` rotates (overwrites)
the pair. An incomplete pair (only one file) exits 1 unless \`--force\`.

--json prints one object:
  ok, command ("keygen"), version, exitCode, fingerprint,
  privateKeyPath, publicKeyPath, created, rotated, reason

Examples:
  agent-receipt keygen
  agent-receipt keygen --json
  agent-receipt keygen --force
  agent-receipt keygen && agent-receipt trust add --self
`,

  sign: `agent-receipt sign — attest the receipt sha256 with the local key

Usage:
  agent-receipt sign [path] [--json] [--cwd <path>]

Resolves the receipt the same way verify does (newest when path is omitted).
Recomputes the Markdown hash first. If the hash fails, sign exits 2 and
does not write a sidecar.

Then it requires the keygen keypair. Missing keys exit 1 and name
\`keygen\`. On success it writes \`foo.sig.json\` next to \`foo.md\`
(overwrite if it already exists). The signature is over the UTF-8 bytes
of the sha256 hex string — the same hex verify uses — not the raw Markdown.

Sidecar fields: alg ("ed25519"), version (1), sha256, fingerprint,
signature (base64 raw 64-byte signature), publicKey (SPKI PEM). The
public key is embedded so a peer can verify without the local keys
directory. The private key is never written. \`sign --keyless\` is not supported.
Keyless OIDC signing is \`attest --keyless\` (a Sigstore bundle, not
\`foo.sig.json\`).

capture, wrap, and watch sign when you pass \`--sign\` or when config
\`sign: true\` (missing keys leave the receipt unsigned and do not exit 2).
\`--no-sign\` overrides that config. \`init --org\` does not set \`sign\`.
share, export, prove, and verify do not read config \`sign\`. share and
export do not sign the source receipt. When they write published Markdown
they may copy a valid sidecar or re-sign that file (see \`help share\`).
Default verify stays hash-only. \`verify --require-sig\` opts in and, when a
known-keys allowlist is configured, requires that fingerprint. prove
reports the sidecar when it is present.

--json prints one object (command "sign"):
  ok, version, exitCode, verified, path, sigPath, sha256, fingerprint, reason

Exit codes:
  0  hash matched and sidecar written
  2  hash failure (no sidecar written)
  1  usage, missing receipt, or missing keys

Examples:
  agent-receipt sign
  agent-receipt sign receipt.md --json
  agent-receipt keygen && agent-receipt sign && agent-receipt prove --json
`,

  trust: `agent-receipt trust — fingerprint trust store (known-keys allowlist)

Usage:
  agent-receipt trust list [--json]
  agent-receipt trust show [--json]
  agent-receipt trust status [--json]
  agent-receipt trust add <fingerprint> [--json]
  agent-receipt trust add --self [--json]
  agent-receipt trust rm <fingerprint> [--json]

\`trust list\`, \`trust add\`, and \`trust rm\` use
\`.agent-receipt/trusted-keys.txt\` (one lowercase 64-hex fingerprint
per line). \`#\` comments and blank lines are kept. An invalid line is not
rewritten and the command exits 1.

\`trust show\` (alias: \`trust status\`) is read-only. It prints whether
the allowlist is active, the count, the file, sources, and the fingerprints
when the store is active. It also prints the local keygen fingerprint when
keys load (\`local\`), or \`local: (none — run keygen)\` when they do not.
\`localListed\` is true, false, or n/a when there is no local key. Missing
keys do not fail the command. It does not create a keypair, does not edit
the allowlist, and does not edit config. When a local key loads and is not
listed, run \`trust add --self\`. \`trust show\` takes no fingerprint.
An unreadable or invalid store exits 1 with the same reason as \`trust list\`.

\`trust add --self\` (alias: \`trust add self\`) loads the local Ed25519
keypair with the same \`loadKeys\` path as \`sign\` and \`keygen\`, then
appends that fingerprint. Already listed exits 0 (\`added: false\`).
Missing keys exit 1 and name \`keygen\`. It does not create a keypair and
does not write the private key.

This is a local allowlist, not a CA. Empty or missing file plus no
\`trustedFingerprints\` config means \`verify --require-sig\` still accepts
any cryptographically valid sidecar. \`trust add\` / \`trust rm\` only
change the file. Config \`trustedFingerprints\` is a separate union.
\`trust show\` reads that same union and does not write it.

--json prints one object:
  ok, command ("trust"), action, version, exitCode, active, count,
  fingerprints, sources, reason
  add also sets added; rm also sets removed.
  \`--self\` also sets fingerprint to the local keygen fingerprint.
  show (and status) set action to "show" and add path, localFingerprint
  (string or null), and localListed (true, false, or null when no local key).

Examples:
  agent-receipt trust list
  agent-receipt trust show
  agent-receipt trust show --json
  agent-receipt trust add <64-hex-fingerprint>
  agent-receipt keygen && agent-receipt trust add --self
  agent-receipt trust add --json --self
  agent-receipt trust rm <64-hex-fingerprint> --json
`,

  prove: `agent-receipt prove — prove-this-run (integrity + audit link)

Usage:
  agent-receipt prove [path] [--json] [--page] [--one-pager] [--html] [--out <path>] [--fail-on high|medium|low] [--trusted-key <fp>]

Resolves the path the same way verify does (newest receipt when omitted).
Recomputes the same SHA-256 as verify, then reports the path, hash,
verified, trailingIgnored, redacted, risk summary, TL;DR, agent,
uncommitted, failedOn, and a best-effort audit link.

This is tamper-evident prove-this-run. The hash and the audit link are
not a cryptographic signature. A local Ed25519 sidecar is reported when
present. Default verify stays hash-only. \`verify --require-sig\` requires
a valid sidecar. There is no CA and no PKI.

\`--page\` (alias \`--one-pager\`) writes a plain-English Markdown one-pager
after that report is computed. Exit codes stay the same, including FAILED
(exit 2). Without \`--page\`, prove stays stdout-only and writes no file.
The one-pager is not itself signed.

Default path: \`foo.md\` → \`foo.prove.md\` in the same directory. A receipt
whose name does not end in \`.md\` gets \`<name>.prove.md\`
(\`notes.txt\` → \`notes.txt.prove.md\`) so it does not collide with a
Markdown receipt of the same stem.

\`--out <path>\` overrides that destination and requires \`--page\` or
\`--html\`. An
existing directory, or a path that ends with a slash, receives
\`<stem>.prove.md\` inside it. Any other path is the file and is used
as-is. The page is not written over the source receipt. \`*.prove.md\` is not a
receipt: \`last\`, \`history\`, and \`prune\` ignore that name so a newer
page does not replace the receipt it describes.

The page is one screen: title "Agent Receipt — Prove", a PROVED or FAILED
verdict (exit 0 vs non-zero), then path, sha256, verified,
trailingIgnored, redacted, risk, tldr, agent, uncommitted, failedOn,
audit (present / chain / events / matched), signature (present / ok /
trusted / fingerprint / reason), and failOn or reason when those are set.
A short footer repeats the tamper-evident tip: not a CA, not access control.

Human stdout keeps the PROVED or FAILED banner. When \`--page\` wrote a
file it also prints one \`page:\` line with that path. \`--json\` stays one
object. When \`--page\` wrote a file it adds \`pagePath\` (string). The
field is omitted when \`--page\` was not passed. Required prove keys are
unchanged. \`prove --page\` does not append the audit log.

\`--html\` (1.0.27) writes one self-contained, offline HTML verification
report: \`foo.md\` → \`foo.prove.html\` (same \`--out\` rules as \`--page\`).
It opens with a PASS or FAIL banner (PASS = exit 0, same as PROVED), then
the hash check, SHA-256, audit chain (present / intact / matched), Ed25519
signature and trust status, redaction, a receipt summary (agent, time,
branch, HEAD, message, TL;DR, files, lines, risk) and the risk findings.
The report is written on FAIL too; exit codes stay the same.

Redaction is always on for the HTML: every receipt-derived string goes
through the same secret rules as \`share\`, secret-bearing risk details
are masked, and everything is HTML-escaped. URLs in receipt text are
defanged (\`https[:]//\`). Inline CSS only: no scripts, no links, no
images, no fonts, no network, with a \`default-src 'none'\` CSP. The HTML
report is not itself signed. \`*.prove.html\` is not a receipt.

\`--html\` and \`--page\` can be combined; both files are written. With
both, \`--out\` must be a directory (end it with \`/\`). Human stdout adds
one \`html:\` line; \`--json\` adds \`htmlPath\` (string), omitted when
\`--html\` was not passed. \`prove --html\` does not append the audit log.

When the receipt has a session or parent link, human stdout, the one-pager,
and the HTML report add session, parent, and parent verify (yes, no,
not local, or (none)). \`--json\` adds session, parent, and parentVerified
only in that case. Those keys are omitted when the receipt is unlinked.
parentVerified does not change the exit code. Host is not shown. The CSP
meta tag is \`default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; ...\`.
Single quotes in receipt text are escaped as \`&#39;\`.

Signature status (foo.md → foo.sig.json, written by \`sign\`):
  - No sidecar: present false, ok null. Exit rules are unchanged for that alone.
  - Present and valid for the current receipt sha256: ok true, plus alg and
    the key fingerprint
  - Present but invalid, mismatched, or malformed JSON: ok false, exit 2
  - Present, cryptographically valid, and a non-empty trust store does not
    list the fingerprint: ok false, exit 2, reason mentions the trust store.
    An empty or missing store does not change the 1.0.17 exit rules.
    An invalid line in the trust store fails closed.

--json adds signature { present, ok, alg, fingerprint, reason, trusted }.
trusted is true when the allowlist lists the fingerprint, false when an
active allowlist rejects it, and null when the allowlist is inactive
(or the sidecar was not checked). --trusted-key <fp> is repeatable or
comma-separated and unions with the file and trustedFingerprints for
this invocation only.

Audit link (still not a signature):
  - No .agent-receipt/audit.jsonl: present false, chainOk null, matched false
  - Log present: verifyAuditChain sets chainOk, the event count, and reason
    when the chain breaks
  - matched is true when any event path equals this receipt (repo-relative,
    the form audit stores today)

uncommitted and failedOn prefer the index row, then the companion receipt
.json. A stored failedOn boolean wins, including false on a high-risk row.
When both are missing, failedOn is high severity only — the same rule
history --failed uses for older rows. Medium or low alone does not count.

--fail-on is explicit only. Config failOn is not applied, so prove stays
integrity-first unless you pass the flag. When the flag trips, failedOn is
true and the exit is 2 even if the hash matches.

--json prints one object on stdout (notes stay off stdout):
  ok, command ("prove"), version, exitCode,
  verified, trailingIgnored, failedOn, failOn, redacted, uncommitted,
  path, sha256, tldr, agent,
  risk { high, medium, low, total, maxSeverity } or null,
  audit { present, chainOk, events, matched, reason },
  signature { present, ok, alg, fingerprint, reason, trusted },
  reason
  When the receipt has a session or parent: session, parent, parentVerified.
  ok is true only when exitCode is 0.
  --page adds pagePath (string) when the one-pager was written.
  --html adds htmlPath (string) when the HTML report was written.

Exit codes:
  0  verified, audit log absent or intact, and signature absent or valid
     (including a valid sidecar when the trust store is inactive)
  2  verify failed, the audit chain is broken, a signature sidecar is
     present but invalid, an active trust store rejects the fingerprint,
     or --fail-on tripped
  1  usage or runtime (missing receipt, unknown flag, bad --fail-on)

Examples:
  agent-receipt prove
  agent-receipt prove --page
  agent-receipt prove --json --page
  agent-receipt prove receipt.md --one-pager --out ./pages/
  agent-receipt prove --html
  agent-receipt prove --json --html --out ./reports/
  agent-receipt prove --page --html --out ./reports/
  agent-receipt prove receipt.md --fail-on high --json
`,

  audit: `agent-receipt audit — list the local compliance log

Usage:
  agent-receipt audit [--limit <N>] [--json] [--event <name>] [--agent <name>] [--failed]
  agent-receipt audit --verify [--json]
  agent-receipt log                  # alias

\`capture\`, \`watch\`, \`wrap\`, \`share\`, and \`export\` each append one JSON
line to \`.agent-receipt/audit.jsonl\`. \`prune\` / \`retain\` append one
\`prune\` line per receipt actually deleted (not on \`--dry-run\`, not when
nothing is deleted, and not a second line for the sibling \`.json\`).
The log stores event, path, sha256, agent, redacted, verified, failedOn, exit code.
It does **not** store diff bodies or the session \`--message\`.

\`wrap\` records \`wrap\` (not a second \`capture\` line). \`share\` records
\`share\` (not a second \`export\` line). \`watch\` records \`watch\` per capture.

Each line's \`prev\` is the SHA-256 of the previous line (or null on the
first). Exactly one trailing CR is stripped before that hash, so a
\`core.autocrlf\` checkout does not break the chain by itself. Two
trailing CRs still fail the chain. If the chain still fails and the
failing line itself ends in CR, the reason names CRLF and
\`core.autocrlf\`. \`audit --verify\` checks that chain. Exit 0 = intact,
exit 2 = mismatch, exit 1 = unreadable or a bad flag. This is
**experimental** tamper-evidence for the log — not a signature and not
PKI. audit.jsonl is not signed. Anyone with write access can extend it.
A prune line written by this version records \`source\` \`command\` when
\`--max-count\` or \`--max-age-days\` was passed, and \`source\`
\`retention\` when the limit came from config, including auto-prune.
Older logs omit \`source\`.

\`--json\` prints a JSON array, oldest first. \`--verify --json\` prints
\`{ ok, command, version, events, brokenAt, reason }\`.

Listing filters (optional; \`log\` accepts the same flags):

  \`--event <name>\`   one of \`capture\`, \`watch\`, \`wrap\`, \`share\`, \`export\`, \`prune\`
  \`--agent <name>\`   exact, case-sensitive match on the \`agent\` field.
                     Events with \`agent: null\` do not match any \`--agent\` filter.
  \`--failed\`         keep events where \`failedOn\` is true or \`exitCode\` is not 0

Filter order: load events → \`--event\` (if set) → \`--agent\` (if set) →
\`--failed\` (if set) → \`--limit\` (newest N of the filtered set) → print.
Human listing is newest last. \`--json\` prints that same slice as a JSON
array, oldest first.

No matches is exit 0: an empty human listing, or \`[]\` with \`--json\`.
Not an error. An unknown \`--event\` name exits 1. \`--agent\` requires a
name. An unknown flag exits 1.

\`--event\`, \`--agent\`, and \`--failed\` are listing-only. \`audit --verify\`
ignores them (and \`--limit\`) and checks the whole chain. When one of those
filters is passed with \`--verify\`, a short note goes to stderr.

Examples:
  agent-receipt audit
  agent-receipt audit --limit 10
  agent-receipt audit --json
  agent-receipt audit --event wrap
  agent-receipt audit --agent cursor
  agent-receipt audit --agent cursor --failed
  agent-receipt audit --event wrap --agent ci --limit 20 --json
  agent-receipt log --event prune
  agent-receipt log --failed
  agent-receipt log --agent ci --failed --json
  agent-receipt audit --verify
  agent-receipt log --verify
`,

  prune: `agent-receipt prune — delete old receipts under outDir (opt-in)

Usage:
  agent-receipt prune [--dry-run] [--max-count <N>] [--max-age-days <N>] [--json] [--force]
  agent-receipt retain                 # alias

Nothing is deleted unless a limit is set. Limits come from
\`.agent-receipt.yml\` (\`maxCount\`, \`maxAgeDays\`) or from the flags below.
Flags override config for this run. Omit both and prune exits 0 without
deleting. Capture, wrap, and watch run this same path after a successful
write when \`autoPrune: true\` or \`--prune\` is set (both a limit and the
flag are required). That auto path does not pass \`--force\` and does not
change the capture exit code: a broken chain warns on stderr and deletes
nothing. Manual \`prune\` still exits 1 on a broken chain.
\`init --retention\` sets \`maxCount: 100\` and \`maxAgeDays: 30\` and does
not turn \`autoPrune\` on. \`init --auto-prune\` sets only \`autoPrune: true\`.
\`--no-prune\` on capture, wrap, or watch forces auto-prune off for that run.

Trusted prune: when \`.agent-receipt/audit.jsonl\` exists, the hash chain
is checked before any delete. A broken chain exits 1, deletes nothing,
and appends no audit line. Dry-run does the same (exit 1) and may still
list candidates, but it does not claim those deletes will proceed.
A missing audit log is fine — absence is not a failure. \`--force\` is
break-glass: it deletes even when the audit chain is broken. Retention
must not paper over a broken audit chain.

A receipt is kept only when it satisfies every limit that is set
(it is deleted when it misses any one of them):
  - maxCount     keep the newest N (by receipt timestamp, else file mtime)
  - maxAgeDays   delete only when strictly older than N days
                 (a receipt exactly N days old is kept)

Both limits together: a file is kept only if it is inside the count AND
young enough. Sibling \`<receipt>.json\` and \`<receipt>.sig.json\` are
deleted with the markdown. A symlink sidecar is refused, not followed.
\`index.json\` is rewritten (temp file + rename) so removed paths drop out.
Rows that already point at missing files under outDir are dropped too.
\`audit.jsonl\` and \`SETUP.md\` are never deleted. Symlinks are skipped.

\`--dry-run\` prints the plan and does not delete, rewrite the index, or
append \`audit.jsonl\`. An applied delete appends one \`prune\` audit line
per receipt (path, sha256, agent, redacted, verified, exit — no diff body
and no \`--message\`). The line records \`source\` \`command\` when
\`--max-count\` or \`--max-age-days\` was passed, and \`source\`
\`retention\` when the limit came from config, including auto-prune.
The sibling \`.json\` is not a second event. A run
that deletes nothing does not append. audit.jsonl is not signed.

\`--json\` adds \`command\`, \`version\`, \`exitCode\`, and \`audited\` (lines
appended; 0 on dry-run). Each \`deleted\` row has the same identity fields
as an audit line (\`sha256\`, \`agent\`, \`redacted\`, \`verified\`,
\`failedOn\`, \`exitCode\`) plus \`reasons\` and \`bytes\`. The report also
includes \`auditPresent\`, \`chainOk\` (null when the log is absent),
\`reason\` (set when trusted prune refuses), and \`forced\`. On a refused
run, \`deleted\` is the plan that was not applied and \`audited\` is 0.
\`ok\` is true only when \`exitCode\` is 0.

outDir must be a subdirectory of the repo (not the repo root, not outside).
A broken \`index.json\` makes prune refuse before it deletes anything.

Exit 0 when the plan is applied, previewed, or retention is off, and the
audit log is absent or intact (or \`--force\` skipped a broken chain).
Exit 1 on a broken audit chain (including dry-run), invalid limits, an
unsafe outDir, or an unreadable index.

Examples:
  agent-receipt prune --dry-run
  agent-receipt prune --dry-run --max-count 50
  agent-receipt prune --max-age-days 30
  agent-receipt prune --json
  agent-receipt prune --force --max-count 50
`,

  retain: `See: agent-receipt help prune`,

  log: `See: agent-receipt help audit`,

  doctor: `agent-receipt doctor — environment health check

Usage:
  agent-receipt doctor [--strict] [--json] [--cwd <path>]

Environment:
  node          Node.js >= 20
  git           git on PATH
  repo          inside a git work tree
  outDir        receipt directory writable
  cli           this version

Prod ready (short checklist — WARN/INFO do not fail the command):
  config        .agent-receipt.yml present + valid (shows redact / failOn)
  hooks         managed post-commit hook installed?
  redact        redact: true in config, or still optional (share redacts by default)
  policy        redact on AND failOn set (examples/org-policy.yml)? Optional.
                INFO by default. FAIL under --strict when unset, on any outDir.
                \`init --org\` sets both keys.
  audit         .agent-receipt/audit.jsonl chain OK? Missing is info.
                Broken is a warning by default, and FAIL with --strict.
  keys          Local Ed25519 keypair (optional). INFO when absent.
                PASS shows the key fingerprint. WARN if the private key
                is missing while the public key is present, or the files
                are unreadable. Missing keys do not fail doctor or
                doctor --strict.
  sign          Config sign (optional). INFO when unset or false.
                PASS when sign: true and the local keypair loads.
                WARN when sign: true but keys are missing (names keygen).
                That warning does not fail doctor or doctor --strict.
                init --org does not set sign. CLI --no-sign overrides
                at capture time. Not a CA.
  trust         Fingerprint trust store / known-keys (optional allowlist).
                INFO when no store is configured (allowlist inactive).
                PASS when the file or trustedFingerprints lists N
                fingerprints. WARN when the store is present but empty,
                unreadable, or has an invalid line. Invalid lines FAIL
                under --strict. A missing store does not fail doctor
                or doctor --strict. After keygen, \`trust add --self\`
                lists this machine's fingerprint.
  retention     maxCount / maxAgeDays (opt-in). Over the cap or a large outDir is a warning.
                Unset fails under --strict on any outDir, including a small one.
                Default doctor leaves unset retention as INFO/WARN.
  autoPrune     Optional. INFO when unset or false. PASS when true and a
                retention limit is set. WARN when true but maxCount and
                maxAgeDays are unset (names init --retention). That WARN
                does not fail doctor or doctor --strict. Unset autoPrune
                does not fail --strict. Not a daemon.
  link          Multi-agent linking (optional). Always INFO, including
                under --strict. Names --session, --parent, --agent, --host,
                and wrap --link. Host stays off unless you opt in. share
                masks secrets, nested receipt bodies, and host unless
                --include-host. session export uses that same redaction
                unless --include-host, which keeps the original bytes.
                session export / session import move a whole session tree.
                Import refuses a symlink destination.
                Not a CA.
  git-clean     working tree clean? Dirty is a warning, not a failure
  cursor        init --cursor rule present?
  grok          init --grok rule + SessionEnd hook present?
  packs         Policy packs from .agent-receipt.yml. INFO when none are
                set, and INFO when a pack is invalid or an exception is
                expired. --strict fails those two cases. Unset packs stay
                INFO under --strict.
  adapters      Native capture adapters (claude-code, codex, grok, cursor).
                Always INFO, including under --strict. Does not fail doctor.

Exit 0 if no FAIL checks; exit 1 otherwise. WARN/INFO are non-fatal.
Default \`doctor\` does not fail when org policy or retention is unset.
A broken audit chain is a warning by default.

\`--strict\` always promotes a broken audit chain from WARN to FAIL (exit 1).
Unset org policy (redact: true and failOn) also fails under \`--strict\`,
even when outDir is small or empty. Set it with \`agent-receipt init --org\`.
\`doctor --json\` reports that policy check as \`fail\`.
Unset retention fails under --strict on any outDir, including a small or
empty directory. Set it with \`agent-receipt init --retention\`.
Default \`doctor\` still leaves unset retention as INFO when the directory
is small, and WARN when it is under pressure (100 receipts or 20 MB).
A configured limit that would still delete files stays a warning — run
\`prune\`. \`--strict\` does not scan diffs.
\`init --retention\` sets maxCount: 100 and maxAgeDays: 30 and does not
turn autoPrune on. \`init --auto-prune\` sets autoPrune: true. Trusted prune
refuses to delete when the audit chain is broken unless you pass
\`prune --force\`. Auto-prune never passes \`--force\`. Unset autoPrune does
not fail doctor or doctor --strict.
CI \`--fail-on\` remains the risk gate.

\`--json\` prints one object on stdout and does not change the exit code:

  { "ok", "command": "doctor", "version", "exitCode", "strict", "checks" }

\`ok\` is true when \`exitCode\` is 0. Each check is \`{ "id", "status", "detail" }\`
with status \`pass\`, \`fail\`, \`warn\`, or \`info\` — the same rows and labels as
the human checklist (Environment, then Prod ready). Human output stays the
default when \`--json\` is omitted.

Team rollout: docs/business.md · examples/org-policy.yml

Examples:
  agent-receipt doctor
  agent-receipt doctor --strict
  agent-receipt doctor --json
  agent-receipt doctor --strict --json
  agent-receipt doctor --cwd ~/code/my-app
`,

  compare: `agent-receipt compare — what changed between two receipts

Usage:
  agent-receipt compare [a] [b]
  agent-receipt diff [a] [b]          # alias

With no args: newest vs previous under outDir.
With one arg: that receipt vs previous.
With two args: compare those two paths.

Shows session deltas, summary metrics, file set diff, and risk set diff.

Examples:
  agent-receipt compare
  agent-receipt compare older.md newer.md
  agent-receipt diff
`,

  diff: `See: agent-receipt help compare`,

  'install-hooks': `agent-receipt install-hooks — opt-in auto-capture on commit

Usage:
  agent-receipt install-hooks [--pre-push] [--force] [--uninstall]

Options:
  --pre-push             Also install a pre-push capture hook
  --force                Refresh managed section
  --uninstall            Same as uninstall-hooks (compat)

Hooks embed this package's bin (node + absolute path) when installable locally/globally.
Fallback order at runtime: AGENT_RECEIPT_BIN → embedded bin path → npx (last resort).
Failure inside the hook is non-blocking (\`|| true\`).

For CI that should fail on secrets, run capture with --fail-on high in the job
(not in the git hook — hooks stay non-blocking).

Examples:
  agent-receipt install-hooks
  agent-receipt install-hooks --pre-push
  AGENT_RECEIPT_BIN=$(pwd)/bin/agent-receipt.js agent-receipt install-hooks
`,

  'uninstall-hooks': `agent-receipt uninstall-hooks — remove managed hook sections

Usage:
  agent-receipt uninstall-hooks [--pre-push]

Only strips the marked agent-receipt block; custom hook lines are preserved.

Examples:
  agent-receipt uninstall-hooks
  agent-receipt uninstall-hooks --pre-push
`,

  'pr-comment': `agent-receipt pr-comment — pull request summary of a receipt gate

Usage:
  agent-receipt pr-comment [--command gate|verify|attest-verify] [--receipts <path-or-glob>] [--fail-on high|medium|low] [--policy <file>] [--require-signature] [--comment on|off|on-failure] [--comment-mode update|create] [--dry-run] [--out <file>] [--json]

Runs the check, then renders one Markdown summary (verdict, risk, receipts
checked, policy hits, signature or keyless status, hash-chain head, share
packages). Every line is passed through the same secret redaction as share.
The summary is appended to GITHUB_STEP_SUMMARY when that variable is set.

\`--dry-run\` prints the summary and does not call GitHub. \`--out\` writes
the same Markdown. \`--json\` prints one object on stdout (the summary is
a field). Exit 0 is pass, 2 is a failed gate, 1 is a usage error.

\`--command gate\` (default) verifies every receipt and fails on high risk
unless \`--fail-on\` or the policy file sets another threshold. \`verify\`
is integrity-first and applies \`--fail-on\` only when you pass it or the
policy sets \`failOn\`. \`attest-verify\` runs \`attest --verify\` on each
attestation. \`--certificate-identity\` (or \`--certificate-identity-regexp\`)
and \`--certificate-oidc-issuer\` are passed through for a Sigstore bundle.
Missing identity or issuer exits 1.

\`--comment\` defaults to \`on\`. \`on-failure\` posts only when the verdict
is fail. \`off\` does not post. \`--comment-mode update\` (default) finds
the comment whose body contains \`<!-- agent-receipt:summary -->\` and
patches it. \`create\` always posts a new comment. Repo, pull request
number, and API URL come from GITHUB_REPOSITORY, GITHUB_EVENT_PATH, and
GITHUB_API_URL. \`--repo\`, \`--pr\`, \`--api-url\`, and \`--event-path\`
override those. The token is GITHUB_TOKEN and is never printed.

A missing pull request context fails with a clear error unless \`--dry-run\`
(or \`--comment off\`) is set. HTTP 403 and 404, and network errors, write
the summary to the step summary and do not change the gate exit code.
Fork pull requests often have a read-only token; that is the 403 case.

No receipts matched fails the gate (exit 2). A missing \`--policy\` file
or an invalid \`--command\` exits 1. An empty match is not a pass.

Options:
  --command <mode>       gate (default), verify, or attest-verify. Alias: --mode
  --receipts <path>      File, directory, or glob. Default: the receipt store
  --fail-on <level>      high, medium, or low. gate defaults to high
  --policy <file>        YAML with failOn and requireSignature. Flag wins
  --policy-pack <name>   Policy pack (repeatable). builtin:<name> or a file.
                         A comma-separated list is rejected; repeat the flag.
                         Deny hits fail the gate. Warn hits are reported.
                         Not used by --command attest-verify.
  --require-signature    Require a valid sidecar (alias: --require-sig)
  --certificate-identity <id>          Keyless SAN for attest-verify
  --certificate-identity-regexp <re>   Keyless SAN pattern. Not with --certificate-identity
  --certificate-oidc-issuer <url>      Keyless issuer for attest-verify
  --trusted-root <file>  Sigstore trusted_root.json for attest-verify
  --comment <when>       on (default), off, or on-failure
  --comment-mode <how>   update (sticky, default) or create
  --dry-run              Print the summary. Do not call GitHub
  --out <file>           Write the summary Markdown
  --repo <owner/name>    Override GITHUB_REPOSITORY
  --pr <number>          Override the pull request number
  --api-url <url>        Override GITHUB_API_URL
  --event-path <file>    Override GITHUB_EVENT_PATH
  --json                 One JSON object on stdout
  --cwd <path>           Run as if started in this directory

Examples:
  agent-receipt pr-comment --dry-run
  agent-receipt pr-comment --fail-on high --policy org.yml --json
  agent-receipt pr-comment --command attest-verify --certificate-identity https://github.com/org/repo --certificate-oidc-issuer https://token.actions.githubusercontent.com
  agent-receipt pr-comment --comment on-failure --comment-mode update
`,

  policy: `agent-receipt policy — declarative policy packs

Usage:
  agent-receipt policy list [--json]
  agent-receipt policy show <pack> [--json]
  agent-receipt policy lint <file> [--json]
  agent-receipt policy test <pack> [receipts...] [--json]

Packs are YAML or JSON (\`apiVersion: agent-receipt/policy/v1\`). A rule has
\`id\`, \`description\`, \`severity\` (low, medium, high, critical), \`action\`
(deny or warn), and \`match\`. Match keys cover commands, files, tools,
adapters, network and package-install commands, exit codes, risk, agent,
unsigned receipts, redaction disabled, and size or count limits. There is
no Rego engine and no eval.

Built-in packs: \`builtin:baseline\`, \`builtin:supply-chain\`,
\`builtin:ci-protect\`, and \`builtin:strict\` (the other three, plus a
signature requirement). \`extends\` composes packs. The same rule id later
in the chain overrides the earlier one.

\`.agent-receipt.yml\` may set \`policyPacks\` and \`policyExceptions\`
(\`rule\`, \`path\`, \`reason\`, optional \`expires\`). An exception whose
date is before today (UTC) does not suppress a hit and fails a gate that
is using packs. \`doctor --strict\` fails on an invalid pack or an expired
exception. Default doctor keeps that row at INFO.

\`policy lint\` exits 1 on a schema error (unknown keys, duplicate ids, bad
globs). \`policy test\` exits 2 when a deny hit or an expired exception
matches, and 0 when there are only warnings or no hits. A missing pack
exits 1. It never passes silently.

\`--policy-pack\` on capture, wrap, share, verify, watch, and pr-comment
repeats. A comma-separated list is rejected. Repeat the flag:
\`--policy-pack <name> --policy-pack <name>\`. Deny hits exit 2. Warn hits
are reported. With no pack configured, those commands omit the policy keys
and behave as before.

\`--json\` prints one object (\`ok\`, \`command\`, \`action\`, \`version\`,
\`exitCode\`).

Examples:
  agent-receipt policy list
  agent-receipt policy show builtin:strict --json
  agent-receipt policy lint policies/baseline.yml
  agent-receipt policy test builtin:baseline
  agent-receipt wrap --policy-pack builtin:baseline --json
`,

  view: `agent-receipt view — local read-only receipt viewer

Usage:
  agent-receipt view [--port <n>] [--host 127.0.0.1] [--open] [--json]
  agent-receipt view --host 0.0.0.0 --allow-remote --allowed-host <name>
  agent-receipt view --static <dir> [--json]
  agent-receipt view --receipts <dir> [--cwd <dir>]

\`view\` serves the receipt store in a browser. The server is node:http
only. It binds 127.0.0.1 port 4173 unless you pass \`--port\` or \`--host\`.
\`--port 0\` picks a free port and prints the URL. A non-loopback host is
refused unless \`--allow-remote\` is also passed, which prints a warning.
\`--json\` prints one line (\`url\`, \`port\`, \`receiptCount\`, \`pid\`,
\`allowedHosts\`) and keeps serving. \`allowedHosts\` is empty when you
did not pass \`--allowed-host\`. \`--open\` opens the default browser and
does not fail the command when it cannot.

\`--allowed-host <name>\` (repeatable) is an exact Host allowlist for a
LAN browser. The value is a hostname, an IPv4 address, or an IPv6
address. IPv6 is compared in compressed lowercase form, so
\`fd00:0::1\`, \`[fd00::1]\`, and \`fd00::1\` are the same entry. Add
\`:port\` only when that Host port is not the bound port. Without
\`:port\` the name matches the bound port only. Names are lowercased.
IPv4 must be four decimal octets from 0 to 255 with no leading zeros
(\`192.168.1.20\`). A last label that is all digits or \`0x\` hex is
rejected (\`127.1\`, \`2130706433\`, \`0x7f000001\`, \`0x\`, \`foo.0x\`,
\`FOO.0X\`, \`1234\`, \`010.0.0.1\`). Punycode labels (\`xn--\`) are accepted. Unicode
internationalized names are rejected; pass the \`xn--\` form. There is
no DNS lookup, no interface list, and no wildcard. A comma-separated
list is rejected. Repeat the flag: \`--allowed-host <name> --allowed-host <name>\`.
An empty value, a value that starts with \`-\`, schemes, paths,
whitespace, and userinfo are rejected before the server listens.
\`--allowed-host -h\` is that usage error. It does not print help.
A non-loopback name requires \`--allow-remote\`. \`127.0.0.1\`,
\`localhost\`, and \`::1\` do not. \`--allowed-host\` is rejected with
\`--static\`.

The remote-bind warning lists the allowed hosts. Anyone who can reach
the port and send an allowed Host can read the redacted receipts.
There is no auth. \`X-Forwarded-Host\` is ignored.

\`--static <dir>\` writes \`index.html\` and \`data.json\` and exits. CSS and
script are inline. There is no CDN and no external font. The only link is
an empty favicon, \`<link rel="icon" href="data:,">\`. The same inputs
write the same bytes. Open \`index.html\` from disk. Do not pass
\`--allowed-host\` with \`--static\`.

The Content-Security-Policy is \`default-src 'none'\` with the sha256 of
the inline script and the inline style. \`connect-src\` is \`'self'\` while
serving and \`'none'\` in the static bundle. \`img-src data:\` allows that
empty favicon so the browser does not request \`/favicon.ico\`.
\`base-uri\` and \`form-action\` are \`'none'\`. There is no
\`unsafe-inline\`, \`unsafe-eval\`, wildcard, or remote origin.
\`frame-ancestors 'none'\` is on the HTTP header only. Browsers ignore that
directive in a meta tag and log a console error, so the meta policy omits
it.

The page lists time, agent, adapter, risk, exit, signed or unsigned,
verify status, and policy-pack hits. Filters cover agent, risk, signed,
failed, and text. A receipt shows commands, files, tool calls, the gate,
policy hits, signature, keyless, attestation, and hash-chain position.
Linked receipts show a parent/child session tree with host labels.

\`GET /api/receipts\`, \`GET /api/receipts/:id\`, \`GET /api/sessions\`, and
\`GET /api/verify/:id\` are the only API routes. Any other method returns
405. Unknown routes return 404 JSON. Receipt ids are an in-memory index.
A path is never a receipt id. The Host header must be the bound
host:port or an \`--allowed-host\` entry. IPv6 matches in compressed
form. Two Host headers are HTTP 400. \`X-Forwarded-Host\` is ignored.

View always redacts. \`--no-redact\` is rejected. Host labels that are not
secrets stay visible. Verify status uses the same hash and signature
checks as \`verify\`, including \`--trusted-key\` and \`--require-sig\`. A
tampered receipt is FAILED.

\`doctor\` reports the viewer as INFO. That row is not a failure.

Examples:
  agent-receipt view
  agent-receipt view --port 0 --open
  agent-receipt view --json
  agent-receipt view --host 0.0.0.0 --allow-remote --allowed-host myhost.local
  agent-receipt view --static ./viewer-dist
  agent-receipt view --require-sig --trusted-key <fp>
`,

  help: `agent-receipt help — show usage

Usage:
  agent-receipt help
  agent-receipt help <command>

Examples:
  agent-receipt help
  agent-receipt help capture
  agent-receipt help watch
`,

  version: `agent-receipt version — print version

Usage:
  agent-receipt version
  agent-receipt --version
`,
};

export function globalHelp(): string {
  return `agent-receipt ${VERSION} — tamper-evident git snapshot receipts for agent sessions

Usage:
  agent-receipt <command> [options]

Commands:
  init                   Write config + notes (--org sets redact + failOn; --retention; --auto-prune; --cursor, --grok, --claude, --codex)
  adapters               Native hooks: list, status, install, uninstall (--dry-run, --json, --no-stop)
  capture                Capture a git snapshot receipt (Markdown; --transcript records tool calls)
  wrap                   End-of-session: capture + TL;DR + verify
  share [path]           Redact + HTML (+ optional md, or --package handoff dir) + verify + TL;DR
  export [path]          Write self-contained HTML, Markdown, or --format intoto
  html [path]            Alias for export as HTML
  show [path]            Pretty-print last / given receipt (full body)
  last                   Path + glance of the most recent receipt (--json for scripts)
  history                List recent receipts (--agent, --uncommitted, --failed, --json)
  ls                     Alias for history
  watch                  Poll git; auto-capture on commits or dirty tree
  session <id>           List one session as a parent/child tree (--json)
  session export <id>    Pack a session into <id>.session/ beside outDir (alias: pack)
  session import <dir>   Verify a session package and merge it into outDir (alias: merge)
  keygen                 Create a local Ed25519 keypair under .agent-receipt/keys
  sign [path]            Attest the receipt sha256 into a .sig.json sidecar
  attest [path|last]     in-toto Statement v1 in a DSSE envelope (.intoto.jsonl). --keyless writes a Sigstore bundle. attest --verify checks either
  trust                  Known-keys allowlist: list, show, add <fp>, add --self, rm <fp>
  verify [path]          Hash-check integrity (hash-only; --package checks a share dir; --require-sig opts in)
  pr-comment             Gate summary as a sticky pull request comment (--dry-run, --json)
  import <dir>           Verify a share package, then copy receipt.md into outDir
  report [path|last]     Signed one-page HTML report (or report verify <file.html>)
  prove [path]           Prove-this-run: verify + audit link + signature status (--page writes foo.prove.md, --html writes foo.prove.html)
  audit                  List the compliance log (--event, --agent, --failed filter the listing)
  log                    Alias for audit
  prune                  Delete old receipts under outDir (opt-in; trusted prune; --dry-run, --force). autoPrune runs this after capture/wrap/watch
  retain                 Alias for prune
  doctor                 Health check (--json; --strict fails unset policy, unset retention, a broken audit chain, an invalid trust store, an invalid policy pack, and an expired policy exception)
  view                   Local read-only receipt viewer (loopback; --static writes an offline bundle)
  policy                 List, show, lint, and test policy packs (builtin:<name> or a file)
  compare [a] [b]        Diff two receipts (default: last vs previous)
  diff [a] [b]           Alias for compare
  install-hooks          Install opt-in post-commit capture hook
  uninstall-hooks        Remove managed hook sections
  help [command]         Show this help, or detailed help for a command
  version                Show version

Global options:
  --cwd <path>           Run as if started in this directory
  -h, --help             Show help
  -V, --version          Show version

Quickstart (≈ 60 seconds):
  npm i -g github:pramodreddyboddu/agent-receipt
  cd your-repo && agent-receipt init --cursor && agent-receipt install-hooks
  agent-receipt capture --agent cursor --message "first receipt"
  agent-receipt history && agent-receipt last && agent-receipt verify

Examples:
  agent-receipt init --org
  agent-receipt init --retention
  agent-receipt init --auto-prune
  agent-receipt init --cursor
  agent-receipt init --grok
  agent-receipt init --claude
  agent-receipt init --codex
  agent-receipt adapters
  agent-receipt adapters install claude-code --dry-run
  agent-receipt capture --agent claude-code --transcript session.jsonl --adapter claude-code
  agent-receipt wrap --agent cursor --message "session done"
  agent-receipt wrap --json --fail-on high
  agent-receipt share --out share.html --md share.md
  agent-receipt share --package
  agent-receipt wrap --agent grok --redact --message "grok session"
  agent-receipt capture --agent cursor --message "ship v0.6"
  agent-receipt capture --base main --message "PR vs main"
  agent-receipt capture --uncommitted --message "wip"
  agent-receipt capture --redact --out share.md
  agent-receipt export --redact --out share.html
  agent-receipt html
  agent-receipt capture --fail-on high
  agent-receipt history --json
  agent-receipt history --agent cursor
  agent-receipt history --uncommitted
  agent-receipt history --failed
  agent-receipt history --agent ci --failed --json
  agent-receipt ls --agent ci --limit 5
  agent-receipt watch --once --agent cursor
  agent-receipt watch --commits-only --once
  agent-receipt watch --interval 5
  agent-receipt last
  agent-receipt last --json
  agent-receipt keygen
  agent-receipt trust add --self
  agent-receipt sign
  agent-receipt attest
  agent-receipt attest --verify .agent-receipt/receipts/receipt.intoto.jsonl
  agent-receipt export --format intoto
  agent-receipt verify
  agent-receipt verify --package foo.share
  agent-receipt import foo.share
  agent-receipt verify --require-sig
  agent-receipt pr-comment --dry-run
  agent-receipt pr-comment --fail-on high --comment on
  agent-receipt trust list
  agent-receipt trust show
  agent-receipt prove
  agent-receipt prove --page
  agent-receipt prove --html
  agent-receipt report last
  agent-receipt report verify .agent-receipt/receipt.report.html
  agent-receipt session <id>
  agent-receipt session <id> --json
  agent-receipt session export <id>
  agent-receipt session import <id>.session --dry-run
  agent-receipt wrap --link --session new -- node agent-receipt wrap --agent child
  agent-receipt prove --json
  agent-receipt audit
  agent-receipt audit --event wrap
  agent-receipt audit --agent cursor --failed
  agent-receipt log --failed
  agent-receipt audit --verify
  agent-receipt prune --dry-run
  agent-receipt prune --force
  agent-receipt doctor
  agent-receipt doctor --json
  agent-receipt view
  agent-receipt view --port 0 --json
  agent-receipt view --host 0.0.0.0 --allow-remote --allowed-host myhost.local
  agent-receipt view --static ./viewer-dist
  agent-receipt compare
  agent-receipt install-hooks
  agent-receipt help wrap

Docs: https://github.com/pramodreddyboddu/agent-receipt
Agent tips: docs/agents.md · docs/grok-cli.md · examples/ (Cursor, Grok, Claude Code, Aider)
Prod / CI: docs/business.md · examples/org-policy.yml · examples/github/
Schema: docs/receipt.schema.json · docs/gate.schema.json · docs/signature.schema.json · docs/report-payload.schema.json · docs/intoto-statement.schema.json · Release: docs/RELEASE.md
`;
}

export function helpFor(topic?: string): string {
  if (!topic) return globalHelp();
  const key = topic.toLowerCase();
  const body = TOPICS[key];
  if (!body) {
    return (
      `Unknown help topic: ${topic}\n\n` +
      `Known topics: ${Object.keys(TOPICS).sort().join(', ')}\n\n` +
      globalHelp()
    );
  }
  return body.trimEnd() + '\n';
}

export { TOPICS };
