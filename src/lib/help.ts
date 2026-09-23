import { VERSION } from './version.js';

const TOPICS: Record<string, string> = {
  init: `agent-receipt init — write config + setup notes

Usage:
  agent-receipt init [--cursor] [--grok] [--org] [--retention] [--cwd <path>]

Options:
  --cursor               Drop .cursor/rules/agent-receipt.mdc (agent runs capture)
  --grok                 Drop .grok rule + SessionEnd hook (dirty-tree wrap, --redact)
  --org                  Set redact: true and failOn: high (alias: --policy)
  --policy               Alias of --org
  --retention            Set maxCount: 100 and maxAgeDays: 30

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
\`failOn\`, \`outDir\`, and comments stay. Re-running when both are
already set exits 0 and does not rewrite them. Prints whether each key
was set or unchanged, then suggests \`prune --dry-run\`. No network.
Trusted prune still refuses to delete when the audit chain is broken.

Creates:
  .agent-receipt.yml          config (outDir, agent, ignore globs, …)
  .agent-receipt/SETUP.md     short next-steps (when the config is created)
  .cursor/rules/…             only with --cursor
  .grok/rules/…               only with --grok (loaded every Grok session)
  .grok/hooks/…               only with --grok (SessionEnd; needs grok --trust)

Examples:
  agent-receipt init
  agent-receipt init --org
  agent-receipt init --policy
  agent-receipt init --retention
  agent-receipt init --cursor
  agent-receipt init --grok
  agent-receipt init --cwd ~/code/my-app
`,

  capture: `agent-receipt capture — snapshot a git range into a Markdown receipt

Usage:
  agent-receipt capture [options]

Options:
  --base <ref>           Changes vs a base branch/ref (e.g. main); shows commits ahead
  --since <ref>          Diff range start (e.g. main, HEAD~5, abc123)
  --commits <N>          Last N commits (default: config or 1)
  --uncommitted          Snapshot dirty working tree (staged+unstaged+untracked)
  --message <text>       Human/agent session message
  --agent <name>         Agent label (default: config or "agent")
  --session <id>         Session / run id label
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
  --cwd <path>           Run as if started in this directory

Config \`.agent-receipt.yml\` may set \`redact: true\`, \`failOn: high\`, and
\`sign: true\` (see examples/org-policy.yml). Those apply when the flags
above are omitted. \`sign: true\` covers capture, wrap, and watch only.
\`init --org\` does not set \`sign\` (keys may be absent). After \`keygen\`
and \`trust add --self\`, add \`sign: true\`. \`--no-sign\` overrides.
Missing keys tip and leave the receipt unsigned (not exit 2).

Each capture under outDir updates .agent-receipt/index.json (stable receipt index).
Captures with --out outside outDir are not indexed (so they do not become newest).
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
  agent-receipt wrap [options]

If the working tree is dirty (and --base is not set), captures with --uncommitted;
otherwise captures commits (optionally vs --base). Explicit --base always uses a
commit range even if the tree is dirty. Prints TL;DR + path, then verifies.

Options:
  --agent <name>         Agent label (default: wrap)
  --message <text>       Session message (default: "session wrap")
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
  --cwd <path>           Run as if started in this directory

\`sign: true\` in \`.agent-receipt.yml\` signs this command when neither
flag is passed. \`init --org\` does not set \`sign\` (keys may be absent).
Add it after \`keygen\` and \`trust add --self\`. \`--no-sign\` overrides.
share, export, prove, and verify do not read config \`sign\`.

Exit codes: 0 OK, 2 fail-on threshold or verify failure, 1 usage/runtime error.
\`--json\` does not change those codes. Both failures still exit 2; the gate
object sets \`failedOn\` and \`verified\` so CI can tell them apart.
A line is appended to \`.agent-receipt/audit.jsonl\` (see \`help audit\`).

Examples:
  agent-receipt wrap --agent cursor --message "done with auth"
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

  export: `agent-receipt export — write a shareable HTML (or Markdown) receipt

Usage:
  agent-receipt export [path] [--out <file>] [--redact] [--format html|markdown]

If path is omitted, exports the newest receipt under outDir.
Default format is self-contained HTML (no external CSS/JS) — open in a browser
or share as a single file.

Options:
  --out <path>           Output path (default: sibling .html next to the receipt)
  --redact               Mask high/secret findings before writing
  --format <html|markdown|md>
                         Output format (default: html)
  --cwd <path>           Run as if started in this directory

Markdown output uses the same sidecar rule as \`share\`: copy a valid source
sidecar when the sha256 is unchanged, or re-sign the published file when
local keys exist and the body was rewritten. HTML stays unsigned. Peers
verify and sign the Markdown.

Appends \`.agent-receipt/audit.jsonl\` (event \`export\`). \`share\` records
\`share\` instead, so an export made by share is not a second line.
The line stores the output path and the markdown body's sha256 — not the
HTML bytes and not a diff.

Examples:
  agent-receipt export
  agent-receipt export --out share.html --redact
  agent-receipt export receipt.md --format markdown --redact --out safe.md
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
  agent-receipt watch [--interval <sec>] [--once] [--commits-only] [--agent <name>] [--message <text>] [--fail-on …] [--sign] [--no-sign]

Defaults: poll every 5 seconds; watch **commits + dirty tree** until Ctrl+C.
Dirty-tree captures are labeled **uncommitted**.
--commits-only: restore v0.4 HEAD-only behavior.
--once: wait for the next change, capture once, exit (Cursor / agent “run after session”).

Options:
  --interval <sec>       Poll interval (default: 5, min 1, max 3600)
  --once                 Capture after the next change, then exit
  --commits-only         Only watch HEAD commits (ignore dirty tree)
  --agent <name>         Agent label (default: watch)
  --message <text>       Session message
  --fail-on [high|medium|low]
                         After capture, exit 2 when --once if threshold met
  --json                 Also write companion .json on each capture
                         (human stdout stays; CI gates use capture/wrap/share/verify --json)
  --sign                 Sign each capture when local keys exist (also on
                         when config sign: true). Missing keys tip and leave
                         the receipt unsigned. Not exit 2. Not a CA.
  --no-sign              Force signing off (overrides config sign: true)
  --cwd <path>           Run as if started in this directory

Config \`sign: true\` is passed through to each capture. \`init --org\` does
not set \`sign\`. \`--no-sign\` overrides. share, export, prove, and verify
do not read this key.

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
directory. The private key is never written.

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
  agent-receipt prove [path] [--json] [--page] [--one-pager] [--out <path>] [--fail-on high|medium|low] [--trusted-key <fp>]

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
The one-pager is not itself signed. HTML export of this page is deferred.

Default path: \`foo.md\` → \`foo.prove.md\` in the same directory. A receipt
whose name does not end in \`.md\` gets \`<name>.prove.md\`
(\`notes.txt\` → \`notes.txt.prove.md\`) so it does not collide with a
Markdown receipt of the same stem.

\`--out <path>\` overrides that destination and requires \`--page\`. An
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
  ok is true only when exitCode is 0.
  --page adds pagePath (string) when the one-pager was written.

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
first). \`audit --verify\` checks that chain. Exit 0 = intact, exit 2 =
mismatch, exit 1 = unreadable or a bad flag. This is **experimental**
tamper-evidence for the log — not a signature and not PKI.

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
deleting. Capture, wrap, and watch never prune on their own.
\`init --retention\` sets \`maxCount: 100\` and \`maxAgeDays: 30\`.

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
young enough. Sibling \`<receipt>.json\` is deleted with the markdown.
\`index.json\` is rewritten (temp file + rename) so removed paths drop out.
Rows that already point at missing files under outDir are dropped too.
\`audit.jsonl\` and \`SETUP.md\` are never deleted. Symlinks are skipped.

\`--dry-run\` prints the plan and does not delete, rewrite the index, or
append \`audit.jsonl\`. An applied delete appends one \`prune\` audit line
per receipt (path, sha256, agent, redacted, verified, exit — no diff body
and no \`--message\`). The sibling \`.json\` is not a second event. A run
that deletes nothing does not append.

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
  git-clean     working tree clean? Dirty is a warning, not a failure
  cursor        init --cursor rule present?
  grok          init --grok rule + SessionEnd hook present?

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
\`init --retention\` sets maxCount: 100 and maxAgeDays: 30. Trusted prune
refuses to delete when the audit chain is broken unless you pass
\`prune --force\`.
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
  init                   Write config + notes (--org sets redact + failOn; --retention; --cursor, --grok)
  capture                Capture a git snapshot receipt (Markdown)
  wrap                   End-of-session: capture + TL;DR + verify
  share [path]           Redact + HTML (+ optional md, or --package handoff dir) + verify + TL;DR
  export [path]          Write self-contained HTML (or Markdown) receipt
  html [path]            Alias for export as HTML
  show [path]            Pretty-print last / given receipt (full body)
  last                   Path + glance of the most recent receipt (--json for scripts)
  history                List recent receipts (--agent, --uncommitted, --failed, --json)
  ls                     Alias for history
  watch                  Poll git; auto-capture on commits or dirty tree
  keygen                 Create a local Ed25519 keypair under .agent-receipt/keys
  sign [path]            Attest the receipt sha256 into a .sig.json sidecar
  trust                  Known-keys allowlist: list, show, add <fp>, add --self, rm <fp>
  verify [path]          Hash-check integrity (hash-only; --package checks a share dir; --require-sig opts in)
  import <dir>           Verify a share package, then copy receipt.md into outDir
  prove [path]           Prove-this-run: verify + audit link + signature status (--page writes foo.prove.md)
  audit                  List the compliance log (--event, --agent, --failed filter the listing)
  log                    Alias for audit
  prune                  Delete old receipts under outDir (opt-in; trusted prune; --dry-run, --force)
  retain                 Alias for prune
  doctor                 Health check (--json; --strict fails unset policy, unset retention, a broken audit chain, and an invalid trust store)
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
  agent-receipt init --cursor
  agent-receipt init --grok
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
  agent-receipt verify
  agent-receipt verify --package foo.share
  agent-receipt import foo.share
  agent-receipt verify --require-sig
  agent-receipt trust list
  agent-receipt trust show
  agent-receipt prove
  agent-receipt prove --page
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
  agent-receipt compare
  agent-receipt install-hooks
  agent-receipt help wrap

Docs: https://github.com/pramodreddyboddu/agent-receipt
Agent tips: docs/agents.md · docs/grok-cli.md · examples/ (Cursor, Grok, Claude Code, Aider)
Prod / CI: docs/business.md · examples/org-policy.yml · examples/github/
Schema: docs/receipt.schema.json · docs/gate.schema.json · docs/signature.schema.json · Release: docs/RELEASE.md
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
