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
\`maxAgeDays\`), and other comments stay. Re-running when both keys are
already set exits 0 and does not rewrite them.

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
  --cwd <path>           Run as if started in this directory

Config \`.agent-receipt.yml\` may set \`redact: true\` and \`failOn: high\`
(see examples/org-policy.yml). Those apply when the flags above are omitted.

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
  --cwd <path>           Run as if started in this directory

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
  agent-receipt share [path] [--out <html>] [--md [file]] [--no-redact] [--fail-on …] [--json]

One shot for handing a receipt to someone else. Reuses export / html / verify /
redact (share-safety from 1.0.3: credential URLs, nested receipt bodies).

Defaults:
  - Newest receipt under outDir when path is omitted
  - --redact is ON unless you pass --no-redact (config redact: false does not turn this off)
  - HTML next to the receipt (sibling .html)
  - Optional Markdown only when --md / --markdown is set
  - Refuses to overwrite the source receipt
  - Does not write anything if the source receipt fails verify (no re-hash of a tampered body)

Prints TL;DR, html path, optional md path, source path, then verify.

Options:
  --out <path>           HTML output (default: sibling .html)
  --md [path]            Also write Markdown (default name: sibling .redacted.md)
  --markdown [path]      Alias for --md
  --redact               Accepted; this is already the default
  --no-redact            Write HTML/Markdown without masking
  --fail-on [high|medium|low]
                         Exit 2 if the source summary meets the threshold
                         (counts are not cleared by redaction). Bare = high.
                         Config failOn applies when the flag is omitted.
  --json                 One CI gate object on stdout (progress on stderr)
  --cwd <path>           Run as if started in this directory

Exit codes: 0 OK, 2 verify failure or --fail-on, 1 usage/runtime error.
Appends \`.agent-receipt/audit.jsonl\` (experimental hash chain; see \`help audit\`).

Examples:
  agent-receipt share
  agent-receipt share --out share.html --md share.md
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
  agent-receipt watch [--interval <sec>] [--once] [--commits-only] [--agent <name>] [--message <text>] [--fail-on …]

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
  --cwd <path>           Run as if started in this directory

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

Recomputes SHA-256 over the Markdown body (everything except the Integrity
section / hash marker) and compares it to the embedded marker.
Exit 0 = OK, exit 2 = mismatch / missing hash (or --fail-on met), exit 1 = usage error.

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

Examples:
  agent-receipt verify
  agent-receipt verify receipt.md
  agent-receipt verify --json
  agent-receipt verify --fail-on high --json
`,

  prove: `agent-receipt prove — prove-this-run (integrity + audit link)

Usage:
  agent-receipt prove [path] [--json] [--fail-on high|medium|low]

Resolves the path the same way verify does (newest receipt when omitted).
Recomputes the same SHA-256 as verify, then reports the path, hash,
verified, trailingIgnored, redacted, risk summary, TL;DR, agent,
uncommitted, failedOn, and a best-effort audit link.

This is tamper-evident prove-this-run. It is not a cryptographic signature.
This cut does not add keys, minisign, or GPG.

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
  reason
  ok is true only when exitCode is 0.

Exit codes:
  0  verified, and there is no audit log or the chain is intact
  2  verify failed, the audit chain is broken, or --fail-on tripped
  1  usage or runtime (missing receipt, unknown flag, bad --fail-on)

Examples:
  agent-receipt prove
  agent-receipt prove --json
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
  retention     maxCount / maxAgeDays (opt-in). Over the cap or a large outDir is a warning.
                Unset fails under --strict only when outDir is under pressure.
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
Unset retention still fails only when outDir is under pressure
(100 receipts or 20 MB). Below that threshold the retention row stays
INFO/WARN. A configured limit that would still delete files stays a
warning — run \`prune\`. \`--strict\` does not scan diffs.
\`init --retention\` sets maxCount: 100 and maxAgeDays: 30. That does not
change this pressure rule. Trusted prune refuses to delete when the audit
chain is broken unless you pass \`prune --force\`.
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
  share [path]           Redact + HTML (+ optional md) + verify + TL;DR
  export [path]          Write self-contained HTML (or Markdown) receipt
  html [path]            Alias for export as HTML
  show [path]            Pretty-print last / given receipt (full body)
  last                   Path + glance of the most recent receipt (--json for scripts)
  history                List recent receipts (--agent, --uncommitted, --failed, --json)
  ls                     Alias for history
  watch                  Poll git; auto-capture on commits or dirty tree
  verify [path]          Hash-check tamper-evident integrity
  prove [path]           Prove-this-run: verify + audit link (not a signature)
  audit                  List the compliance log (--event, --agent, --failed filter the listing)
  log                    Alias for audit
  prune                  Delete old receipts under outDir (opt-in; trusted prune; --dry-run, --force)
  retain                 Alias for prune
  doctor                 Health check (--json; --strict fails unset org policy and a broken audit chain)
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
  agent-receipt verify
  agent-receipt prove
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
Schema: docs/receipt.schema.json · docs/gate.schema.json · Release: docs/RELEASE.md
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
