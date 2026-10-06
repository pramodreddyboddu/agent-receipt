# Policy packs

Policy packs are declarative rules an org can review in git. `agent-receipt`
evaluates them against a receipt. A **deny** hit fails the gate (exit 2). A
**warn** hit is reported and does not change the exit code. A missing,
unreadable, or invalid pack fails closed (exit 1). It never passes silently.

The matcher is small and deterministic. Conditions are AND across keys and OR
inside a list. There is no Rego engine and no `eval`.

Schema: [`policy-pack.schema.json`](policy-pack.schema.json).

## Pack file

YAML and JSON use the same fields. JSON is used when the file ends in `.json`
or the text starts with `{`.

```yaml
apiVersion: agent-receipt/policy/v1
name: local
description: Repo overrides on top of the baseline pack.
extends:
  - builtin:baseline
rules:
  - id: secrets-files
    description: Warn on env examples; baseline still denies real secret files.
    severity: low
    action: warn
    match:
      files:
        - "**/.env.example"
```

| Field | Required | Values |
|-------|----------|--------|
| `apiVersion` | yes | `agent-receipt/policy/v1` |
| `name` | yes | Pack name stored on each hit |
| `description` | yes | One line |
| `extends` | no | `builtin:<name>` or a path relative to this file |
| `rules` | no | Own rules. A pack needs `rules`, `extends`, or both |

Each rule needs `id` (kebab-case, unique in the file), `description`,
`severity` (`low`, `medium`, `high`, `critical`), `action` (`deny` or `warn`),
and a non-empty `match`. The same id contributed by `extends` is an override:
the later definition wins. A cycle, or an extends chain deeper than 8, fails
closed.

### Match keys

Receipt fields already on the Markdown are what the matcher reads: the files
table, tool-call bullets, the adapter line, the agent line, the risk summary,
and whether a signature sidecar is present.

| Key | Matches |
|-----|---------|
| `command` / `commands` | Command text. A glob by default. `regex:` or `/pattern/flags` is a regular expression (flags `i`, `m`, `s` only, source at most 200 characters) |
| `files` / `file` | Changed-path globs, such as `.github/workflows/**`, `**/.env`, `**/.env.*`, `**/package-lock.json` |
| `tool` / `tools` | Tool name globs |
| `adapter` | Adapter name globs |
| `agent` | Agent name globs |
| `network` | `true` when a command starts `curl`, `wget`, `ssh`, or the same client set |
| `packageInstall` | `true` for `npm install`, `pip install`, and the same install forms |
| `publish` | `true` for `npm publish` and the same publish forms |
| `exitCode` / `exitCodes` | An integer, `nonzero`, `any`, or a list |
| `risk` | `low`, `medium`, or `high` (at or above). `critical` is not a receipt risk and fails lint |
| `unsigned` | `true` when the receipt has no valid signature sidecar |
| `redactionDisabled` | `true` when the body was not redacted |
| `maxFiles`, `maxBytes`, `maxCommands`, `maxToolCalls` | Integers. A hit when the receipt is strictly greater |

`**` must be its own path segment. An unclosed `[` fails lint. Unknown keys
fail lint. Alias pairs (`command` and `commands`, and the same for files,
tools, and exit codes) cannot both be set.

Evidence stored on a hit is redacted with the same secret masks as receipts,
clipped, and has pipes and newlines replaced so a Markdown table stays intact.

## Built-in packs

Shipped under `policies/` and referenced as `builtin:<name>`.

| Pack | What it denies |
|------|----------------|
| `builtin:baseline` | Secret and credential paths, `.github/workflows/**`, force-push and history rewrite, `curl` or `wget` piped to `sh` or `bash` |
| `builtin:supply-chain` | Lockfiles, package install commands, publish commands. Dependency manifests (`package.json` and the same) are **warn** |
| `builtin:ci-protect` | Workflow and CI config paths, credential paths |
| `builtin:strict` | The three packs above, plus `unsigned: true` |

`policy list` prints the built-ins. `policy show builtin:strict` prints the
composed rules. A rule keeps the name of the pack that defined or overrode it.

## Repo config

`.agent-receipt.yml` may set:

```yaml
policyPacks:
  - builtin:baseline
  - ./policies/local.yml
policyExceptions:
  - rule: secrets-files
    path: "**/.env.example"
    reason: templates are not secrets
    expires: 2099-01-01
```

`policyPacks` entries are `builtin:<name>` or a file path. Repeat
`--policy-pack` on the command line. Flags are applied first, then the config
list. The same rule id later in that list wins. Pack paths cannot contain a
comma: repeatable flags are joined with commas.

An exception needs `rule`, `path` (a glob), and `reason`. `expires` is
`YYYY-MM-DD` in UTC. The exception applies on that date. A date before today
is expired: it does not suppress the hit, and a gate that is using packs
exits 2. `doctor --strict` fails an invalid pack or an expired exception.
Default `doctor` keeps the `packs` row at INFO. Unset packs stay INFO under
`--strict`.

A file exception drops only the paths that match. The hit remains when any
triggering path is left. For a hit that is not a file path, `**` or `*`
suppresses it everywhere. Any other glob suppresses it only when every
changed file matches.

Commented `# policyPacks:` in the default config is not active.

## Commands

```bash
agent-receipt policy list
agent-receipt policy show builtin:baseline
agent-receipt policy lint policies/baseline.yml
agent-receipt policy test builtin:baseline
agent-receipt policy test ./local.yml .agent-receipt/receipts/receipt.md --json
```

| Command | Exit |
|---------|------|
| `policy lint` | 1 on schema errors, unknown keys, duplicate ids, or bad globs. 0 when the pack composes |
| `policy test` | 2 on a deny hit or an expired exception. 0 on warnings or no hits. 1 when the pack or a receipt path is missing |
| `policy list` / `policy show` | 1 when a named pack is missing or invalid |

`--json` prints one object (`ok`, `command`, `action`, `version`, `exitCode`).

`--policy-pack` is repeatable on `capture`, `wrap`, `share`, `verify`,
`watch`, and `pr-comment`. With no pack configured, those commands omit
`policyPacks`, `policyPackHits`, and `policyDenied` and behave as before.
When packs run and nothing hits, the keys are present, `policyDenied` is
false, and the receipt has a `## Policy packs` section that says none.

`verify --package` does not take `--policy-pack`. `attest-verify` does not
evaluate packs.

## Gate, receipt, and comment

A deny hit sets `failedOn` and exit 2. The reason looks like
`policy pack deny: secrets-files`. An expired exception adds
`expired policy exception: secrets-files (2000-01-01)`.

The gate JSON and the companion receipt JSON include `policyPackHits`
(`rule`, `pack`, `severity`, `action`, `evidence`, `receipt`) and
`policyDenied`. The receipt Markdown gains `## Policy packs` before the
integrity footer, and the hash covers that section. `pr-comment` adds
`### Policy packs` to the summary. Evidence is redacted in all three.

The GitHub Action input `policy-pack` is a comma-separated list passed
through as repeated `--policy-pack`. See [`github-action.md`](github-action.md).
