# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] — 2026-09-11

### Changed

- Renamed npm package to scoped `@pramodreddyboddu/agent-receipt` (unscoped `agent-receipt` is taken on npm)
- Package version bumped to `1.0.1`
- CLI binary name remains `agent-receipt` (UX unchanged)
- README / `docs/RELEASE.md` install and publish commands updated for the scoped name

## [1.0.0] — 2026-09-11

First **stable** public-ready release. Same feature surface as 0.6.0; version and
packaging polish for npm strangers.

### Highlights (0.1 → 0.6 → 1.0)

- **Core**: `init`, `capture`, `show`, `verify` with SHA-256 tamper-evident receipts
- **Session UX**: TL;DR + “What to review”, `last`, `history` / `ls`, `compare` / `diff`
- **Automation**: `install-hooks`, `watch` (commits + dirty tree), Cursor rule via `init --cursor`
- **Risk**: high-signal diff/path heuristics, `--fail-on`, `riskAllowlist`, high-entropy scan
- **v0.6**: `wrap` (end-of-session one-shot), `export` / `html`, `--base`, `--redact`
- **Ops**: `doctor`, config `ignore` globs, JSON schema, GitHub install path

### Changed

- Package version bumped to `1.0.0`
- npm metadata: punchier description, expanded keywords, `publishConfig.access=public`
- README aimed at npm / GitHub installers; `wrap` as the hero command
- `SECURITY.md` added (reporting + heuristic scanner limits)
- `docs/RELEASE.md` updated for v1.0.0 tag / publish commands
- `npm run pack:check` asserts `npm pack --dry-run` includes `bin` + `dist`

## [0.6.0] — 2026-09-11

### Added

- `wrap` — one-shot end-of-session: capture (with `--uncommitted` if dirty) →
  print TL;DR + path → verify (`--agent`, `--message`, `--fail-on`, `--base`,
  `--redact`)
- `export` / `html` — write a self-contained HTML receipt (or export last) for
  open/share; `--out`, `--redact`, `--format html|markdown`
- `capture --base <ref>` — summarize changes vs a base branch (e.g. `main`);
  range label shows **commits ahead** + file stats
- `--redact` on capture / wrap / export — mask high/secret findings in
  Markdown/HTML for safer sharing (re-hashed so verify still passes)
- README docs for wrap / export / base / redact

### Changed

- Package version bumped to `0.6.0`

## [0.5.1] — 2026-09-11

### Added

- Text `history` / `ls` shows a yellow **`[uncommitted]`** badge on dirty-tree
  receipts (same `uncommitted` field already present in `history --json` / index)

### Changed

- Text history prefers `.agent-receipt/index.json` (like `--json`) so the badge
  and risk counts stay consistent with the index
- Package version bumped to `0.5.1`

## [0.5.0] — 2026-09-11

### Added

- `watch` dirty-tree detection — auto-capture staged/unstaged/untracked changes
  (labeled **uncommitted**); `--commits-only` restores v0.4 HEAD-only behavior
- `capture --uncommitted` — snapshot the dirty working tree explicitly
- Config `riskAllowlist` — suppress findings by rule id and/or path glob
  (`code`, `code:pathGlob`, `*:pathGlob`); documented in README
- Light **high-entropy** token scan on added diff lines (`high-entropy-secret`)
  to reduce secret false negatives without pulling gitleaks
- `history --json` — machine-readable receipt list
- Stable receipt index at `.agent-receipt/index.json` (updated on every capture)

### Changed

- Default `watch` now monitors commits **and** dirty tree
- Package version bumped to `0.5.0`

## [0.4.0] — 2026-09-11

### Added

- `history` / `ls` — list recent receipts (time, agent, risk counts, short summary)
- `watch` — poll git HEAD and auto-capture on new commits
  - default interval 5s; `--interval <sec>`; `--once` waits for the next commit then exits
  - captures `--since` the previous HEAD so the whole interval is in the receipt
  - documented as the Cursor / agent “run after session” path
- `init --cursor` — drops `.cursor/rules/agent-receipt.mdc` (`alwaysApply: true`)
  that instructs the agent to **run** capture (not only remind)
- `capture --fail-on [high|medium|low]` — write the receipt, then exit 2 if max
  severity meets the threshold (bare `--fail-on` = high). For CI scripts.
- Smarter risk engine:
  - high-signal **diff content**: AWS access key ids, AWS secret assignments,
    private key PEM/blocks, GitHub tokens, Slack tokens
  - dedicated `env-file` for committed `.env` / `.env.local` / `.env.production`
  - severity ranking (high → low) on the receipt and in `--fail-on`
- Receipt polish: one-screen **TL;DR** at top + **What to review** checklist
- JSON `summary.tldr` and `summary.review`

### Changed

- Risk false-positive trim: `src/auth/*.ts` is no longer a medium “auth-path”;
  only secret-store filenames (`tokens.json`, `htpasswd`, …) flag
- `.env.example` / `.env.sample` / `.env.template` are low `env-template`, not high
- `id_rsa.pub` is not treated as an SSH private key; common image/font binaries
  are low instead of medium
- README leads with “why this exists” + a 60-second best path
- Cursor example rule is `alwaysApply: true` and requires the agent to run capture
- Package version bumped to `0.4.0`

## [0.3.1] — 2026-09-11

### Fixed

- `install-hooks` embeds `node` + absolute path to this package's bin so local/global
  installs work without npm publish (`npx` is last resort only)
- Hook runtime prefers `AGENT_RECEIPT_BIN` → embedded bin → `npx`

### Changed

- Documented `AGENT_RECEIPT_BIN` and default hook resolution in README + `examples/hooks.md`

## [0.3.0] — 2026-09-11

### Added

- `doctor` — environment health check (Node ≥ 20, git, repo, config, hooks, outDir)
- `compare` / `diff` — show what changed between two receipts (default: last vs previous)
- Config `ignore` globs — exclude noise paths from risk / summary / file tables
  (defaults: `node_modules/**`, `dist/**`, `coverage/**`; lockfile options documented)
- `agent-receipt help <cmd>` — man-page style per-command help
- `docs/receipt.schema.json` — JSON Schema for `capture --json` companion files
- `docs/RELEASE.md` — public + npm publish checklist (manual; agents do not publish)
- Capture flags: `--diff-stat` / `--no-diff-stat`, `--top-risks <N>`
- `install-hooks --uninstall` compat alias

### Changed

- README leads with a 30-second GitHub install → init → hooks → last/verify path
- Default `.agent-receipt.yml` from `init` includes `ignore` list
- Package version bumped to `0.3.0`

## [0.2.0] — 2026-09-11

### Added

- `last` command — path + glance of the newest receipt (`--path` for scripting)
- `install-hooks` / `uninstall-hooks` — opt-in post-commit (and optional `--pre-push`) auto-capture
- Agent integration docs: Cursor, Claude Code, Aider (`docs/agents.md`, `examples/`)
- Receipt **Summary** rollup, **Notable changes**, **Diff stat**, **Risk findings** table
- Richer risk signals: auth paths, package.json / manifests, large/broad diffs, `.netrc`
- JSON receipts include a `summary` object (counts + notable)
- Clearer CLI help / success / error messages (optional ANSI color)

### Changed

- Package version bumped to `0.2.0`
- npm publish readiness: `files` allowlist includes `docs/`, `types`/`exports` refined, `prepublishOnly` runs tests

## [0.1.0] — 2026-09-11

### Added

- Initial release of `agent-receipt` CLI
- Commands: `init`, `capture`, `show`, `verify`
- Capture flags: `--since`, `--commits`, `--message`, `--agent`, `--session`, `--out`, `--full`, `--json`, `--cwd`
- Risk hints for secret-looking paths, binaries, lockfile/CI deletions
- SHA-256 tamper-evident integrity footer
- TypeScript ESM build, `node:test` suite, GitHub Actions CI (shipped under `docs/`)
- Example receipt under `examples/`
