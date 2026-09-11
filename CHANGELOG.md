# Changelog

All notable changes to this project will be documented in this file.

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
