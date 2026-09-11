# Changelog

All notable changes to this project will be documented in this file.

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
