# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] — 2026-09-11

### Added

- Initial release of `agent-receipt` CLI
- Commands: `init`, `capture`, `show`, `verify`
- Capture flags: `--since`, `--commits`, `--message`, `--agent`, `--out`, `--full`, `--json`
- Risk hints for secret-looking paths, binaries, lockfile/CI deletions
- SHA-256 tamper-evident integrity footer
- TypeScript ESM build, `node:test` suite, GitHub Actions CI
- Example receipt under `examples/`
