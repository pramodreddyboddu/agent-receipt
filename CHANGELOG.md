# Changelog

All notable changes to this project will be documented in this file.

## [1.0.21] — 2026-09-22

### Added

- `prove --page` (alias `--one-pager`) writes a plain-English Markdown one-pager after the existing prove report. Exit codes are unchanged, including FAILED (exit 2). Default path: `foo.md` → `foo.prove.md` beside the receipt. A receipt whose name does not end in `.md` gets `<name>.prove.md` (`notes.txt` → `notes.txt.prove.md`). `--out <path>` overrides that destination (an existing directory, or a path ending in `/`, receives `<stem>.prove.md` inside; any other path is the file). The page lists verdict (PROVED or FAILED), path, sha256, verified, trailingIgnored, redacted, risk, tldr, agent, uncommitted, failedOn, audit (present / chain / events / matched), signature (present / ok / trusted / fingerprint / reason), and failOn or reason when set, plus a short tamper-evident footer. It is not itself signed. Human stdout keeps the PROVED/FAILED banner and prints one `page:` line when a file was written. `--json` stays one prove object and adds `pagePath` only when `--page` wrote a file. Without `--page`, prove stays stdout-only. The command does not append the audit log. `last`, `history`, and `prune` ignore `*.prove.md` so the page is not treated as a receipt.

### Changed

- Package version bumped to `1.0.21`.
- [`docs/business.md`](docs/business.md) documents the one-pager under prove. The prove-for-humans one-pager is landed. HTML/share signed package stays deferred. The lead sentence tracks 1.0.21.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`README.md`](README.md) tip `prove --page` after prove. Pin comments that track the current cut are `v1.0.21`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.21. After wrap/sign, smoke runs `prove --json --page` and checks `pagePath`, `PROVED`, and sha256 in `*.prove.md`. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.21`. No new action input.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. The one-pager is not a signature and not access control.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, config `sign: true` (and `--no-sign`) so org policy can default capture/wrap to sign, `trust show`, SSO / IdP, Cloud Agents, a background deleter, an HTML/share signed package (and a signed one-pager), multi-agent receipt linking, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.20] — 2026-09-22

### Added

- `trust add --self` (alias: `trust add self`) loads the local Ed25519 keypair with `loadKeys` (the same pair as `sign` and `keygen`) and appends that fingerprint to `.agent-receipt/trusted-keys.txt` via `addTrustedFingerprint`. Already listed exits 0 with `added: false`. Missing keys exit 1 and name `keygen`. The command does not create a keypair, does not write private keys, and does not edit config `trustedFingerprints`. `--json` keeps the trust report (`action: "add"`) and adds `fingerprint` when the local key resolved. `trust add <64-hex>` is unchanged. This is not a CA.

### Changed

- Package version bumped to `1.0.20`.
- [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) auto-trust, when `require-sig` is true and `trusted-keys` is empty, runs `agent-receipt trust add --self` after temp `keygen` instead of hand-writing the fingerprint file. Fail-closed semantics are unchanged: prove still requires `signature.trusted` true. A non-empty `trusted-keys` value is still installed as given. Pin comments are `v1.0.20`.
- [`examples/github/action.yml`](examples/github/action.yml) pin comments are `v1.0.20`. A comment names `trust add --self`. No new action input.
- Recommended local recipe in [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`docs/business.md`](docs/business.md): `keygen` → `trust add --self` → `wrap --sign --fail-on high --json` → `prove` → `verify --require-sig`. Still not a CA.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.20 and smoke `trust add --self` (allowlist activates, prove `signature.trusted` true, `verify --require-sig` exits 0, second call is idempotent). Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/org-policy.yml`](examples/org-policy.yml) pin comment is `v1.0.20`.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, config `sign: true` (and `--no-sign`) so org policy can default capture/wrap to sign, SSO / IdP, Cloud Agents, a background deleter, an HTML/share signed package, a prove-for-humans one-pager, multi-agent receipt linking, `trust show`, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.19] — 2026-09-22

### Added

- CI signed gate drop-in (live [`.github/workflows/*`](.github/workflows) was not edited). [`examples/github/action.yml`](examples/github/action.yml) accepts optional `sign` (default false). When true, `wrap` is invoked with `--sign`. `share` still re-signs published Markdown when keys exist; if the gate path has no sidecar, the step runs `sign` on that path. Missing Ed25519 keys fail the step and name `keygen` (CLI `wrap --sign` still only tips and leaves the receipt unsigned). `trusted-keys` is installed before wrap, sign, prove, and verify. After `sign: true` and `require-sig: true`, the step runs `verify --require-sig` on the gate path. When prove is also on and the allowlist lists a fingerprint, prove must report `signature.trusted` true. Recommended combo: `sign: true`, `require-sig: true`, `trusted-keys: "<path-or-comma-fps>"`. Not a CA. No org secret.
- [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) accepts optional `sign` (default false) with the same fail-closed rule. When `require-sig` is true and `trusted-keys` is empty, the job writes the temp `keygen` fingerprint to `.agent-receipt/trusted-keys.txt` and the signed prove requires `signature.trusted` true. A non-empty `trusted-keys` value is installed as given and is not appended.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) is the signed CI recipe: `keygen` (or restore keys) → trusted-keys allowlist → `wrap --sign --fail-on high --json` → `prove` → `verify --require-sig`. Linked from the README and [`docs/business.md`](docs/business.md).

### Changed

- Package version bumped to `1.0.19`.
- Pin comments in the GitHub examples, [`docs/business.md`](docs/business.md), and [`examples/org-policy.yml`](examples/org-policy.yml) are `v1.0.19`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) keeps the 1.0.18 trust-store smoke and adds a `wrap --sign` smoke: a sidecar is written, prove `signature.ok` is true, and with that fingerprint allowlisted prove `signature.trusted` is true and `verify --require-sig` exits 0. Version-range comments include 1.0.19. Live [`.github/workflows/*`](.github/workflows) was not edited.
- `capture --sign` / `wrap --sign` help names the CI fail-closed difference in one line. The CLI flags themselves are unchanged.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, config `sign: true` (and `--no-sign`) so org policy can default capture/wrap to sign, `trust add --self`, SSO / IdP, Cloud Agents, a background deleter, an HTML/share signed package, a prove-for-humans one-pager, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.18] — 2026-09-22

### Added

- Fingerprint trust store / known-keys allowlist. Not a CA. `.agent-receipt/trusted-keys.txt` holds one lowercase 64-hex fingerprint per line (`#` comments and blank lines ignored; trailing whitespace stripped). An invalid line fails closed when the store is loaded for a gate. Config key `trustedFingerprints` (YAML list) unions with the file. Either source alone is enough. Empty or missing both leaves the allowlist inactive: `verify --require-sig` still accepts any cryptographically valid sidecar (1.0.17 behavior). The default path stays under gitignored `.agent-receipt/` so local lists stay private. Teams may commit a copy under `examples/` or `docs/` and copy it in.
- `verify --require-sig` checks the sidecar fingerprint after the hash matches and the signature verifies, when the allowlist is non-empty. A missing fingerprint exits 2 with `fingerprint not trusted` and the fingerprint. `--trusted-key <fp>` (repeatable or comma-separated) unions with the file and config for that invocation only. `verify --json` signature gains additive `trusted` (`true`, `false`, or `null`). Required gate keys are unchanged.
- `prove` uses the same allowlist when a sidecar is present and cryptographically valid. A fingerprint that is not listed sets `signature.ok` false, `signature.trusted` false, and exits 2. The reason mentions the trust store. When the store is inactive, `signature.trusted` is null and prove stays as in 1.0.17 (a missing sidecar still does not fail).
- `doctor` adds a `trust` row: INFO when no store is configured, PASS with the fingerprint count when the store is readable, WARN when the store is present but empty or unreadable or has an invalid line. A missing store does not fail default `doctor` or `doctor --strict`. Invalid lines FAIL under `--strict`.
- `trust list`, `trust add <fp>`, and `trust rm <fp>` edit `trusted-keys.txt` (`--json` prints one object).
- `capture --sign` and `wrap --sign` are opt-in. After a successful write, local keys produce `*.sig.json` (the same sidecar as `sign`). Missing keys print a tip and leave the receipt unsigned. That does not exit 2. The flags are off by default. Share still re-signs published Markdown when keys exist.

### Changed

- Package version bumped to `1.0.18`.
- CI examples (live [`.github/workflows/*`](.github/workflows) was not edited). Pin comments are `v1.0.18`. [`examples/github/action.yml`](examples/github/action.yml) and [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) accept optional `trusted-keys` (a file path or comma-separated fingerprints) installed as `.agent-receipt/trusted-keys.txt` before prove / `verify --require-sig`. Empty leaves the allowlist inactive.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) keeps the 1.0.17 `verify --require-sig` smoke and adds a trust-store smoke: a matching fingerprint exits 0, a non-matching fingerprint exits 2 on verify and prove. Version-range comments include 1.0.18. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. The thin known-keys allowlist landed; full PKI/CA is still deferred.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.17] — 2026-09-22

### Added

- `verify --require-sig` (alias `--require-signature`) is opt-in. Default `verify` stays hash-only: unsigned receipts still pass, and a missing or invalid sidecar does not fail. With the flag, the existing Markdown hash check runs first (hash failure still exits 2). After a matching hash, a valid `*.sig.json` beside the receipt is required (`inspectReceiptSignature` / `verifySignature`). A missing sidecar exits 2 with reason `signature required: signature absent`. A present sidecar that is invalid, mismatched, or malformed exits 2 with the signature reason. A valid sidecar for the current sha256 exits 0 unless `--fail-on` also trips. `verify --json --require-sig` adds optional `signature` `{ present, ok, alg, fingerprint, reason }` on the gate. The field is omitted when `--require-sig` was not passed. No config key. `capture`, `wrap`, and `share` do not turn the flag on.
- Share and export Markdown sidecar handoff. `foo.md` → `foo.sig.json`. HTML stays unsigned. When the published Markdown sha256 equals the source and a valid source sidecar exists, that sidecar is copied. When redact (or any rewrite) changes the sha256, the old sidecar is not copied. Local keys (`loadKeys`, the same pair as `sign`) re-sign the published Markdown. Missing keys leave it unsigned, remove any destination sidecar, and print a short `keygen` / `sign` tip. That tip does not exit 2. `share --json` adds optional `sigPath` (string or null). Private keys are never written into a receipt or sidecar.
- CI examples (live [`.github/workflows/*`](.github/workflows) was not edited). [`examples/github/action.yml`](examples/github/action.yml) gains optional `require-sig` (default false). When true, after a green gate it runs `verify --require-sig` on the receipt path. The job must `keygen` and `sign` (or restore keys) first. [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) gains optional `require-sig` (default false) that temp-`keygen`s, `sign`s, and checks `prove` `signature.ok` plus `verify --require-sig`. No org secret. Pin comments are `v1.0.17`.
- `doctor --strict` always fails unset retention (`maxCount` / `maxAgeDays`) on any `outDir`, including a small or empty one. Default `doctor` stays pressure-gated (INFO until 100 receipts or 20 MB, then WARN). A configured limit that would still delete stays a warning. `init --retention` still sets the two limits.

### Changed

- Package version bumped to `1.0.17`.
- [`docs/gate.schema.json`](docs/gate.schema.json) documents optional `signature` and `sigPath`. Required gate keys are unchanged.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) runs `verify --require-sig` on the signed receipt (exit 0) and on an unsigned copy (exit 2) after `keygen` → `sign` → `prove`. `doctor --strict` on the small smoke repo fails unset retention until `init --retention`. Version-range comments include 1.0.17. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, a fingerprint trust store, minisign, GPG/OpenPGP, auto-sign on capture, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.16] — 2026-09-22

### Added

- `keygen [--force] [--json]` writes a local Ed25519 keypair under `.agent-receipt/keys/` using Node `crypto` only (`ed25519.private` PKCS8 PEM mode `0600`, `ed25519.public` SPKI PEM). The key fingerprint is the lowercase hex SHA-256 of the DER SPKI bytes. Existing keys are left unchanged (exit 0). `--force` rotates. No network, no CA, no key escrow. The private key is never printed.
- `sign [path] [--json]` resolves a receipt the same way `verify` does, hash-checks it, and writes `foo.sig.json` beside `foo.md`. The signature is over the UTF-8 bytes of the receipt sha256 hex string (the same hex `verify` uses), not the raw Markdown. The sidecar is `{ alg: "ed25519", version: 1, sha256, fingerprint, signature, publicKey }` with the SPKI PEM embedded so a peer can verify without the local keys directory. Hash failure exits 2 and does not write a sidecar. Missing keys exit 1 and name `keygen`. Capture, wrap, and share do not sign.
- `prove` (and `prove --json`) gains a `signature` object: `{ present, ok, alg, fingerprint, reason }`. A missing sidecar is `present: false`, `ok: null`, and does not change the exit. A valid sidecar that matches the current receipt sha256 is `ok: true`. A present sidecar that is invalid, mismatched, or malformed JSON is `ok: false` and prove exits 2. Human output adds one signature line. `verify` stays hash-only.
- [`docs/signature.schema.json`](docs/signature.schema.json) documents the sidecar. No new npm dependency validates it. Receipt capture omits `.agent-receipt/keys/` and `ed25519.private` / `ed25519.public` paths so a local key is not copied into a receipt.
- `doctor` adds an optional `keys` row: INFO when no keys, PASS with the key fingerprint when the pair is readable, WARN when the pair is incomplete or unreadable. Missing keys do not fail default `doctor` or `doctor --strict`.

### Changed

- Package version bumped to `1.0.16`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) smokes `keygen`, `sign`, and `prove --json` (`signature.ok === true`) after wrap. Unsigned prove still expects `signature.present === false`. Version-range comments include 1.0.16. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This is a thin local Ed25519 attest of the receipt hash. It is not a CA and not PKI. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, auto-sign on capture, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), npm Trusted Publishing (this cut does not publish), and `doctor --strict` always-fail for unset retention (retention stays pressure-gated at 100 receipts or 20 MB).

## [1.0.15] — 2026-09-22

### Added

- Drop-in CI/PR gate polish in examples only (live `.github/workflows/*` was not edited). [`examples/github/action.yml`](examples/github/action.yml) is a composite action to copy to `.github/actions/agent-receipt/`. Optional `install` (default false) runs `npm install -g` from `from` (default `github:pramodreddyboddu/agent-receipt`, pin `#v1.0.15`). Optional `prove` (default false) runs `prove --json` after a green wrap/share gate and fails the step unless `ok` is true, `verified` is true, and `exitCode` is 0. Step outputs: `ok`, `exit-code`, `sha256`, `path`, `gate-json`. The exit rule is unchanged (`exitCode !== 0` or `ok !== true` fails), including the `trailingIgnored` boolean-when-set check. [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) keeps an explicit `--fail-on`, bumps the install pin comment to `v1.0.15`, adds `workflow_call` input `prove` (boolean, default true), runs `prove --json` after a green gate (share proves the latest receipt), and uploads `receipt-gate.json` plus the receipt Markdown with `actions/upload-artifact@v4` (name `agent-receipt-gate`). A missing receipt file does not fail the job.
- [`docs/gate.schema.json`](docs/gate.schema.json) documents the CI `GateReport` object (`command` `capture|wrap|share|verify`, `ok`, `version`, `exitCode` 0|1|2, `verified`, `failedOn`, `failOn`, `redacted`, `uncommitted`, `path`, `jsonPath`, `htmlPath`, `markdownPath`, `tldr`, `sha256`, `risk`, `ignored`, `trailingIgnored`, `reason`). No new npm dependency validates it.
- `init --retention` merges opt-in retention defaults onto `.agent-receipt.yml`: `maxCount: 100` and `maxAgeDays: 30` (the same numbers as the disk-pressure and org-policy tips). A missing file is written like `init` with those keys set. An existing file rewrites only those two keys (`ignore`, `redact`, `failOn`, `outDir`, and comments stay). Re-running when both are already set exits 0 and does not rewrite them. Prints the config path and whether each key was set or unchanged, then suggests `prune --dry-run`. No network.
- Trusted prune. When `.agent-receipt/audit.jsonl` exists, `prune` runs `verifyAuditChain` before deleting. A broken chain exits 1, deletes nothing, and appends no audit line. Dry-run exits 1 as well: the plan may still list candidates, with `ok: false`, `exitCode: 1`, `reason`, `chainOk: false`, and `auditPresent: true`. A missing audit log is unchanged (absence is fine). `prune --force` skips the trust gate and deletes even when the chain is broken.

### Changed

- Package version bumped to `1.0.15`
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) checks that `docs/gate.schema.json` exists and that every required gate key is present on the wrap JSON smoke. Version-range comments include 1.0.15. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- `doctor --strict` retention pressure-gating is unchanged. Unset retention still fails only when `outDir` is under pressure (100 receipts or 20 MB). Always-fail for unset retention stays deferred.
- Still deferred: cryptographic signing / signed receipts (PKI) and any attest or key-management slice (no minisign, GPG, or signing keys in this cut), SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing (this cut does not publish).

## [1.0.14] — 2026-09-22

### Added

- `init --org` (alias `init --policy`) sets org policy on `.agent-receipt.yml`: `redact: true` and `failOn: high`. A missing config is written in the same shape as `init`, with those two keys enabled. An existing file is merged in place: active `redact` / `failOn` lines are rewritten, a commented key is uncommented when no active key exists, and missing keys are appended. `ignore`, `riskAllowlist`, `outDir`, retention keys, and other comments stay. Re-running when the keys are already set exits 0 and does not rewrite them. The command prints the config path and whether each key was set or unchanged, and suggests `doctor --strict`. No network. Full example remains [`examples/org-policy.yml`](examples/org-policy.yml); `init --org` does not copy that file over a local ignore list.

### Changed

- Package version bumped to `1.0.14`
- `doctor --strict` fails unset org policy (`redact: true` and a valid `failOn`) on every `outDir`, including a small or empty one (exit 1). `doctor --json` reports that policy check as `fail`. Default `doctor` is unchanged: unset policy stays INFO and does not change the exit code. A broken audit chain still fails `--strict` always and stays WARN by default. Unset retention stays pressure-gated (100 receipts or 20 MB). A configured limit that would still delete files stays a warning.
- CI examples: [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) pins the install comment to `github:pramodreddyboddu/agent-receipt` (with a `v1.0.14` tag note) and records that the job passes `--fail-on` so a missing config cannot weaken the gate. After a successful wrap or share it checks `trailingIgnored` is a boolean when that field is set. [`examples/github/action.yml`](examples/github/action.yml) documents `trailingIgnored` (`boolean | null`) and keeps the same `exitCode` / `ok` failure rule. [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) proves fail-closed policy: `--strict` fails before `init --org` and passes the policy row after. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Still deferred: cryptographic signing / signed receipts (PKI), SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), npm Trusted Publishing (this cut does not publish), and always-fail unset retention under `doctor --strict` (retention stays pressure-gated). No signing slice in this cut.

## [1.0.13] — 2026-09-22

### Added

- `prove [path]` is a thin prove-this-run report. It resolves the receipt the same way `verify` does, checks the same Markdown hash, and prints path, sha256, verified, trailingIgnored, redacted, risk, TL;DR, agent, uncommitted, and failedOn. The audit link is best-effort and still not a signature: a missing `.agent-receipt/audit.jsonl` is `present: false` with `chainOk: null`; a present log runs `verifyAuditChain` (`chainOk`, event count, reason on break). `matched` is true when any event `path` equals the receipt (repo-relative, the form the log stores). `uncommitted` and `failedOn` prefer the index row, then the companion `.json`. A stored boolean wins. Otherwise `failedOn` is high severity only, the same rule as `history --failed` for older rows. `--json` prints one object (`command: "prove"`). `ok` is true only when `exitCode` is 0. Exit 0 when the hash matches and the log is absent or intact. Exit 2 when verify fails, the chain is broken, or explicit `--fail-on` trips (`failedOn` becomes true even if the hash matches). Exit 1 on a missing receipt or a bad flag. Config `failOn` is not applied.
- `last --json` prints one object (`command: "last"`): `ok`, `version`, `path`, `sha256`, `agent`, `message`, `timestamp`, `failedOn`, `uncommitted`, `tldr`. The index row wins for agent, failedOn, uncommitted, and sha256 when that receipt is listed; otherwise the Markdown glance. No receipt still exits 1. Human `last` is unchanged. `--json` wins over `--path` when both are set.
- CI gate JSON gains `trailingIgnored` (`boolean | null`). `verify --json` sets the boolean (true when content after `## Integrity` was ignored). `wrap` and `share` set it when they verified a body. `capture` and usage errors leave it null.

### Changed

- Package version bumped to `1.0.13`
- `doctor --strict` promotes a broken audit chain from WARN to FAIL (exit 1), including on a small `outDir`. Unset org policy and retention stay pressure-gated. Default `doctor` still warns on a broken chain and does not fail for that row. `doctor --json` reports the audit check as `fail` under `--strict`.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `prove --json` and `last --json` after wrap.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Prove-this-run UX landed in this cut. Still deferred: cryptographic signing / signed receipts (PKI), SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing (this cut does not publish).

## [1.0.12] — 2026-09-22

### Added

- `history --failed` and `ls --failed` keep receipts that failed the gate. An index row with `failedOn` uses that boolean: `true` is kept, and a stored `false` stays out even when the risk summary is high. Rows written before 1.0.12 omit `failedOn` and match when `risk.high > 0` or `risk.maxSeverity` is `high`. A scan (no index) matches when the glance has a high-severity risk row. Medium or low alone does not match. Combines with `--agent`, `--uncommitted`, `--limit`, and `--json`. No matches is exit 0 and an empty listing (`[]` with `--json`). An empty receipt store still errors. `--failed` takes no value.
- New captures store `failedOn: true` or `false` on `.agent-receipt/index.json` (the gate result, computed before the index update). The companion receipt `.json`, when written, carries the same boolean. Older index rows without the field stay valid.
- Human history rows that failed the gate show a `[failed]` badge.
- `history` / `ls` `--json` stays a JSON array. Every row includes `failedOn` (the stored bit when the index has it, otherwise the same boolean the filter uses). Scan-path rows also include `uncommitted` (boolean).

### Changed

- Package version bumped to `1.0.12`
- Known `history` / `ls` flags: `--limit`, `--json`, `--agent`, `--uncommitted`, `--failed`, `--cwd`. Unknown flags still exit 1. `--agent` still requires a name.
- Listing filter order: load receipts (index when present, otherwise scan `outDir`), then `--agent` (if set), then `--uncommitted` (if set), then `--failed` (if set), then `--limit` (newest N of the filtered set).
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `history --failed --json` and `history --agent ci --failed --json`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing / prove-this-run signatures, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing (this cut does not publish).

## [1.0.11] — 2026-09-22

### Added

- `history --agent <name>` and `ls --agent <name>` keep receipts whose `agent` field equals that name (exact string, case-sensitive). Receipts with `agent: null` or a missing agent do not match any `--agent` filter. Combines with `--limit` and `--json`. No matches is exit 0 and an empty listing (`[]` with `--json`), not an error. An empty receipt store still errors, as before.
- `history --uncommitted` and `ls --uncommitted` keep receipts where `uncommitted` is true. Combines with `--agent`, `--limit`, and `--json`. Same empty-result exit.
- Listing filter order: load receipts (index when present, otherwise scan `outDir`), then `--agent` (if set), then `--uncommitted` (if set), then `--limit` (newest N of the filtered set). Human listing stays newest first. `--json` is that same slice.

### Changed

- Package version bumped to `1.0.11`
- `history` / `ls` exit 1 on an unknown flag (for example `--failed` or `--agents`) instead of ignoring it. Known flags: `--limit`, `--json`, `--agent`, `--uncommitted`, `--cwd`. `--agent` requires a name.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `history --agent ci --json` and `history --uncommitted --json`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, a background deleter, live workflow sync, and npm Trusted Publishing (this cut does not publish). `history` does not gain `--failed` in this cut.

## [1.0.10] — 2026-09-22

### Added

- `audit --agent <name>` and `log --agent <name>` keep events whose `agent` field equals that name (exact string, case-sensitive). Events with `agent: null` do not match any `--agent` filter. Combines with `--event`, `--failed`, `--limit`, and `--json` (still a JSON array, oldest first). No matches is exit 0 and an empty listing (`[]` with `--json`), not an error. `--verify` ignores `--agent` and checks the whole chain; a short stderr note says so.
- `audit --failed` and `log --failed` keep events where `failedOn` is true or `exitCode` is not 0. Same combination rules, empty-result exit, and `--verify` behavior as `--agent`.
- Listing filter order: load events, then `--event` (if set), then `--agent` (if set), then `--failed` (if set), then `--limit` (newest N of the filtered set). Human output is newest last. `--json` is that same slice, oldest first.

### Changed

- Package version bumped to `1.0.10`
- `audit` / `log` exit 1 on an unknown flag (for example `--agents`) instead of ignoring it. Known flags: `--limit`, `--json`, `--event`, `--agent`, `--failed`, `--verify`, `--cwd`.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `audit --agent ci --failed`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, a background deleter, live workflow sync, and npm Trusted Publishing (this cut does not publish). `history` does not gain `--agent` in this cut.

## [1.0.9] — 2026-09-22

### Added

- `doctor --json` prints one object on stdout for CI and scripts: `ok` (true when the exit code is 0), `command` (`doctor`), `version`, `exitCode`, `strict`, and `checks` (`id`, `status`, `detail`). Status labels stay `pass` / `fail` / `warn` / `info`. The rows match the human checklist (Environment, then Prod ready). Exit codes are unchanged: 0 when nothing FAILs, 1 on FAIL or a `--strict` pressure failure. Human output stays the default when `--json` is omitted.
- `audit --event <name>` and `log --event <name>` filter the listing to one event: `capture`, `watch`, `wrap`, `share`, `export`, or `prune`. Works with `--limit` and `--json` (still a JSON array, oldest first). An unknown name exits 1. `--event` is listing-only — `audit --verify` ignores it and checks the whole chain.

### Changed

- Package version bumped to `1.0.9`
- [`examples/org-policy.yml`](examples/org-policy.yml) comments point at `doctor --strict` and `doctor --json`. `maxCount` / `maxAgeDays` stay commented; retention remains opt-in.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) smokes `doctor --json` and `audit --event wrap`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, a background deleter, live workflow sync, and npm Trusted Publishing (this cut does not publish).

## [1.0.8] — 2026-09-22

### Added

- `prune` / `retain` append one `.agent-receipt/audit.jsonl` line per receipt actually deleted. Same fields as wrap/share/capture (`path`, `sha256`, `agent`, `redacted`, `verified`, `failedOn`, `exitCode`, `prev`). No diff body and no `--message`. The sibling `.json` is not a second event. `--dry-run` and a run that deletes nothing do not append. `audit --verify` checks the same hash chain.
- `doctor --strict` exits 1 when org policy (`redact` + `failOn`) and/or retention is unset **and** `outDir` is under pressure (100 receipts or 20 MB). Below that threshold those rows stay INFO/WARN. Default `doctor` is unchanged: WARN/INFO do not fail the process. CI `--fail-on` is still the risk gate — `--strict` does not scan diffs.
- `prune --json` rows carry the same identity fields as an audit line (`sha256`, `agent`, `redacted`, `verified`, `failedOn`, `exitCode`) plus `reasons` and `bytes`. The report adds `command`, `version`, `exitCode`, and `audited` (lines appended; 0 on dry-run). `audit --verify --json` includes `command` and `version`.
- Redaction and risk hints for Groq `gsk_` keys and xAI `xai-` keys (long alphanumeric form; hyphenated model names are left alone).

### Changed

- Package version bumped to `1.0.8`

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, and a background deleter. `doctor --strict` does not fail merely because a configured limit would still delete files — that stays a warning until you run `prune`.

## [1.0.7] — 2026-09-22

### Added

- Audit log coverage for `capture`, `watch`, and `export` / `html`. Same line shape as wrap/share (`path`, `sha256`, `agent`, `redacted`, `verified`, `failedOn`, `exitCode`, `prev`). No diff body and no `--message`. `wrap` still records one `wrap` line (not a second capture). `share` still records one `share` line (not a second export). `watch` records one `watch` line per capture. `audit --verify` checks the same hash chain.
- `prune` / `retain` — opt-in deletion of old receipts under `outDir`. Config keys `maxCount` and `maxAgeDays` (integers ≥ 1). Nothing is deleted until a limit is set. `--dry-run` prints the plan and does not rewrite `index.json`. Apply deletes the markdown and its sibling `.json`, then refreshes the index (temp file + rename) and drops rows whose files are already gone. Refuses a repo-root or outside-repo `outDir`, symlinks, and a broken `index.json` (no deletes). Does not touch `audit.jsonl`.
- `doctor` **retention** row: INFO when opt-in is off, WARN on disk pressure (100 receipts or 20 MB with no limit, or a limit that would delete files), FAIL on invalid keys or an unsafe `outDir`. WARN stays non-fatal.
- Redaction and risk hints for OpenAI `sk-` / `sk-proj-`, Anthropic `sk-ant-`, Hugging Face `hf_`, and `Authorization: Bearer` tokens.

### Changed

- Package version bumped to `1.0.7`
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `prune --dry-run --json` and checks that retention stays off.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. `gh auth status` scopes were `gist`, `read:org`, and `repo` — no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, and a background deleter. `prune` does not append audit events.

## [1.0.6] — 2026-09-21

### Added

- `audit` / `log` — append-only `.agent-receipt/audit.jsonl` for `wrap` and `share` (path, sha256, agent, redacted, verified, exit code; no diff body and no `--message`). `prev` is the SHA-256 of the previous line. `audit --verify` exits 0 when the chain matches and 2 when a line was edited. Experimental tamper-evidence, not a signature.
- `doctor` prod checklist rows **policy** (redact + failOn, optional) and **audit** (chain OK / missing / broken). WARN/INFO stay non-fatal.
- Cloud-token redaction and risk hints: GitHub `gho_` / `ghu_` / `ghs_` / `ghr_` (with `ghp_`), GitLab `glpat-`, npm, Google `AIza` / `ya29.`, AWS `ASIA`, Stripe, SendGrid, Slack `xoxc` / `xoxe` / `xapp` / webhook URLs, Azure `AccountKey` / `SharedAccessKey`, and `sig=` query params.
- [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) — pull-request and reusable workflow for `--fail-on` + `--json`. [`examples/github/action.yml`](examples/github/action.yml) — composite action.
- Enterprise section in [`docs/business.md`](docs/business.md): SSO-free rollout, org policy, CI gate, share defaults, audit, retention for `.agent-receipt/`.

### Fixed

- SessionEnd / `scripts/grok-wrap.sh`: prefer `node` for a multi-chunk drain; skip `timeout` when it rejects the wait value (BusyBox fractional seconds). After the drain, stdin is redirected from `/dev/null` so a host blocked on a full write gets `EPIPE` instead of stalling wrap.

### Changed

- Package version bumped to `1.0.6`
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) runs a temp-repo `wrap --json` and `share --json` smoke plus `audit --verify`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The `gh` token scopes were `gist`, `read:org`, and `repo` — no `workflow` scope — and GitHub rejects workflow-file pushes without it. Install the mirror after `gh auth refresh -h github.com -s workflow` (fine-grained PAT: Actions Read and write). See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO, Cloud Agents, automatic receipt deletion, and audit events for capture / watch / export.

## [1.0.5] — 2026-09-21

### Added

- `share` — one shot: verify the source, apply `--redact` (default on; 1.0.3 share-safety), write HTML and optional Markdown (`--md`), verify the published body, print paths + TL;DR. Refuses to overwrite the source and does not re-hash a tampered receipt.
- CI gate JSON on stdout for `capture --json`, `wrap --json`, `share --json`, and `verify --json` (human progress on stderr). Companion receipt `.json` is unchanged. `watch --json` stays companion-file + human stdout.
- Stable `--fail-on` exits: 0 pass, 2 policy and/or verify failure, 1 usage error (invalid threshold). Config `failOn` / `redact` (see `examples/org-policy.yml`) apply to capture / wrap / watch / share. Plain `verify` ignores config `failOn` unless `--fail-on` is passed.
- `doctor` **Prod ready** checklist: hooks, redact default (optional), config, git clean, Cursor init, Grok init. WARN/INFO stay non-fatal.
- [`docs/business.md`](docs/business.md) — team rollout: install, hooks, CI gate, share-safety, SessionEnd stdin contract, what not to put in receipts.
- SessionEnd / `scripts/grok-wrap.sh` stdin drain: at most one read of `HOOK_STDIN_MAX` bytes, capped by `HOOK_STDIN_WAIT_SEC` (`timeout`, else `node`). An open pipe with no EOF cannot hang the hook. Payload is discarded.

### Changed

- Package version bumped to `1.0.5`
- `capture --json` / `wrap --json` stdout is the gate object (logs moved to stderr). Scripts that scraped “Wrote receipt” from stdout of `--json` should read stderr or the gate fields.

## [1.0.4] — 2026-09-21

### Added

- `init --grok` — writes `.grok/rules/agent-receipt.md` (Grok Build loads it every session) and a SessionEnd hook (`.grok/hooks/agent-receipt.json` + `agent-receipt-wrap.sh`) that runs `wrap --agent grok --redact --uncommitted` **only when the working tree is dirty** (non-blocking; needs `grok --trust` / `/hooks-trust`)
- [`docs/grok-cli.md`](docs/grok-cli.md) — post-session recipe for the Grok Build CLI
- `scripts/grok-wrap.sh` and npm script `wrap:grok` — `wrap --agent grok --redact` (does not force `--uncommitted`; a dirty tree is captured automatically)
- Example copies under `examples/.grok/`

### Changed

- Package version bumped to `1.0.4`
- Promote CI to `.github/workflows/ci.yml` (docs mirror retained under `docs/github-actions-ci.yml`)
- Add OIDC Trusted Publishing release workflow (`.github/workflows/release.yml`) — no long-lived `NPM_TOKEN`
- Document Trusted Publisher + GitHub Environment setup in `docs/RELEASE.md`
- Harden `npm run pack:check` against npm 11 `./bin/...` publish footgun (bin already canonical on 1.0.2)

## [1.0.3] — 2026-09-13

### Fixed

- **`--redact`**: mask credential URLs (`DATABASE_URL`, `postgres://user:pass@…`,
  Redis/Mongo URIs, `password=` query params) — passwords no longer leak while
  API/AWS keys were masked
- **`--redact`**: omit nested prior-receipt / `.agent-receipt` index diff bodies so
  truncated secrets from earlier receipts cannot re-embed
- **Risk**: skip high-entropy false positives on `.agent-receipt/` artifact paths
  and pure hex digests (sha1/sha256 footers)
- **History / index**: captures with `--out` outside configured `outDir` are no
  longer prepended as newest in `.agent-receipt/index.json`

### Changed

- Package version bumped to `1.0.3`
- Document that trailing appends after `## Integrity` are ignored by `verify`
  (canonical-body design); `verify` prints a brief note when such content exists


## 1.0.2

- Republish after 1.0.1 version was reserved/yanked on npm (installs 404'd; same version cannot be restaged).
- Keep scoped name `@pramodreddyboddu/agent-receipt`.

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
