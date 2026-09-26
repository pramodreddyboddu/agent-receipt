# Signed CI gate

A job can require an Ed25519 sidecar and a known fingerprint. This is not a CA, not key escrow, and not an org secret. The private key stays under `.agent-receipt/keys/` (gitignored) or is created for that job and thrown away with the runner.

## Recommended path

```bash
agent-receipt keygen
# or restore .agent-receipt/keys before the step
agent-receipt trust add --self
agent-receipt trust show

agent-receipt wrap --sign --fail-on high --json
agent-receipt prove --json
agent-receipt prove --page
agent-receipt verify --require-sig
```

Expect `prove` `signature.ok === true`. With that allowlist, also expect `signature.trusted === true`, and `verify --require-sig` exit 0.

`trust show` (alias `trust status`) reports the allowlist and whether the local key is listed (`localListed`). It is read-only: it does not create keys and it does not edit the allowlist. After `keygen` and `trust add --self`, `localListed` is true. Missing keys stay exit 0.

`prove --page` writes a plain-English one-pager next to the receipt (`foo.md` → `foo.prove.md`) so a human can read the verdict without the full receipt or the JSON. It does not change the exit code. The page is not signed.

`trusted-keys` may be a file path or comma-separated fingerprints. Empty leaves the allowlist inactive: a valid sidecar still passes `--require-sig`, and `signature.trusted` stays null.

CLI `wrap --sign` with missing keys prints a `keygen` tip and leaves the receipt unsigned. That does not exit 2. The same tip applies when config `sign: true` asks capture, wrap, or watch to sign and the keys are missing. CLI `--no-sign` overrides that config for one run. `init --org` does not set `sign`. The CI input `sign: true` fails the step instead and names `keygen`. That input is independent of config `sign` and stays fail-closed. A request to sign in CI should not ship an unsigned receipt.

## Drop-in

| File | What it does |
|------|----------------|
| [`examples/github/action.yml`](../examples/github/action.yml) | Composite action. `sign: true` passes `--sign` to `wrap` and fails closed without keys. `trusted-keys` is installed before wrap, sign, prove, and verify. `require-sig: true` runs `verify --require-sig` on the gate path. |
| [`examples/github/pr-gate.yml`](../examples/github/pr-gate.yml) | Workflow to copy. `require-sig: true` temp-`keygen`s (no org secret). When `trusted-keys` is empty, the job runs `agent-receipt trust add --self` so `signature.trusted` is true. A non-empty `trusted-keys` value is installed as given. |

Recommended action inputs, after `keygen` or a restored keypair:

```yaml
sign: true
require-sig: true
trusted-keys: "<path-or-comma-fps>"
```

`share` re-signs published Markdown when local keys exist. It has no `--sign` flag. The examples run `sign` on the gate receipt path when `sign: true` and that path has no sidecar. HTML stays unsigned.

`share --package` (alias `--pack`) ships the HTML and the Markdown together in `foo.share/` (`receipt.html`, `receipt.md`, optional `receipt.sig.json`, `manifest.json`). Peers open the HTML and run `verify --package` on that directory (manifest, file hashes, `receipt.md`, optional signatures). `verify` or `verify --require-sig` on `receipt.md` still works. `import` copies the proved Markdown into the local store after the same check. Optional `manifest.sig.json` is written when local keys load. The HTML body stays unsigned.

Pin comments are `v1.0.26` (`github:pramodreddyboddu/agent-receipt#v1.0.26` once the tag exists). After `keygen`, `trust add --self` allowlists that fingerprint. `trust show` reports that allowlist and whether the local key is listed. A laptop or org config may also set `sign: true` so bare `wrap` signs; CLI `--no-sign` overrides. `autoPrune: true` plus `maxCount` or `maxAgeDays` deletes older receipts after a successful capture, wrap, or watch (same trusted prune, no `--force`). A broken audit chain skips that delete and does not fail the capture. `--no-prune` turns it off for one run. `init --retention` does not enable `autoPrune`. Not a CA. Not a daemon.

## Live workflows

This repo does not install the example under [`.github/workflows/`](../.github/workflows). Pushing that tree needs the OAuth `workflow` scope. Copy the example in your own repo. The smoke that runs `wrap --sign` lives in [`docs/github-actions-ci.yml`](github-actions-ci.yml).

`prove --page` landed in 1.0.21 (unsigned Markdown one-pager). Config `sign: true` / `--no-sign` landed in 1.0.22 (capture, wrap, and watch; missing keys tip and stay unsigned). `trust show` landed in 1.0.23 (read-only allowlist status, including whether the local key is listed). `share --package` landed in 1.0.24 (HTML + Markdown + optional receipt sidecar + manifest in one directory; HTML body unsigned). `verify --package` and `import` landed in 1.0.25 (peer check of that directory, then an optional copy of the proved Markdown). Auto-prune landed in 1.0.26 (config `autoPrune: true` or `--prune` after capture, wrap, and watch when a retention limit is set; a broken chain skips the delete and does not fail the capture). Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a signed one-pager, unsigned HTML prove export (`prove --html`), a long-running prune daemon or cron, and multi-agent receipt linking. `trust add --self` is a local allowlist write, not a CA.
