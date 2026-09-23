# Signed CI gate

A job can require an Ed25519 sidecar and a known fingerprint. This is not a CA, not key escrow, and not an org secret. The private key stays under `.agent-receipt/keys/` (gitignored) or is created for that job and thrown away with the runner.

## Recommended path

```bash
agent-receipt keygen
# or restore .agent-receipt/keys before the step

# one lowercase 64-hex fingerprint per line
printf '%s\n' "<fingerprint>" > .agent-receipt/trusted-keys.txt

agent-receipt wrap --sign --fail-on high --json
agent-receipt prove --json
agent-receipt verify --require-sig
```

Expect `prove` `signature.ok === true`. With that allowlist, also expect `signature.trusted === true`, and `verify --require-sig` exit 0.

`trusted-keys` may be a file path or comma-separated fingerprints. Empty leaves the allowlist inactive: a valid sidecar still passes `--require-sig`, and `signature.trusted` stays null.

CLI `wrap --sign` with missing keys prints a `keygen` tip and leaves the receipt unsigned. That does not exit 2. The CI input `sign: true` fails the step instead and names `keygen`. A request to sign should not ship an unsigned receipt.

## Drop-in

| File | What it does |
|------|----------------|
| [`examples/github/action.yml`](../examples/github/action.yml) | Composite action. `sign: true` passes `--sign` to `wrap` and fails closed without keys. `trusted-keys` is installed before wrap, sign, prove, and verify. `require-sig: true` runs `verify --require-sig` on the gate path. |
| [`examples/github/pr-gate.yml`](../examples/github/pr-gate.yml) | Workflow to copy. `require-sig: true` temp-`keygen`s (no org secret). When `trusted-keys` is empty, the job writes that fingerprint into `.agent-receipt/trusted-keys.txt` so `signature.trusted` is true. A non-empty `trusted-keys` value is installed as given. |

Recommended action inputs, after `keygen` or a restored keypair:

```yaml
sign: true
require-sig: true
trusted-keys: "<path-or-comma-fps>"
```

`share` re-signs published Markdown when local keys exist. It has no `--sign` flag. The examples run `sign` on the gate receipt path when `sign: true` and that path has no sidecar. HTML stays unsigned.

Pin comments are `v1.0.19` (`github:pramodreddyboddu/agent-receipt#v1.0.19` once the tag exists).

## Live workflows

This repo does not install the example under [`.github/workflows/`](../.github/workflows). Pushing that tree needs the OAuth `workflow` scope. Copy the example in your own repo. The smoke that runs `wrap --sign` lives in [`docs/github-actions-ci.yml`](github-actions-ci.yml).

Still deferred: full PKI/CA, minisign, GPG/OpenPGP, a config `sign: true` default, `trust add --self`, an HTML/share signed package, a background deleter, and a prove-for-humans one-pager.
