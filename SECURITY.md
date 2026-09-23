# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | Best-effort only |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

1. Email the maintainer (see GitHub profile / commit author for `pramodreddyboddu`) **or**
2. Open a [private security advisory](https://github.com/pramodreddyboddu/agent-receipt/security/advisories/new) on this repository if available.

Include:

- Affected version / commit
- Steps to reproduce
- Impact (e.g. integrity bypass, unexpected file overwrite, path traversal)

You should hear back within a few days. Coordinated disclosure is preferred.

## What this tool is (and is not)

`agent-receipt` produces **tamper-evident** Markdown/HTML receipts (SHA-256 of the
canonical body). Default `verify` recomputes that hash and stays hash-only.
`verify --require-sig` (1.0.17) additionally requires a valid `*.sig.json`.
When a fingerprint trust store is configured (1.0.18), that check also
requires the sidecar fingerprint to be on the known-keys allowlist.
`audit` adds an experimental hash chain over capture, watch, wrap, share,
export, and prune-delete events (`.agent-receipt/audit.jsonl`). That chain
is not a signature.

`keygen` / `sign` (1.0.16) add a **thin local Ed25519 attest** of the receipt
sha256 hex. The sidecar (`foo.sig.json`) carries the signature and the SPKI
public key. The private key is PKCS8 PEM mode `0600` under
`.agent-receipt/keys/` and is never written into a receipt or sidecar.
There is no CA, no PKI, and no key escrow. A thin fingerprint trust store
(known-keys allowlist) is opt-in: `.agent-receipt/trusted-keys.txt` and/or
`trustedFingerprints` in `.agent-receipt.yml`. Empty or missing both leaves
the allowlist inactive, so any cryptographically valid sidecar still passes
`verify --require-sig`. A non-empty store requires that fingerprint.
`trust add --self` appends the local keygen fingerprint to that file. It
does not create keys and it is not a CA. This
is not a certificate chain and not a revocation list. There is no default
auto-sign on capture. `capture --sign` and `wrap --sign` are opt-in and
leave the receipt unsigned when keys are missing. `prove` reports the
sidecar when it is present (`trusted` is null when the allowlist is
inactive). A missing sidecar does not fail default `verify` or `prove`.
It does fail `verify --require-sig`. `share` and Markdown `export` copy a
matching sidecar or re-sign the published Markdown when local keys exist.
They do not attach a stale sidecar, and they do not sign HTML.

It is **not**:

- A certificate authority or a PKI product (no minisign, GPG, or OpenPGP)
- A substitute for `gitleaks`, secret scanning CI, or code review
- A guarantee that a session was safe to ship

### Heuristic scanner limits

The built-in **risk** engine is a **heuristic** diff/path scanner. It looks for
high-signal patterns (e.g. AWS key ids, private key PEM blocks, `.env` commits,
high-entropy tokens) to surface review hints.

It will:

- **Miss** novel or obfuscated secrets (false negatives)
- **Flag** benign lookalikes (false positives)
- **Not** replace dedicated secret scanners or human review

Use `--fail-on` / CI as a **tripwire**, not as your only control. Prefer
`share` (redact is on unless `--no-redact`) or `--redact` when sharing receipts
outside a trusted channel (masks credential URLs / DB passwords, common cloud
tokens such as GitHub `gho_`/`ghs_`, GitLab `glpat-`, Google, npm, Stripe,
SendGrid, Slack, Azure `AccountKey`, OpenAI `sk-` / Anthropic `sk-ant-`,
Hugging Face `hf_`, Groq `gsk_`, xAI `xai-`, and `Authorization: Bearer`, and
omits nested prior-receipt bodies). Redaction is not a DLP guarantee. `prune`
deletes receipt files only when you set `maxCount` / `maxAgeDays` and run it
(default is keep everything) and then appends one audit line per receipt
deleted (`--dry-run` does not). Trusted prune refuses that delete when
`.agent-receipt/audit.jsonl` exists and the hash chain is broken
(`prune --force` is break-glass). `init --retention` sets the two limits.
See [`docs/business.md`](docs/business.md) for what not to put in receipts.

## Supply chain

- Prefer installing from npm once published, or a pinned GitHub ref
- Review `files` allowlist in `package.json` before `npm publish`
- Never commit `.npmrc` tokens or real production receipts with live secrets
