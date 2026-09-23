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
canonical body). `audit` adds an experimental hash chain over capture, watch,
wrap, share, export, and prune-delete events (`.agent-receipt/audit.jsonl`). It is **not**:

- Cryptographic signing (no keys, no PKI, including the audit log)
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
