# Contributing

Thanks for helping improve `agent-receipt`.

## Setup

1. Fork and clone the repo (or work on a branch).
2. `npm install`
3. `npm test`

## Guidelines

- Keep dependencies minimal (stdlib-first).
- Prefer small, focused PRs with tests for new behavior.
- Match existing TypeScript ESM style (`NodeNext`).
- Do not commit secrets, `.env`, or real production receipts with sensitive diffs.
- Keep `src/lib/version.ts` in sync with `package.json` version.

## Release checklist

- Bump `version` in `package.json` **and** `src/lib/version.ts`
- Update `CHANGELOG.md`
- `npm test`
- Tag and publish (maintainers) — do not publish unless explicitly requested

## CI workflow

The intended GitHub Actions workflow is [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)
(Node 20/22, `npm test`, `pack:check`, and a temp-repo `wrap --json` /
`share --json` smoke).

The live file is `.github/workflows/ci.yml`. Updating it requires the OAuth
**`workflow`** scope in addition to `repo`:

```bash
gh auth refresh -h github.com -s workflow
gh auth status   # Token scopes must include workflow
cp docs/github-actions-ci.yml .github/workflows/ci.yml
```

`gh auth status` on the tokens used for the 1.0.6 through 1.0.12 cuts listed
`gist`, `read:org`, and `repo` only, so that live file was not modified.
GitHub rejects the push
with: refusing to allow an OAuth App to create or update workflow
`.github/workflows/ci.yml` without `workflow` scope.

Fine-grained PATs need **Actions: Read and write**. GitHub Apps need the
**Workflows** permission. Do not force-push.
