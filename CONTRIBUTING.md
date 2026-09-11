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

## Release checklist

- Bump `version` in `package.json`
- Update `CHANGELOG.md`
- `npm test`
- Tag and publish (maintainers)

## CI workflow

The GitHub Actions workflow lives at [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml).
Copy it to `.github/workflows/ci.yml` with a token that has the `workflow` scope
(or via the GitHub UI), then commit.
