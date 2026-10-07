# GitHub Action

`action.yml` at the repository root is a composite action. One `uses:` line
checks agent receipts on a pull request and posts a summary comment. It
installs an exact version with `npx` (`@pramodreddyboddu/agent-receipt@1.0.39`
by default). `latest` is rejected. The token is passed only as `GITHUB_TOKEN`
and is never printed.

The snippets below are documentation. They are not installed under
[`.github/workflows/`](../.github/workflows).

The copy-in recipe at [`examples/github/action.yml`](../examples/github/action.yml)
is a different, older drop-in (`wrap` / `share` in your own workflow). This
page is the published action.

`pr-comment` is the command the action runs. `--dry-run` prints the summary.
`--comment off` skips the GitHub API. HTTP 403 and 404 (a fork pull request
with a read-only token is the usual 403) write the same Markdown to the job
summary and do not change the gate exit code. A network error does the same.

## Basic gate

`gate` verifies every receipt in the store and fails on high risk. The
comment is updated in place (`<!-- agent-receipt:summary -->`).

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: pramodreddyboddu/agent-receipt@v1
    with:
      command: gate
      fail-on: high
      comment: on
```

`pull-requests: write` is what lets the token post the comment. `contents: read`
is enough to read the checkout.

## Policy and fail-on

`--fail-on` on the step wins. Otherwise `failOn` in the policy file is used.
`gate` with neither still fails on high. `requireSignature: true` in the
policy is the same as `require-signature: true`.

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: pramodreddyboddu/agent-receipt@v1
    with:
      command: gate
      fail-on: medium
      policy: examples/org-policy.yml
      receipts: .agent-receipt/receipts/*.md
      comment: on-failure
      comment-mode: update
```

`comment: on-failure` posts only when the verdict is fail. The job summary
still receives the Markdown. `comment-mode: create` posts a new comment
every run instead of updating the sticky one.

`policy-pack` is a comma-separated list of `builtin:<name>` refs or file
paths. Deny hits fail the step (exit 2). Warn hits stay in the comment.
An empty value skips packs. A missing or invalid pack fails closed (exit 1).

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: pramodreddyboddu/agent-receipt@v1
    with:
      command: gate
      fail-on: high
      policy-pack: builtin:baseline,builtin:supply-chain
      comment: on
```

## Signed and keyless verify

`command: verify` with `require-signature: true` is the Ed25519 sidecar
check. `command: attest-verify` passes the identity and issuer through to
`attest --verify`. A Sigstore bundle needs exactly one of
`certificate-identity` or `certificate-identity-regexp`, plus
`certificate-oidc-issuer`. Missing either fails closed (exit 1).

Keyless signing in the same job needs `id-token: write`. Verifying a bundle
is offline and does not need that permission. Posting the comment needs
`pull-requests: write`.

```yaml
permissions:
  contents: read
  id-token: write
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: pramodreddyboddu/agent-receipt@v1
    with:
      command: attest-verify
      receipts: .agent-receipt/receipts/*.sigstore.json
      certificate-identity: https://github.com/ORG/REPO/.github/workflows/ci.yml@refs/heads/main
      certificate-oidc-issuer: https://token.actions.githubusercontent.com
      comment: on
```

Use the workflow's own subject. An identity that does not match the
certificate fails the gate (exit 2). See [`docs/keyless.md`](keyless.md).

Local Ed25519 gate (not keyless, not a CA):

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: pramodreddyboddu/agent-receipt@v1
    with:
      command: verify
      require-signature: true
      fail-on: high
      comment: on
```

## Outputs

| Output | Meaning |
|--------|---------|
| `verdict` | `pass` or `fail` |
| `risk` | `high`, `medium`, `low`, or `none` |
| `receipts-count` | Files checked |
| `summary-path` | Markdown summary file |
| `comment-url` | Comment URL, empty when nothing was posted |

The step exits non-zero when the gate fails. Invalid inputs (a version that
is not `x.y.z`, an unknown command, a bad `fail-on`) exit 1 before `npx`.

## Marketplace checklist

Do this when cutting a release. This repository does not create the tag or
the Marketplace listing from CI.

1. Land the change on `main`. The root `action.yml` must be on that commit.
2. Tag the release `v1.0.39` (the same version as `package.json`). Push the tag. Do not force-push.
3. Move the major tag `v1` to that commit so `uses: pramodreddyboddu/agent-receipt@v1` stays current. Push `v1`.
4. Open the GitHub release for `v1.0.39`. Marketplace reads `action.yml` from the tag (`name`, `description`, `branding.icon`, `branding.color`).
5. Publish the listing from the release page. The icon is `shield` and the color is `blue`.
6. Confirm a pull request in a throwaway repo with `permissions: pull-requests: write` posts one comment, and a second run updates that comment instead of adding another.

Pin consumers to `@v1` or to `@v1.0.39`. Do not point them at a branch.
