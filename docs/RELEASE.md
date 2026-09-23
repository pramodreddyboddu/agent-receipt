# Release checklist (agent-receipt)

Do **not** publish or flip the GitHub repo to public until you intentionally
want a public release. This checklist is the playbook when you are ready.

## Preflight

- [ ] `npm test` green locally — **automated** (`npm test` / CI)
- [ ] `node bin/agent-receipt.js doctor` clean (or only expected WARNs) in a sample repo
- [ ] Version bump consistent across:
  - [ ] `package.json` → `"version"` + scoped name `@pramodreddyboddu/agent-receipt`
  - [ ] `src/lib/version.ts` → `VERSION`
  - [ ] Integrity docs note: trailing appends after `## Integrity` ignored by verify
  - [ ] `CHANGELOG.md` → dated section
- [ ] `npm run pack:check` — **automated** (`npm pack --dry-run` asserts `bin` + `dist`, and bin path has no leading `./`)
- [ ] README 60-second path still works from a fresh clone / GitHub install
- [ ] `docs/receipt.schema.json` matches current `--json` shape
- [ ] Example receipt under `examples/` still looks sane (`verify` on it optional)

## CI workflow

Canonical workflow: **`.github/workflows/ci.yml`**

Docs mirrors (fallback if OAuth lacks `workflow` scope):

- `docs/github-actions-ci.yml` → copy to `.github/workflows/ci.yml`
- `docs/github-actions-release.yml` → copy to `.github/workflows/release.yml`

Exact scope to update the live workflow: OAuth **`workflow`** (plus `repo`).

```bash
gh auth refresh -h github.com -s workflow
```

Fine-grained PAT: **Actions: Read and write**. GitHub App: **Workflows**.
A token whose `gh auth status` scopes are only `gist`, `read:org`, `repo`
cannot push `.github/workflows/*`. v1.0.6 through v1.0.13 left
`.github/workflows/ci.yml` unchanged for that reason; the docs mirror has
the `share --json` smoke, `prove --json`, `last --json`, a `prune --dry-run`
check, `doctor --strict`, `doctor --json`, `audit --event wrap`,
`audit --agent ci --failed`, and `history --agent ci` /
`history --uncommitted` / `history --failed`.

```bash
mkdir -p .github/workflows
cp docs/github-actions-ci.yml .github/workflows/ci.yml
cp docs/github-actions-release.yml .github/workflows/release.yml
git add .github/workflows/
git commit -m "ci: enable GitHub Actions workflows"
git push
```

## npm Trusted Publishing (OIDC) — preferred

Prefer **Trusted Publishing** over long-lived `NPM_TOKEN` secrets. The release
workflow (`.github/workflows/release.yml`) publishes with OIDC; no npm token is
stored in GitHub Actions secrets.

### 1. Create GitHub Environment `npm-publish`

1. GitHub → **Settings** → **Environments** → **New environment**
2. Name it exactly: `npm-publish` (must match `environment:` in `release.yml`)
3. Optional but recommended:
   - Required reviewers (you) before deploy
   - Deployment branches / tags: restrict to tags matching `v*` if available

### 2. Configure Trusted Publisher on npmjs.com

1. Open https://www.npmjs.com/package/@pramodreddyboddu/agent-receipt → **Settings**
2. Find **Trusted Publisher** → choose **GitHub Actions**
3. Fill in **exactly** (case-sensitive):

   | Field | Value |
   | --- | --- |
   | Organization or user | `pramodreddyboddu` |
   | Repository | `agent-receipt` |
   | Workflow filename | `release.yml` (filename only, not a path) |
   | Environment name | `npm-publish` |

4. Allowed actions: allow **`npm publish`** (and/or staged publish if you prefer review-then-approve)
5. Save. npm does **not** verify the config until the first publish attempt.

Requirements (as of npm Trusted Publishing GA):

- npm CLI **≥ 11.5.1**
- Node **≥ 22.14.0** on the runner (the workflow pins `22.14` and upgrades npm)
- Workflow permission: `id-token: write`
- GitHub-hosted runners (self-hosted not supported for OIDC publish today)

### 3. Publish via tag (automated)

```bash
# on a clean main tip matching the intended release
git checkout main && git pull
# ensure version / CHANGELOG / version.ts already bumped on main
git tag -a v1.0.6 -m "agent-receipt v1.0.6"
git push origin v1.0.6
# Release workflow runs: test → pack:check → npm publish --access public (OIDC)
gh release create v1.0.6 --title "v1.0.6" --notes-file CHANGELOG.md
```

Or run **Actions → Release → Run workflow** (`workflow_dispatch`) after Trusted Publisher is configured.

### 4. After Trusted Publishing works — harden token policy

1. npm package **Settings** → **Publishing access**
2. Select **Require two-factor authentication and disallow tokens**
3. Revoke any leftover automation / classic publish tokens

Trusted Publishing continues to work; only traditional tokens are blocked.

### Troubleshooting OIDC publish

- **ENEEDAUTH / Unable to authenticate**: workflow filename mismatch (`release.yml`), wrong owner/repo case, missing `id-token: write`, or Environment name mismatch (`npm-publish`).
- **Empty `_authToken` in `.npmrc`**: do **not** set `NODE_AUTH_TOKEN` / `NPM_TOKEN` on the publish step. If `actions/setup-node` wrote an empty token line, remove it before `npm publish` or upgrade setup-node.
- Provenance is automatic for public repos using Trusted Publishing (no `--provenance` flag needed).

## Manual npm publish (fallback — not for CI agents)

Only if Trusted Publishing is not configured yet:

```bash
npm login
npm whoami
npm run pack:check
npm publish --access public
```

Notes:

- Package name is scoped: `@pramodreddyboddu/agent-receipt` (unscoped `agent-receipt` is taken)
- CLI binary remains `agent-receipt`
- **`bin` path must not use a leading `./`** — use `"bin/agent-receipt.js"`. npm 11 treats `./bin/...` as invalid at publish time and may strip the bin (`npm warn publish "bin[agent-receipt]" ... was invalid and removed` / cleaned). `npm run pack:check` guards this.
- `prepublishOnly` runs `npm test`
- `files` allowlist in `package.json` controls the tarball (`bin`, `dist`, `docs`, `examples`, `SECURITY.md`, …)
- `publishConfig.access` is `public` (required for scoped packages)
- After publish: `npm view @pramodreddyboddu/agent-receipt version`

## GitHub install (works before npm publish)

```bash
npm i -g github:pramodreddyboddu/agent-receipt
# or a branch/ref:
npm i -g github:pramodreddyboddu/agent-receipt#v1.0.6
```

## Post-release smoke

```bash
npm i -g @pramodreddyboddu/agent-receipt@latest
cd $(mktemp -d) && git init
echo hi > README.md && git add . && git commit -m init
agent-receipt init
agent-receipt install-hooks
agent-receipt doctor
echo bye >> README.md && git add . && git commit -m tweak
agent-receipt wrap --agent demo --message "smoke"
agent-receipt share --json
agent-receipt audit --verify
agent-receipt last
agent-receipt history
agent-receipt verify
agent-receipt compare   # after a second capture
agent-receipt capture --fail-on high || true
agent-receipt --version
```

## Do not

- Publish from a dirty working tree
- Force-push release tags
- Commit secrets / `.npmrc` tokens / long-lived `NPM_TOKEN` for publish once OIDC works
- Flip visibility / publish as part of an automated agent task unless explicitly asked
