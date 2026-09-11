# Release checklist (agent-receipt)

Do **not** publish or flip the GitHub repo to public until you intentionally
want a public release. This checklist is the playbook when you are ready.

## Preflight

- [x] `npm test` green locally — **automated** (`npm test` / CI)
- [ ] `node bin/agent-receipt.js doctor` clean (or only expected WARNs) in a sample repo
- [x] Version bump consistent across — **automated on this release branch**:
  - [x] `package.json` → `"version"` (`1.0.0`)
  - [x] `src/lib/version.ts` → `VERSION`
  - [x] `CHANGELOG.md` → dated `1.0.0` section
- [x] `npm run pack:check` — **automated** (`npm pack --dry-run` asserts `bin` + `dist`)
- [ ] README 60-second path still works from a fresh clone / GitHub install
- [ ] `docs/receipt.schema.json` matches current `--json` shape
- [ ] Example receipt under `examples/` still looks sane (`verify` on it optional)

## Make the GitHub repo public (optional, manual)

1. GitHub → Settings → Danger Zone → Change repository visibility → Public
2. Confirm README / LICENSE / SECURITY expectations
3. (Optional) Add topics: `cli`, `git`, `ai-agents`, `audit`, `tamper-evident`

## npm publish (optional, manual — do NOT run from CI agents blindly)

```bash
# from a clean main tip matching the release tag
npm login
npm whoami
npm run pack:check   # or: npm pack --dry-run
npm publish --access public
```

Notes:

- `prepublishOnly` runs `npm test`
- `files` allowlist in `package.json` controls the tarball (`bin`, `dist`, `docs`, `examples`, `SECURITY.md`, …)
- `publishConfig.access` is `public` (scoped packages would need it; harmless for unscoped)
- After publish: `npm view agent-receipt version`

## GitHub install (works before npm publish)

```bash
npm i -g github:pramodreddyboddu/agent-receipt
# or a branch/ref:
npm i -g github:pramodreddyboddu/agent-receipt#v1.0.0
```

## Tag + GitHub Release (v1.0.0)

After this PR is merged to `main` (Release QA gates):

```bash
git checkout main
git pull
git tag -a v1.0.0 -m "agent-receipt v1.0.0"
git push origin v1.0.0
gh release create v1.0.0 --title "v1.0.0" --notes-file CHANGELOG.md
```

## CI workflow

If the GitHub OAuth token lacks the `workflow` scope, keep the workflow under
`docs/github-actions-ci.yml` and copy it into `.github/workflows/ci.yml`
manually (or with a PAT that has workflow scope):

```bash
mkdir -p .github/workflows
cp docs/github-actions-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: enable GitHub Actions"
git push
```

On the v1.0.0 publish-ready branch we attempt to add `.github/workflows/ci.yml`;
if push/PR is rejected for workflow scope, leave docs-only and note it on the PR.

## Post-release smoke

```bash
npm i -g agent-receipt@1.0.0   # or github:…#v1.0.0
cd $(mktemp -d) && git init
echo hi > README.md && git add . && git commit -m init
agent-receipt init
agent-receipt install-hooks
agent-receipt doctor
echo bye >> README.md && git add . && git commit -m tweak
agent-receipt wrap --agent demo --message "smoke"
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
- Commit secrets / `.npmrc` tokens
- Flip visibility / publish as part of an automated agent task unless explicitly asked
