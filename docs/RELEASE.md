# Release checklist (agent-receipt)

Do **not** publish or flip the GitHub repo to public until you intentionally
want a public release. This checklist is the playbook when you are ready.

## Preflight

- [ ] `npm test` green locally
- [ ] `node bin/agent-receipt.js doctor` clean (or only expected WARNs) in a sample repo
- [ ] Version bump consistent across:
  - [ ] `package.json` → `"version"`
  - [ ] `src/lib/version.ts` → `VERSION`
  - [ ] `CHANGELOG.md` → new section with date
- [ ] README 30-second path still works from a fresh clone / GitHub install
- [ ] `docs/receipt.schema.json` matches current `--json` shape
- [ ] Example receipt under `examples/` still looks sane

## Make the GitHub repo public (optional, manual)

1. GitHub → Settings → Danger Zone → Change repository visibility → Public
2. Confirm README / LICENSE / SECURITY expectations
3. (Optional) Add topics: `cli`, `git`, `ai-agents`, `audit`

## npm publish (optional, manual — do NOT run from CI agents blindly)

```bash
# from a clean main tip matching the release tag
npm login
npm whoami
npm pack --dry-run   # inspect tarball contents
npm publish --access public
```

Notes:

- `prepublishOnly` runs `npm test`
- `files` allowlist in `package.json` controls the tarball (`bin`, `dist`, `docs`, `examples`, …)
- After publish: `npm view agent-receipt version`

## GitHub install (works before npm publish)

```bash
npm i -g github:pramodreddyboddu/agent-receipt
# or a branch/ref:
npm i -g github:pramodreddyboddu/agent-receipt#v0.3.0
```

## Tag + GitHub Release

```bash
git checkout main
git pull
git tag -a v0.3.0 -m "agent-receipt v0.3.0"
git push origin v0.3.0
gh release create v0.3.0 --title "v0.3.0" --notes-file CHANGELOG.md
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

## Post-release smoke

```bash
npm i -g agent-receipt@0.3.0   # or github:…#v0.3.0
cd $(mktemp -d) && git init
echo hi > README.md && git add . && git commit -m init
agent-receipt init
agent-receipt install-hooks
agent-receipt doctor
echo bye >> README.md && git add . && git commit -m tweak
agent-receipt last
agent-receipt verify
agent-receipt compare   # after a second capture
```

## Do not

- Publish from a dirty working tree
- Force-push release tags
- Commit secrets / `.npmrc` tokens
- Flip visibility / publish as part of an automated agent task unless explicitly asked
